#!/usr/bin/env python3
"""
検知した drift を、人が読みやすい Issue 本文＋「取り込み用の Terraform サンプル」に
変換する。detect.py の classify() が返す report を入力にする純関数群。

方針:
  - 新規オブジェクト（未割り当て custom rule 等）の定義を、そのまま
    `resource ... { ... = jsonencode({...}) }` に起こし、import コマンドも添える
    （利用者はこれを手元の .tf に貼って取り込める）。版 export の diff はテキストなので
    そこからは機械生成できず、config-object 一覧から取った実体を使う。
  - 変更されたオブジェクトは「新しい中身」を同じ形で出す（既存ブロックを差し替える用）。
  - 削除は「該当ブロックを .tf から消す（or apply で戻す）」と案内。
  - 版の内容差分（export-diff）はそれ自体が .tf の差分なので、そのまま diff として見せる。

生成する HCL は terraform validate を通る形（テストで実証）。
"""
import hashlib
import json
import re

# API/メタ・読み取り専用でリソース定義（jsonencode）に含めないキー
METADATA_KEYS = frozenset((
    "id", "version", "link", "createDate", "updateDate", "createdBy",
    "structured", "ruleActivated", "status", "used",
))


def _tf_local_name(name, oid):
    """任意の名前を Terraform のリソースローカル名に正規化（英小数字と _ のみ）。

    name だけでなく oid にも同じ正規化を掛ける。実運用の oid は Akamai 採番の整数
    だが、baseline の objects.json のキー経由でも来るため、生で連結すると HCL を
    脱出しうる。防御は 1 行なので入れておく。"""
    def _norm(s):
        s = re.sub(r"[^a-zA-Z0-9_]", "_", str(s or "")).strip("_").lower()
        return re.sub(r"_+", "_", s)
    base = _norm(name)
    if not base or not re.match(r"[a-z_]", base):
        base = "r_" + base if base else "obj"
    return f"{base}_{_norm(oid)}"


def _clean(obj):
    """リソース定義に不要な API メタを全階層で落とす。"""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items() if k not in METADATA_KEYS}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


def _bf_escapes(m):
    """JSON の \\b / \\f エスケープだけを \\u0008 / \\u000c に置き換える。
    バックスラッシュの連なりが奇数のときだけ最後の1本がエスケープ導入子＝本物の
    制御文字。偶数ならデータ中のリテラルなバックスラッシュ（例: 正規表現の \\b＝
    単語境界）なので触らない。ここを素朴な文字列置換にすると `\\bexec\\b` のような
    WAF ルールの正規表現を \\u0008 に化けさせて壊す。"""
    slashes, ch = m.group(1), m.group(2)
    if len(slashes) % 2 == 0:
        return m.group(0)
    return slashes[:-1] + ("\\u0008" if ch == "b" else "\\u000c") + ""


def _jsonencode_body(obj):
    """jsonencode(...) の中身。JSON を HCL の式として使うが、HCL の補間シーケンス
    ${...} / %{...} を無効化する（WAF ルール値の `${jndi:...}`（Log4Shell 検知）等で
    HCL がパースエラー/黙って評価するのを防ぐ）。HCL が解さない \\b \\f も無害化する。"""
    body = json.dumps(_clean(obj), ensure_ascii=False, indent=2, sort_keys=True)
    body = body.replace("${", "$${").replace("%{", "%%{")
    body = re.sub(r"(\\+)([bf])", _bf_escapes, body)
    # jsonencode( の中身を2スペース字下げして読みやすく
    return "\n".join("  " + ln if ln else ln for ln in body.splitlines())


# type ごとの Terraform リソース種別（未知 type は自動生成しない）
_RESOURCE = {
    "custom_rules": ("akamai_appsec_custom_rule", "custom_rule"),
    "rate_policies": ("akamai_appsec_rate_policy", "rate_policy"),
}


def resource_hcl(typ, obj, config_id_ref="local.config_id", config_id=None):
    """1オブジェクト → resource ブロック HCL ＋ import コマンド（文字列2つ）。
    未対応 type や中身が空の場合は HCL を出さず（"", 案内文）を返す。
    config_id を渡すと import コマンドに実 ID を埋める（未指定なら <config_id> のまま）。
    HCL 側は DRY のため常に config_id_ref（既定 local.config_id）を参照する。"""
    oid = obj.get("id", "x")
    if typ not in _RESOURCE:
        return "", f"# type '{typ}' は自動 HCL 化に未対応。手元の .tf で手動対応してください（id={oid}）。"
    if not _clean({k: v for k, v in obj.items() if k != "id"}):
        return "", f"# id={oid} の定義が空。API から本体を取得できていない可能性（手動確認）。"
    res_type, attr = _RESOURCE[typ]
    local = _tf_local_name(obj.get("name"), oid)
    body = _jsonencode_body(obj)
    hcl = (f'resource "{res_type}" "{local}" {{\n'
           f'  config_id   = {config_id_ref}\n'
           f'  {attr} = jsonencode(\n{body}\n  )\n'
           f'}}')
    cid = config_id if config_id not in (None, "") else "<config_id>"
    # import には実 id が要るので正規化できない。安全なトークンでなければコマンドを
    # 出さない（利用者はこれをそのままシェルに貼るため、改行や記号を通さない）。
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(oid)):
        return hcl, (f"# id={_code(oid)} は想定外の形式。import コマンドは自動生成せず、"
                     "値を確認して手で実行してください。")
    imp = f'terraform import {res_type}.{local} {cid}:{oid}'
    return hcl, imp


def adoption_items(report, config_id=None):
    """report → 取り込み案内のリスト。各要素 {kind,typ,id,name,hcl,imports,note}。
    名前など ACC 由来の文字列は生で持つ（Markdown 化は render 側で _code 無害化）。
    config_id を渡すと import コマンドに実 ID を埋める。"""
    items = []
    for typ, d in (report.get("config_objects") or {}).items():
        cur = d.get("current", {})
        base = d.get("baseline", {})
        for i in d.get("added", []):
            hcl, imp = resource_hcl(typ, cur.get(i, {"id": i}), config_id=config_id)
            items.append({"kind": "added", "typ": typ, "id": i,
                          "name": (cur.get(i) or {}).get("name", ""),
                          "hcl": hcl, "imports": [imp] if hcl else [imp] if imp else [],
                          "note": "ACC で新規に作られた定義。手元の .tf に貼り、既存を取り込むなら import する。"})
        for i in d.get("modified", []):
            hcl, imp = resource_hcl(typ, cur.get(i, {"id": i}), config_id=config_id)
            items.append({"kind": "modified", "typ": typ, "id": i,
                          "name": (cur.get(i) or {}).get("name", ""),
                          "hcl": hcl, "imports": [] if hcl else ([imp] if imp else []),
                          "note": "中身が変わった。該当リソースの jsonencode を上の内容に差し替える。"})
        for i in d.get("removed", []):
            items.append({"kind": "removed", "typ": typ, "id": i,
                          "name": (base.get(i) or {}).get("name", ""),
                          "hcl": "", "imports": [],
                          "note": "ACC 側で消えた。対応する resource ブロックを .tf から削除する"
                                  "（残したいなら terraform apply で戻す）。"})
    return items


def _fence(content, lang=""):
    """中身の最長バッククォート連続より長い fence で囲む（fence 破り対策）。"""
    longest = max((len(m.group()) for m in re.finditer(r"`+", content)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{content}\n{ticks}"


def _code(s):
    """非 fence の本文に ACC 由来文字列を出すときの無害化。インラインコードで包み、
    @mention・#ref・**・</...>・見出し記号などを不活性化。バッククォートも安全に。"""
    s = str(s).replace("\n", " ")
    if not s:
        return "``"
    longest = max((len(m.group()) for m in re.finditer(r"`+", s)), default=0)
    t = "`" * (longest + 1)
    pad = " " if (s.startswith("`") or s.endswith("`")) else ""
    return f"{t}{pad}{s}{pad}{t}"


ISSUE_LIMIT = 60000  # GitHub Issue 本文上限(65536)への余裕


def body_fingerprint(body):
    """Issue 本文そのものの指紋。

    report 全体を hash すると、ドリフト判定では無視している揮発キー（version /
    updateDate / used / ruleActivated 等）まで拾ってしまい、**表示内容が完全に
    同一でも指紋が変わって重複コメントが出る**。判定したいのは「読み手にとって
    同じ通知か」なので、本文に対して取る。"""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def fp_marker(fp):
    """Issue 本文/コメントに埋める不可視マーカー。次回の実行が『この内容は既に
    通知済みか』を判定するための痕跡。"""
    return f"<!-- dg-fp:{fp} -->"


def render_issue(report, config_name="", when="", config_id=None):
    """Issue 本文（Markdown）。分かりやすい差分＋取り込み用サンプル Terraform。
    config_id を渡すと import コマンドに実 ID を埋める（未指定なら <config_id> のまま）。"""
    if not report.get("drift"):
        return "drift なし。"
    head = f" — {_code(config_name)}" if config_name else ""
    L = [f"## AppSec ドリフト検知{head}",
         "", "ACC 側で Terraform を通さない変更が入りました。中身を確認し、"
         "採用するなら下のサンプルを手元の `.tf` に取り込んでください。", ""]
    if when:
        L.append(f"検知時刻: {_code(when)}\n")

    act = report.get("activation") or []
    if act:
        L += ["### 稼働版が変わっています", ""]
        for a in act:
            L.append(f"- **{a['network']}**: {a['baseline']} → {a['current']}")
        L += ["", "Terraform を通さずに activate された可能性があります。**古い版へ戻されている場合、"
              "設定の中身は baseline と一致したままでも、実際に効いている保護は弱くなっています。**"
              "どの版が載るべきかを確認してください。", ""]

    vc = report.get("version_content") or []
    if vc:
        L += ["### 版の内容の差分（管理下リソース）", ""]
        for ch in vc:
            if ch["kind"] == "modified":
                L += [f"{_code(ch['file'])}:", _fence("\n".join(ch.get("diff", [])[:40]), "diff"), ""]
            else:
                L.append(f"- {ch['kind']}: {_code(ch['file'])}")
        L.append("")

    items = adoption_items(report, config_id=config_id)
    if items:
        L += ["### 取り込み用のサンプル Terraform", ""]
        for it in items:
            verb = {"added": "を追加", "modified": "を変更", "removed": "を削除"}[it["kind"]]
            L.append(f"**{it['typ']} id={it['id']} {_code(it['name'])} {verb}** — {it['note']}")
            if it["hcl"]:
                L.append(_fence(it["hcl"], "hcl"))
            for imp in it["imports"]:
                if imp.lstrip().startswith("#"):      # unknown/空のときの案内コメント
                    L.append(_code(imp))
                else:
                    L += ["取り込み（既存を state へ）:", _fence(imp, "bash")]
            L.append("")

    L += ["---",
          "確認したら：採用なら上を `.tf` に反映して `terraform apply`、"
          "棄却なら ACC 側を元に戻す。落ち着いたら baseline を更新してこの Issue を閉じる。"]
    body = "\n".join(L)
    if len(body) > ISSUE_LIMIT:
        body = body[:ISSUE_LIMIT] + ("\n\n---\n**本文が長いため省略しました。"
                                     "全差分は Actions run のログを参照してください。**")
    return body
