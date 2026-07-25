#!/usr/bin/env python3
"""
Akamai Security Config ドリフト検知の核。

設計（実測に基づく二段検知）:
  1) version-content diff : commit 済みの export(baseline) と、いま再 export した
     ものを fmt して突き合わせる。版に入っている変更（rate policy のフィールド、
     policy に割り当てられた custom rule とその action、WAF mode 等）を拾う。
     export は決定的（同一 config を2回 export すると fmt 後に完全一致）。
  2) config-object diff   : config レベルのオブジェクト一覧（custom rules /
     rate policies）を API から取り、baseline スナップショットと突き合わせる。
     未割り当ての custom rule 定義は版 export に出ないため、ここで拾う。

注意（実測で確認した設計の性質）:
  - custom rule の *action*（alert/deny）は定義でなく policy 側にあり、config-object
    一覧（custom-rules / rate-policies）には出ない。version-content 経路（export）で拾う。
  - security policy / match target / advanced settings も version-content 経路。
  - よって「取得の失敗」を「空＝削除」と取り違えると本物を握り潰す。live_objlists /
    run_export は失敗時に必ず例外を投げ、main は baseline が空なら異常終了する（fail-safe）。

純関数 classify() が全判定を持ち、fixtures でテストする。live 依存
（akamai CLI / terraform fmt）は main() 側に隔離する。
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import difflib

DEFAULT_SUBPATH = ("modules", "security")
DEFAULT_EXTS = (".tf", ".tf.json")
# 指紋から落とす揮発/読み取り専用キー（version/日時/link/作成者/状態）。全階層に再帰適用。
# トップレベルの "id" は辞書キーと重複するため別途トップだけ除外（ネストした
# id 参照は content なので残す）。status/used/ruleActivated は「割り当て状態」など
# 読み取り専用で、adopt.py が生成 HCL からも落とすので検知側でも揮発扱いにして揃える
# （揃えないと「変わった」のに取り込み HCL に差が出ない Issue になる）。
VOLATILE = frozenset(("version", "createDate", "updateDate", "link", "createdBy",
                      "status", "used", "ruleActivated"))


# ---- 純関数（テスト対象。live 依存なし） --------------------------------

def _normalize_text(s):
    """改行を LF に統一し、末尾改行を正規化（fmt/OS 差の偽陽性を消す）。"""
    return s.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def load_export(root, subpath=DEFAULT_SUBPATH, exts=DEFAULT_EXTS):
    """export ルート配下（既定 modules/security）を再帰で読み、
    .tf / .tf.json を {相対パス: 正規化テキスト} で返す。"""
    base = os.path.join(root, *subpath)
    out = {}
    if not os.path.isdir(base):
        return out
    for dirpath, _dirs, files in os.walk(base):
        for name in sorted(files):
            if name.endswith(exts):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, base)
                with open(full, encoding="utf-8") as f:
                    out[rel] = _normalize_text(f.read())
    return out


def diff_exports(baseline_files, current_files):
    """2つの {relpath: text} を比較。ファイル単位で added/removed/modified を返す。"""
    changes = []
    for n in sorted(set(baseline_files) | set(current_files)):
        b = baseline_files.get(n)
        c = current_files.get(n)
        if b == c:
            continue
        if b is None:
            changes.append({"file": n, "kind": "added"})
        elif c is None:
            changes.append({"file": n, "kind": "removed"})
        else:
            ud = list(difflib.unified_diff(
                b.splitlines(), c.splitlines(), lineterm="", n=1))
            body = ud[2:] if len(ud) >= 2 else []   # 先頭2行(---/+++)は header
            hunk = [ln for ln in body if ln[:1] in "+-"]  # @@ や context を除外
            changes.append({"file": n, "kind": "modified", "diff": hunk})
    return changes


def _canon(x, volatile=VOLATILE):
    """指紋用の正規化。全階層で volatile を落とし、整数値の float を int に、
    dict キーをソート。list は順序を保つ（順序は意味を持ち得るため保存）。"""
    if isinstance(x, dict):
        return {k: _canon(v, volatile) for k, v in sorted(x.items())
                if k not in volatile}
    if isinstance(x, list):
        return [_canon(v, volatile) for v in x]
    if isinstance(x, bool):
        return x
    if isinstance(x, float) and x.is_integer():
        return int(x)
    return x


def _fingerprint(obj, volatile=VOLATILE):
    # トップレベル id は辞書キーと重複するので指紋から除外（型ゆれ誤検知を防ぐ）。
    if isinstance(obj, dict) and "id" in obj:
        obj = {k: v for k, v in obj.items() if k != "id"}
    return json.dumps(_canon(obj, volatile), sort_keys=True,
                      ensure_ascii=False, default=str)


def diff_objlists(baseline_objs, current_objs):
    """{type: {id: obj}} を2つ比較。type ごとに added/removed/modified を返す。"""
    baseline_objs = baseline_objs or {}
    current_objs = current_objs or {}
    result = {}
    for typ in sorted(set(baseline_objs) | set(current_objs)):
        bt = baseline_objs.get(typ) or {}
        ct = current_objs.get(typ) or {}
        if not isinstance(bt, dict) or not isinstance(ct, dict):
            raise TypeError(f"objlist type '{typ}' の値が dict でない")
        b = {str(k): v for k, v in bt.items()}
        c = {str(k): v for k, v in ct.items()}
        added = sorted(set(c) - set(b))
        removed = sorted(set(b) - set(c))
        modified = sorted(
            i for i in (set(b) & set(c))
            if _fingerprint(b[i]) != _fingerprint(c[i]))
        if added or removed or modified:
            result[typ] = {"added": added, "removed": removed,
                           "modified": modified, "current": c, "baseline": b}
    return result


def classify(baseline_files, current_files, baseline_objs, current_objs):
    """全判定の核。drift の有無と内訳を返す純関数。"""
    content = diff_exports(baseline_files, current_files)
    objects = diff_objlists(baseline_objs, current_objs)
    return {
        "drift": bool(content) or bool(objects),
        "version_content": content,
        "config_objects": objects,
    }


def _name(o):
    return o.get("name", "") if isinstance(o, dict) else ""


def render_report(report):
    lines = []
    if not report["drift"]:
        return "drift なし。baseline と一致。"
    lines.append("drift あり:")
    vc = report["version_content"]
    if vc:
        lines.append("  版の内容（export-diff）:")
        for ch in vc:
            if ch["kind"] == "modified":
                lines.append(f"    ~ {ch['file']}")
                for d in ch.get("diff", [])[:20]:
                    lines.append(f"        {d}")
            else:
                lines.append(f"    {ch['kind']}: {ch['file']}")
    co = report["config_objects"]
    if co:
        lines.append("  config レベルのオブジェクト（API 一覧 diff）:")
        for typ, d in co.items():
            for i in d["added"]:
                lines.append(f"    + {typ} id={i} {_name(d['current'].get(i))}"
                             "（新規。未割り当てなら版 export には出ない）")
            for i in d["removed"]:
                lines.append(f"    - {typ} id={i} {_name(d['baseline'].get(i))}（削除）")
            for i in d["modified"]:
                lines.append(f"    ~ {typ} id={i} {_name(d['current'].get(i))}（変更）")
    return "\n".join(lines)


# ---- live 依存（main 側に隔離。失敗は必ず例外） --------------------------

def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def run_export(dest, config_name, section):
    r = sh(["akamai", "terraform", "--section", section, "export-appsec",
            "--tfworkpath", dest, config_name])
    if r.returncode != 0:
        raise RuntimeError(f"export 失敗: {r.stderr[:400]}")
    # fmt 失敗を握り潰すと未整形の current が整形済み baseline と食い違い偽ドリフトになる
    f = sh(["terraform", "fmt", os.path.join(dest, *DEFAULT_SUBPATH)])
    if f.returncode != 0:
        raise RuntimeError(f"terraform fmt 失敗（偽ドリフト回避のため中断）: {f.stderr[:300]}")


def _sleep(sec):
    import time
    time.sleep(sec)


def _appsec_json(section, config_id, *args, _tries=3):
    """akamai appsec <args> --json を実行し dict を返す。
    一過性エラーに指数バックオフで再試行し、恒久失敗のときだけ例外（fail-safe を保ちつつ
    N+1 個別取得のフレーク赤を減らす）。"""
    last = ""
    for attempt in range(_tries):
        r = sh(["akamai", "appsec", *args, "--section", section,
                "--config", str(config_id), "--json"])
        if r.returncode == 0:
            try:
                return json.loads(r.stdout)
            except Exception as e:
                raise RuntimeError(f"{' '.join(args)} の JSON parse 失敗: {e}")
        last = r.stderr[:300]
        if attempt + 1 < _tries:
            _sleep(2 ** attempt)   # 1s, 2s
    raise RuntimeError(f"{' '.join(args)} 取得失敗（空扱いにせず中断）: {last}")


def live_objlists(config_id, section):
    """custom rules / rate policies を API から取り {type:{id:obj}} に。
    取得やパースに失敗したら **例外**（空扱い＝偽の削除 drift を防ぐ fail-safe）。

    注意: custom-rules の *一覧* API はサマリ（id/name/status/version）しか返さず、
    conditions 等の本体が無い。検知と取り込みの両方に本体が要るので、各 rule を
    個別取得して full 定義を得る。rate-policies の一覧は full 定義を返す。"""
    out = {"custom_rules": {}, "rate_policies": {}}

    # rate policies: 一覧が full
    for o in (_appsec_json(section, config_id, "rate-policies").get("ratePolicies") or []):
        oid = o.get("id")
        if oid is None:
            raise RuntimeError("rate-policies に id 無しオブジェクトがある")
        out["rate_policies"][oid] = o

    # custom rules: 一覧はサマリ → 個別に full 定義を取る
    for s in (_appsec_json(section, config_id, "custom-rules").get("customRules") or []):
        oid = s.get("id")
        if oid is None:
            raise RuntimeError("custom-rules に id 無しオブジェクトがある")
        out["custom_rules"][oid] = _appsec_json(
            section, config_id, "custom-rule", "--custom-rule", str(oid))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Akamai Security Config drift 検知")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--baseline-objs", required=True)
    ap.add_argument("--config-name", required=True)
    ap.add_argument("--config-id", required=True)
    ap.add_argument("--section", default="default")
    ap.add_argument("--current", help="再 export 済みルート（省略時は live export）")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    baseline_files = load_export(args.baseline)
    with open(args.baseline_objs, encoding="utf-8") as f:
        baseline_objs = json.load(f)

    # fail-safe: baseline が空なら「clean」でなく異常。export パス/設定ミスを握り潰さない。
    if not baseline_files:
        print(f"ERROR: baseline export が空（{args.baseline}/modules/security）。"
              "パス・config 名・CLI を確認。", file=sys.stderr)
        return 3
    if not baseline_objs:
        print("ERROR: baseline のオブジェクト一覧が空。", file=sys.stderr)
        return 3

    try:
        if args.current:
            current_files = load_export(args.current)
        else:
            tmp = tempfile.mkdtemp(prefix="driftguard_")
            run_export(tmp, args.config_name, args.section)
            current_files = load_export(tmp)
        current_objs = live_objlists(args.config_id, args.section)
    except RuntimeError as e:
        print(f"ERROR: 現況取得に失敗（drift 判定を出さず中断）: {e}", file=sys.stderr)
        return 3

    report = classify(baseline_files, current_files, baseline_objs, current_objs)
    print(render_report(report))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    # 10 = drift あり（argparse エラーの exit 2 と衝突させない）、0 = clean、3 = 異常
    return 10 if report["drift"] else 0


if __name__ == "__main__":
    sys.exit(main())
