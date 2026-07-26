#!/usr/bin/env python3
"""adopt.py のテスト。取り込み用 Terraform 生成の正しさと、生成 HCL が
terraform の構文検証(fmt)を通ることを確認する。"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import adopt  # noqa: E402

RULE = {"id": 1234, "name": "DRIFTGUARD-DEMO", "tag": ["DEMO"],
        "operation": "AND", "version": 3, "link": "/x", "createDate": "2026",
        "conditions": [{"type": "requestMethodMatch", "positiveMatch": True,
                        "value": ["PATCH"]}]}
RATE = {"id": 5678, "name": "RateA", "averageThreshold": 99,
        "burstThreshold": 200, "version": 5, "updateDate": "2026"}


def _report(added_cr=None, modified_rp=None, removed_cr=None, vc=None):
    co = {}
    if added_cr:
        co["custom_rules"] = {"added": [str(added_cr["id"])], "removed": [], "modified": [],
                              "current": {str(added_cr["id"]): added_cr}, "baseline": {}}
    if modified_rp:
        co.setdefault("rate_policies", {"added": [], "removed": [], "modified": [],
                                        "current": {}, "baseline": {}})
        co["rate_policies"]["modified"].append(str(modified_rp["id"]))
        co["rate_policies"]["current"][str(modified_rp["id"])] = modified_rp
    if removed_cr:
        co.setdefault("custom_rules", {"added": [], "removed": [], "modified": [],
                                       "current": {}, "baseline": {}})
        co["custom_rules"]["removed"].append(str(removed_cr["id"]))
        co["custom_rules"]["baseline"][str(removed_cr["id"])] = removed_cr
    return {"drift": True, "version_content": vc or [], "config_objects": co}


class TestResourceHcl(unittest.TestCase):
    def test_custom_rule_block(self):
        hcl, imp = adopt.resource_hcl("custom_rules", RULE)
        self.assertIn('resource "akamai_appsec_custom_rule"', hcl)
        self.assertIn("custom_rule = jsonencode(", hcl)
        self.assertIn("DRIFTGUARD-DEMO", hcl)
        self.assertIn("requestMethodMatch", hcl)
        # メタは落ちている
        for meta in ('"version"', '"link"', '"createDate"'):
            self.assertNotIn(meta, hcl)
        self.assertIn("terraform import akamai_appsec_custom_rule.", imp)
        self.assertIn("1234", imp)
        # config_id 未指定なら import はプレースホルダのまま
        self.assertIn("<config_id>:1234", imp)

    def test_import_fills_config_id(self):
        # config_id を渡すと import に実 ID が埋まる（HCL 側は local.config_id 参照のまま）
        hcl, imp = adopt.resource_hcl("custom_rules", RULE, config_id="12345")
        self.assertIn("12345:1234", imp)
        self.assertNotIn("<config_id>", imp)
        self.assertIn("config_id   = local.config_id", hcl)   # HCL は DRY 参照を維持

    def test_render_issue_threads_config_id(self):
        # render_issue → adoption_items → resource_hcl まで config_id が通る
        body = adopt.render_issue(_report(added_cr=RULE), config_id="12345")
        self.assertIn("12345:1234", body)
        self.assertNotIn("<config_id>:1234", body)

    def test_rate_policy_block(self):
        hcl, _ = adopt.resource_hcl("rate_policies", RATE)
        self.assertIn('resource "akamai_appsec_rate_policy"', hcl)
        self.assertIn("rate_policy = jsonencode(", hcl)
        self.assertIn("99", hcl)  # 変更後の averageThreshold
        self.assertNotIn('"updateDate"', hcl)

    def test_local_name_sanitized(self):
        self.assertEqual(adopt._tf_local_name("A B-c/d", 7), "a_b_c_d_7")
        self.assertEqual(adopt._tf_local_name("", 9), "obj_9")
        self.assertTrue(adopt._tf_local_name("123abc", 1).startswith("r_"))


class TestAdoptionItems(unittest.TestCase):
    def test_added(self):
        items = adopt.adoption_items(_report(added_cr=RULE))
        self.assertEqual(items[0]["kind"], "added")
        self.assertIn("jsonencode", items[0]["hcl"])
        self.assertTrue(items[0]["imports"])

    def test_modified_has_no_import(self):
        items = adopt.adoption_items(_report(modified_rp=RATE))
        self.assertEqual(items[0]["kind"], "modified")
        self.assertEqual(items[0]["imports"], [])

    def test_removed_has_no_hcl(self):
        items = adopt.adoption_items(_report(removed_cr=RULE))
        self.assertEqual(items[0]["kind"], "removed")
        self.assertEqual(items[0]["hcl"], "")
        self.assertIn("削除", items[0]["note"])


class TestRenderIssue(unittest.TestCase):
    def test_clean(self):
        self.assertIn("drift なし",
                      adopt.render_issue({"drift": False, "version_content": [], "config_objects": {}}))

    def test_body_has_diff_and_sample(self):
        rep = _report(added_cr=RULE,
                      vc=[{"file": "rate-policies.tf", "kind": "modified",
                           "diff": ['-  "averageThreshold" : 5,', '+  "averageThreshold" : 99,']}])
        body = adopt.render_issue(rep, config_name="example")
        self.assertIn("版の内容の差分", body)
        self.assertIn("```diff", body)
        self.assertIn("averageThreshold", body)
        self.assertIn("取り込み用のサンプル Terraform", body)
        self.assertIn("```hcl", body)
        self.assertIn("terraform import", body)

    def test_injection_safe_no_unclosed_fence(self):
        # ACC 由来の名前に ``` が入っても本文の code fence が破られない。
        # 正しい不変条件: 行頭が3連以上バッククォートの「fence 区切り行」が偶数。
        import re as _re
        rule = dict(RULE); rule["name"] = "evil```rm -rf"
        body = adopt.render_issue(_report(added_cr=rule))
        fence_lines = [ln for ln in body.splitlines() if _re.match(r"^`{3,}", ln)]
        self.assertEqual(len(fence_lines) % 2, 0, "code fence が破れている")
        # 中身の ``` は行頭でない（fence 区切りに化けていない）ことも確認
        self.assertTrue(any("evil" in ln and not _re.match(r"^`{3,}", ln)
                            for ln in body.splitlines()))


class TestTerraformSyntax(unittest.TestCase):
    """生成 HCL が terraform fmt（構文）を通ることを実証。terraform 無ければ skip。"""
    @unittest.skipIf(shutil.which("terraform") is None, "terraform 未インストール")
    def test_generated_hcl_is_valid_syntax(self):
        d = tempfile.mkdtemp(prefix="dg_adopt_")
        hcl1, _ = adopt.resource_hcl("custom_rules", RULE)
        hcl2, _ = adopt.resource_hcl("rate_policies", RATE)
        with open(os.path.join(d, "adopt.tf"), "w") as f:
            f.write("locals { config_id = 1 }\n\n" + hcl1 + "\n\n" + hcl2 + "\n")
        r = subprocess.run(["terraform", "fmt", "-check", "-diff", d],
                           capture_output=True, text=True)
        # fmt が整形差分を出しても構文エラーでなければ 0/3。パースエラーなら非0でstderrにError。
        self.assertNotIn("Error:", r.stderr, f"HCL 構文エラー: {r.stderr}")


class TestAdversarialContent(unittest.TestCase):
    """敵対レビューで確定した破壊入力を回帰テスト化。"""

    def _fmt_ok(self, *objs_typed):
        """生成 HCL を terraform fmt に通し、構文エラー(Error:)が無いことを確認。"""
        if shutil.which("terraform") is None:
            self.skipTest("terraform 未インストール")
        d = tempfile.mkdtemp(prefix="dg_adv_")
        blocks = ["locals { config_id = 1 }"]
        for typ, obj in objs_typed:
            hcl, _ = adopt.resource_hcl(typ, obj)
            blocks.append(hcl)
        with open(os.path.join(d, "adopt.tf"), "w") as f:
            f.write("\n\n".join(blocks) + "\n")
        r = subprocess.run(["terraform", "fmt", "-check", "-diff", d],
                           capture_output=True, text=True)
        self.assertNotIn("Error:", r.stderr, f"HCL 構文エラー: {r.stderr}")

    def test_log4shell_dollar_brace_value_valid(self):
        # WAF ルールが Log4Shell を検知するための値 ${jndi:...} を含んでも HCL が壊れない
        rule = {"id": 1, "name": "log4shell", "operation": "AND",
                "conditions": [{"type": "requestHeaderMatch",
                                "value": ["${jndi:ldap://evil/x}", "%{if}", "${8}"]}]}
        self._fmt_ok(("custom_rules", rule))
        hcl, _ = adopt.resource_hcl("custom_rules", rule)
        self.assertIn("$${jndi:", hcl)   # 補間が無効化されている
        self.assertIn("%%{", hcl)

    def test_control_chars_valid(self):
        rule = {"id": 2, "name": "ctl", "operation": "AND",
                "conditions": [{"type": "x", "value": ["a\bb\fc"]}]}
        self._fmt_ok(("custom_rules", rule))

    def test_code_neutralizes_markdown(self):
        # 無害化プリミティブ: @mention/#ref/**/</> をインラインコードで包む
        c = adopt._code("@here #1 **x** </details>")
        self.assertTrue(c.startswith("`") and c.endswith("`"))
        self.assertIn("@here", c)                 # 中身は保持
        # バッククォート入りでも壊れない（内側より長い fence で包む）
        c2 = adopt._code("a`b``c")
        self.assertTrue(c2.startswith("```"))      # 内側最長2 → 3連で包む

    def test_removed_name_is_inside_code_span(self):
        import re as _re
        rep = _report(removed_cr={"id": 9, "name": "@here #1 </details>"})
        title = [ln for ln in adopt.render_issue(rep).splitlines() if "を削除" in ln][0]
        # 危険文字は全てインラインコード span 内（title を code span 除去すると消える）
        stripped = _re.sub(r"`[^`]*`", "", title)
        self.assertNotIn("@here", stripped)
        self.assertNotIn("</details>", stripped)

    def test_unknown_type_emits_note_not_resource(self):
        rep = {"drift": True, "version_content": [],
               "config_objects": {"match_targets": {"added": ["5"], "removed": [], "modified": [],
                                                     "current": {"5": {"id": 5, "name": "mt"}}, "baseline": {}}}}
        items = adopt.adoption_items(rep)
        self.assertEqual(items[0]["hcl"], "")            # 未対応 type は resource を作らない
        body = adopt.render_issue(rep)
        self.assertIn("未対応", body)

    def test_empty_definition_no_garbage_block(self):
        # current に本体が無い(サマリのみ)id → jsonencode({}) の空ブロックを出さない
        rep = _report(added_cr={"id": 7})
        items = adopt.adoption_items(rep)
        self.assertEqual(items[0]["hcl"], "")

    def test_literal_backslash_b_survives(self):
        """正規表現の \\b(単語境界)を \\u0008(バックスペース)に化けさせない。

        WAF ルールの正規表現で \\b は頻出する。素朴な文字列置換だと、JSON の
        \\b エスケープと『リテラルのバックスラッシュ + b』を区別できず、
        取り込み用コードが本番のルールを静かに壊す。terraform で評価した値が
        元データと一致することは別途実機で確認済み。"""
        rule = dict(RULE, conditions=[{"type": "requestHeaderMatch",
                                       "value": [r"\bexec\b", r"C:\bin\file"]}])
        hcl, _ = adopt.resource_hcl("custom_rules", rule)
        self.assertIn(r"\\bexec\\b", hcl)        # HCL 上は \\b ＝ 評価すると \b
        self.assertIn(r"C:\\bin\\file", hcl)
        self.assertNotIn("u0008", hcl)
        self.assertNotIn("u000c", hcl)

    def test_real_control_chars_are_escaped(self):
        """本物の U+0008 / U+000C は HCL が解さないので \\uXXXX にする。"""
        rule = dict(RULE, conditions=[{"type": "x", "value": ["a\bb", "a\fc"]}])
        hcl, _ = adopt.resource_hcl("custom_rules", rule)
        self.assertIn(r"a\u0008b", hcl)
        self.assertIn(r"a\u000cc", hcl)

    def test_oid_is_sanitized_in_local_name(self):
        """id 側も正規化する。name だけ正規化していると、id 経由で HCL を脱出できる。

        実運用では id は Akamai 採番の整数なので到達しないが、baseline の
        objects.json のキーからも来るため、防御は 1 行で済む。"""
        evil = 'x" {}\n  provisioner "local-exec" { command = "id" }\n  x = "'
        local = adopt._tf_local_name("n", evil)
        self.assertNotIn('"', local)
        self.assertNotIn("\n", local)
        self.assertNotIn(" ", local)
        rule = {"id": evil, "name": "n", "conditions": [{"type": "x", "value": ["1"]}]}
        hcl, imp = adopt.resource_hcl("custom_rules", rule)
        # 脱出コードは識別子の一部として無害化されるだけで、ブロックにはならない
        self.assertNotIn('provisioner "', hcl)
        self.assertEqual(hcl.count('resource "'), 1)
        self.assertEqual(len(imp.splitlines()), 1)    # import も 1 行のまま


if __name__ == "__main__":
    unittest.main(verbosity=2)
