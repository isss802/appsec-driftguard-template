#!/usr/bin/env python3
"""detect.py の入念なテスト。敵対レビュー（偽陰性/偽陽性/クラッシュ）と
網羅性レビュー（実 drift 種別）の指摘を全てケース化している。"""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import detect  # noqa: E402


RATE_5 = 'resource "x" {\n  rate_policy = jsonencode({ "averageThreshold" : 5 })\n}\n'
RATE_99 = 'resource "x" {\n  rate_policy = jsonencode({ "averageThreshold" : 99 })\n}\n'
ACTION_ALERT = 'resource "akamai_appsec_custom_rule_action" "a" {\n  custom_rule_action = "alert"\n}\n'
ACTION_DENY = 'resource "akamai_appsec_custom_rule_action" "a" {\n  custom_rule_action = "deny"\n}\n'
WAF_AAG = 'resource "akamai_appsec_waf_mode" "w" {\n  mode = "AAG"\n}\n'
WAF_KRS = 'resource "akamai_appsec_waf_mode" "w" {\n  mode = "KRS"\n}\n'

BASE_EXPORT = {"rate-policies.tf": RATE_5, "waf.tf": WAF_AAG}
BASE_OBJS = {
    "custom_rules": {1001: {"id": 1001, "name": "RuleA", "status": "activated",
                                "conditions": [{"type": "geoMatch", "value": ["JP"]}]}},
    "rate_policies": {2002: {"id": 2002, "name": "RateA", "averageThreshold": 5}},
}


class TestDiffExports(unittest.TestCase):
    def test_no_change(self):
        self.assertEqual(detect.diff_exports(BASE_EXPORT, dict(BASE_EXPORT)), [])

    def test_field_modified(self):
        cur = {"rate-policies.tf": RATE_99, "waf.tf": WAF_AAG}
        ch = detect.diff_exports(BASE_EXPORT, cur)
        self.assertEqual([(c["file"], c["kind"]) for c in ch], [("rate-policies.tf", "modified")])
        joined = "\n".join(ch[0]["diff"])
        self.assertIn("5", joined); self.assertIn("99", joined)

    def test_action_alert_to_deny(self):
        # action 変更（alert↔deny）は export 経路でしか拾えない（config-object には出ない）
        ch = detect.diff_exports({"actions.tf": ACTION_ALERT}, {"actions.tf": ACTION_DENY})
        self.assertEqual(ch[0]["kind"], "modified")
        j = "\n".join(ch[0]["diff"]); self.assertIn("alert", j); self.assertIn("deny", j)

    def test_waf_mode_change(self):
        ch = detect.diff_exports({"waf.tf": WAF_AAG}, {"waf.tf": WAF_KRS})
        self.assertEqual(ch[0]["kind"], "modified")

    def test_file_added_removed(self):
        cur = dict(BASE_EXPORT); cur["custom-rules.tf"] = "x\n"
        self.assertEqual(detect.diff_exports(BASE_EXPORT, cur),
                         [{"file": "custom-rules.tf", "kind": "added"}])
        self.assertEqual(detect.diff_exports(cur, BASE_EXPORT),
                         [{"file": "custom-rules.tf", "kind": "removed"}])

    def test_deterministic_order(self):
        base = {"a.tf": "x\n", "b.tf": "y\n", "c.tf": "z\n"}
        cur = {"a.tf": "1\n", "b.tf": "2\n", "c.tf": "3\n"}
        self.assertEqual([c["file"] for c in detect.diff_exports(base, cur)],
                         ["a.tf", "b.tf", "c.tf"])

    def test_hunk_keeps_deletion_line_starting_with_dash(self):
        # 回帰: 内容が "-" 始まりの削除行を header と誤判定して落とさないこと
        base = {"a.tf": "-- keepme\nother\n"}
        cur = {"a.tf": "other\n"}
        ch = detect.diff_exports(base, cur)
        j = "\n".join(ch[0]["diff"])
        self.assertIn("keepme", j)


class TestNormalizeText(unittest.TestCase):
    def test_trailing_newline_and_crlf(self):
        # FP-6: 末尾改行/CRLF ゆれを吸収（正規化後は同一 → drift なし）
        self.assertEqual(detect._normalize_text("x = 1"), "x = 1\n")
        self.assertEqual(detect._normalize_text("x = 1\r\n"), "x = 1\n")
        self.assertEqual(detect._normalize_text("x = 1\n\n\n"), "x = 1\n")


class TestDiffObjlists(unittest.TestCase):
    def test_no_change(self):
        self.assertEqual(detect.diff_objlists(BASE_OBJS, copy.deepcopy(BASE_OBJS)), {})

    def test_unused_rule_added(self):
        cur = copy.deepcopy(BASE_OBJS)
        cur["custom_rules"][99999] = {"id": 99999, "name": "NEW", "status": "unused"}
        d = detect.diff_objlists(BASE_OBJS, cur)
        self.assertEqual(d["custom_rules"]["added"], ["99999"])

    def test_rule_removed(self):
        cur = copy.deepcopy(BASE_OBJS); del cur["custom_rules"][1001]
        self.assertEqual(detect.diff_objlists(BASE_OBJS, cur)["custom_rules"]["removed"],
                         ["1001"])

    def test_rate_policy_removed(self):
        cur = copy.deepcopy(BASE_OBJS); del cur["rate_policies"][2002]
        self.assertEqual(detect.diff_objlists(BASE_OBJS, cur)["rate_policies"]["removed"],
                         ["2002"])

    def test_custom_rule_conditions_modified(self):
        # ルールの検知ロジック(conditions)の書き換え = 重い drift。modified で拾う。
        cur = copy.deepcopy(BASE_OBJS)
        cur["custom_rules"][1001]["conditions"] = [{"type": "geoMatch", "value": ["US"]}]
        self.assertEqual(detect.diff_objlists(BASE_OBJS, cur)["custom_rules"]["modified"],
                         ["1001"])

    def test_rate_policy_modified(self):
        cur = copy.deepcopy(BASE_OBJS); cur["rate_policies"][2002]["averageThreshold"] = 99
        self.assertEqual(detect.diff_objlists(BASE_OBJS, cur)["rate_policies"]["modified"],
                         ["2002"])

    # ---- 偽陽性を潰す回帰 ----
    def test_volatile_fields_ignored_toplevel(self):
        cur = copy.deepcopy(BASE_OBJS)
        cur["rate_policies"][2002].update({"version": 999, "updateDate": "2026", "link": "/x"})
        self.assertEqual(detect.diff_objlists(BASE_OBJS, cur), {})

    def test_volatile_fields_ignored_nested(self):
        # FP-5: ネストした updateDate/version も無視（再帰 strip）
        base = {"rp": {1: {"id": 1, "name": "A", "meta": {"updateDate": "x", "v": 1}}}}
        cur = {"rp": {1: {"id": 1, "name": "A", "meta": {"updateDate": "y", "v": 1}}}}
        self.assertEqual(detect.diff_objlists(base, cur), {})

    def test_numeric_int_vs_float(self):
        # FP-2: 5 vs 5.0 は同値 → modified にしない
        base = {"rp": {1: {"id": 1, "t": 5}}}
        cur = {"rp": {1: {"id": 1, "t": 5.0}}}
        self.assertEqual(detect.diff_objlists(base, cur), {})

    def test_id_value_type_wobble(self):
        # FP-3: オブジェクト内 "id" の int/str ゆれは指紋から除外され誤検知しない
        base = {"cr": {123: {"id": 123, "name": "A"}}}
        cur = {"cr": {"123": {"id": "123", "name": "A"}}}
        self.assertEqual(detect.diff_objlists(base, cur), {})

    def test_list_order_is_significant_by_design(self):
        # 設計判断: list 順は意味を持ち得るので順序保存（順序変化は modified）。
        # ルール順・match target 順の入れ替えを見逃さないための意図的挙動。
        base = {"cr": {1: {"id": 1, "c": [{"a": 1}, {"b": 2}]}}}
        cur = {"cr": {1: {"id": 1, "c": [{"b": 2}, {"a": 1}]}}}
        self.assertEqual(detect.diff_objlists(base, cur)["cr"]["modified"], ["1"])

    # ---- クラッシュ耐性 ----
    def test_none_inputs(self):
        self.assertEqual(detect.diff_objlists(None, None), {})
        self.assertEqual(detect.diff_objlists(None, copy.deepcopy(BASE_OBJS)) != {}, True)

    def test_non_dict_type_raises(self):
        with self.assertRaises(TypeError):
            detect.diff_objlists({"cr": [1, 2]}, {"cr": [1, 2]})

    def test_silent_delete_is_safe_side(self):
        # 取得失敗を空で渡すと「全 removed」= drift(安全側)。live_objlists は例外を
        # 投げるので実運用では両側空にならない。ここは classify の振る舞いを固定。
        d = detect.diff_objlists(BASE_OBJS, {"custom_rules": {}, "rate_policies": {}})
        self.assertEqual(d["rate_policies"]["removed"], ["2002"])


class TestClassify(unittest.TestCase):
    def test_clean(self):
        r = detect.classify(BASE_EXPORT, dict(BASE_EXPORT), BASE_OBJS, copy.deepcopy(BASE_OBJS))
        self.assertFalse(r["drift"])

    def test_field_drift_only(self):
        cur = {"rate-policies.tf": RATE_99, "waf.tf": WAF_AAG}
        r = detect.classify(BASE_EXPORT, cur, BASE_OBJS, copy.deepcopy(BASE_OBJS))
        self.assertTrue(r["drift"]); self.assertTrue(r["version_content"])
        self.assertEqual(r["config_objects"], {})

    def test_unused_rule_invisible_to_export(self):
        cur_objs = copy.deepcopy(BASE_OBJS)
        cur_objs["custom_rules"][99999] = {"id": 99999, "name": "N", "status": "unused"}
        r = detect.classify(BASE_EXPORT, dict(BASE_EXPORT), BASE_OBJS, cur_objs)
        self.assertTrue(r["drift"]); self.assertEqual(r["version_content"], [])
        self.assertIn("custom_rules", r["config_objects"])

    def test_action_change_is_export_only_not_objlist(self):
        # action 変更は export に出るが objlist には出ない、を固定
        r = detect.classify({"actions.tf": ACTION_ALERT}, {"actions.tf": ACTION_DENY},
                            BASE_OBJS, copy.deepcopy(BASE_OBJS))
        self.assertTrue(r["version_content"]); self.assertEqual(r["config_objects"], {})

    def test_simultaneous_both_paths(self):
        cur = {"rate-policies.tf": RATE_99, "waf.tf": WAF_KRS}
        cur_objs = copy.deepcopy(BASE_OBJS)
        cur_objs["custom_rules"][88888] = {"id": 88888, "name": "X", "status": "unused"}
        cur_objs["rate_policies"][2002]["averageThreshold"] = 7
        r = detect.classify(BASE_EXPORT, cur, BASE_OBJS, cur_objs)
        self.assertTrue(r["version_content"]); self.assertTrue(r["config_objects"])

    def test_empty_both_is_no_drift_but_main_guards(self):
        # 純関数としては空同士=drift なし（定義通り）。ただし main() が baseline 空を
        # 異常(exit 3)として弾く（下の TestMain 参照）ので本番では握り潰さない。
        self.assertFalse(detect.classify({}, {}, {}, {})["drift"])


class TestRenderReport(unittest.TestCase):
    def test_clean(self):
        self.assertIn("drift なし", detect.render_report(
            {"drift": False, "version_content": [], "config_objects": {}}))

    def test_both_sections(self):
        cur = {"rate-policies.tf": RATE_99, "waf.tf": WAF_AAG}
        cur_objs = copy.deepcopy(BASE_OBJS)
        cur_objs["custom_rules"][77777] = {"id": 77777, "name": "Z", "status": "unused"}
        txt = detect.render_report(detect.classify(BASE_EXPORT, cur, BASE_OBJS, cur_objs))
        self.assertIn("export-diff", txt); self.assertIn("77777", txt)

    def test_non_dict_object_does_not_crash(self):
        # 非 dict オブジェクトが混じっても render は落ちない
        r = detect.classify({}, {}, {"cr": {}}, {"cr": {5: "notadict"}})
        detect.render_report(r)  # 例外が出ないこと


SEC = os.path.join("modules", "security")


class TestLoadExport(unittest.TestCase):
    def _mkexport(self, files):
        """export root からの相対パスでファイルを置く。"""
        d = tempfile.mkdtemp(prefix="dg_")
        for rel, content in files.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
        return d

    def test_reads_tf_and_tf_json_recursively(self):
        # FN-1: .tf.json とサブディレクトリも読む
        d = self._mkexport({os.path.join(SEC, "a.tf"): "A\n",
                            os.path.join(SEC, "rules.tf.json"): '{"x":1}\n',
                            os.path.join(SEC, "sub", "deep.tf"): "D\n",
                            os.path.join(SEC, "notes.txt"): "ignore\n"})
        files = detect.load_export(d)
        self.assertIn(os.path.join(SEC, "a.tf"), files)
        self.assertIn(os.path.join(SEC, "rules.tf.json"), files)
        self.assertIn(os.path.join(SEC, "sub", "deep.tf"), files)
        self.assertNotIn(os.path.join(SEC, "notes.txt"), files)

    def test_root_level_files_are_scanned(self):
        """root の appsec-variables.tf も見る。hostname はここにしかないので、
        modules/security だけに絞ると『保護対象ホストが1本消えた』を取りこぼす。"""
        d = self._mkexport({"appsec-variables.tf": 'variable "hostnames" {}\n',
                            os.path.join(SEC, "a.tf"): "A\n"})
        files = detect.load_export(d)
        self.assertIn("appsec-variables.tf", files)
        self.assertIn(os.path.join(SEC, "a.tf"), files)

    def test_provider_file_is_excluded(self):
        """appsec-main.tf は export した端末の .edgerc 絶対パスを含むので比較対象外。
        含めると CI と手元で永久に食い違う。"""
        d = self._mkexport({"appsec-main.tf": 'provider "akamai" { edgerc = "/Users/x/.edgerc" }\n',
                            "appsec.tf": "module x {}\n"})
        files = detect.load_export(d)
        self.assertNotIn("appsec-main.tf", files)
        self.assertIn("appsec.tf", files)

    def test_normalizes_trailing_newline(self):
        d = self._mkexport({"a.tf": "x = 1"})   # 末尾改行なし
        self.assertEqual(detect.load_export(d)["a.tf"], "x = 1\n")

    def test_missing_dir_empty(self):
        self.assertEqual(detect.load_export("/nonexistent/xyz"), {})


class TestActivationDiff(unittest.TestCase):
    """稼働版の突き合わせ。ACC で何も編集せず古い版を activate し直すだけの
    ロールバックは、export diff にもオブジェクト一覧の diff にも出ない。"""

    def test_same_versions_no_drift(self):
        a = {"staging": 12, "production": 9}
        self.assertEqual(detect.diff_activation(a, dict(a)), [])

    def test_rollback_is_detected(self):
        r = detect.classify({}, {}, {}, {},
                            {"staging": 12, "production": 9},
                            {"staging": 12, "production": 3})
        self.assertTrue(r["drift"])
        self.assertEqual(r["activation"],
                         [{"network": "production", "baseline": 9, "current": 3}])
        self.assertIn("production", detect.render_report(r))

    def test_missing_side_is_not_drift(self):
        # 片方が無い（古い baseline 等）ときに偽の drift を出さない。
        # 「baseline に稼働版が無い」ケースは main が exit 3 で弾く。
        self.assertEqual(detect.diff_activation(None, {"staging": 1}), [])
        self.assertEqual(detect.diff_activation({"staging": 1}, None), [])


class TestLiveFailSafe(unittest.TestCase):
    def test_objlist_fetch_failure_raises(self):
        # FP-1/CaseA の核: API 失敗を空(=削除 drift)にせず例外にする
        orig = detect.sh
        detect.sh = lambda cmd: type("R", (), {"returncode": 1, "stdout": "", "stderr": "boom"})()
        try:
            with self.assertRaises(RuntimeError):
                detect.live_objlists(123, "default")
        finally:
            detect.sh = orig

    def test_objlist_bad_json_raises(self):
        orig = detect.sh
        detect.sh = lambda cmd: type("R", (), {"returncode": 0, "stdout": "not json", "stderr": ""})()
        try:
            with self.assertRaises(RuntimeError):
                detect.live_objlists(123, "default")
        finally:
            detect.sh = orig


class TestMain(unittest.TestCase):
    """CI 判定の根幹＝main の exit code マッピング（0/2/3）を固定する。"""
    def _baseline(self, content="X\n", objs=None):
        d = tempfile.mkdtemp(prefix="dg_bl_")
        sec = os.path.join(d, "modules", "security"); os.makedirs(sec)
        with open(os.path.join(sec, "a.tf"), "w") as f:
            f.write(content)
        oj = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        base_objs = objs if objs is not None else {"custom_rules": {}, "rate_policies": {}}
        base_objs = dict(base_objs)
        base_objs.setdefault(detect.ACTIVATION_KEY, {"staging": 12, "production": 9})
        json.dump(base_objs, oj)
        oj.close()
        return d, oj.name

    def _run(self, args, objs_return=None, objs_raise=None, export_raise=None,
             act_return=None):
        orig_lo, orig_re, orig_la = (detect.live_objlists, detect.run_export,
                                     detect.live_activation)
        if objs_raise:
            detect.live_objlists = lambda c, s: (_ for _ in ()).throw(RuntimeError("boom"))
        else:
            detect.live_objlists = lambda c, s: (objs_return
                                                 if objs_return is not None
                                                 else {"custom_rules": {}, "rate_policies": {}})
        detect.live_activation = lambda c, s: (act_return if act_return is not None
                                               else {"staging": 12, "production": 9})
        if export_raise:
            detect.run_export = lambda *a: (_ for _ in ()).throw(RuntimeError("export failed"))
        try:
            return detect.main(args)
        finally:
            (detect.live_objlists, detect.run_export,
             detect.live_activation) = orig_lo, orig_re, orig_la

    def test_clean_returns_0(self):
        d, oj = self._baseline()
        code = self._run(["--baseline", d, "--baseline-objs", oj,
                          "--config-name", "x", "--config-id", "1", "--current", d])
        self.assertEqual(code, 0)

    def test_content_drift_returns_2(self):
        d, oj = self._baseline()
        d2, _ = self._baseline(content="DIFFERENT\n")
        code = self._run(["--baseline", d, "--baseline-objs", oj,
                          "--config-name", "x", "--config-id", "1", "--current", d2])
        self.assertEqual(code, 10)   # drift = 10

    def test_object_drift_returns_2(self):
        # baseline に rule あり、current(live) で消える → removed drift → 2
        d, oj = self._baseline(objs={"custom_rules": {"1": {"id": 1, "name": "A"}},
                                     "rate_policies": {}})
        code = self._run(["--baseline", d, "--baseline-objs", oj,
                          "--config-name", "x", "--config-id", "1", "--current", d],
                         objs_return={"custom_rules": {}, "rate_policies": {}})
        self.assertEqual(code, 10)   # drift = 10


    def test_rollback_only_returns_10(self):
        """設定の中身は baseline と同じでも、稼働版が戻されていたら drift。
        これを拾えないと『古い版を activate し直すだけ』の弱体化を見逃す。"""
        d, oj = self._baseline()
        code = self._run(["--baseline", d, "--baseline-objs", oj,
                          "--config-name", "x", "--config-id", "1", "--current", d],
                         act_return={"staging": 12, "production": 3})
        self.assertEqual(code, 10)

    def test_baseline_without_activation_returns_3(self):
        """稼働版を持たない古い形式の baseline は clean 扱いにせず異常で止める。"""
        d, _ = self._baseline()
        oj = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"custom_rules": {}, "rate_policies": {}}, oj); oj.close()
        code = self._run(["--baseline", d, "--baseline-objs", oj.name,
                          "--config-name", "x", "--config-id", "1", "--current", d])
        self.assertEqual(code, 3)

    def test_empty_baseline_files_returns_3(self):
        empty = tempfile.mkdtemp(prefix="dg_empty_")
        oj = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        oj.write('{"custom_rules":{}}'); oj.close()
        self.assertEqual(detect.main(["--baseline", empty, "--baseline-objs", oj.name,
                                      "--config-name", "x", "--config-id", "1",
                                      "--current", empty]), 3)

    def test_empty_baseline_objs_returns_3(self):
        d, _ = self._baseline()
        oj = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        oj.write("{}"); oj.close()
        self.assertEqual(detect.main(["--baseline", d, "--baseline-objs", oj.name,
                                      "--config-name", "x", "--config-id", "1",
                                      "--current", d]), 3)

    def test_current_fetch_failure_returns_3(self):
        d, oj = self._baseline()
        code = self._run(["--baseline", d, "--baseline-objs", oj,
                          "--config-name", "x", "--config-id", "1", "--current", d],
                         objs_raise=True)
        self.assertEqual(code, 3)

    def test_export_failure_returns_3(self):
        # --current 省略 → live export。run_export が raise → 3
        d, oj = self._baseline()
        code = self._run(["--baseline", d, "--baseline-objs", oj,
                          "--config-name", "x", "--config-id", "1"],
                         export_raise=True)
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
