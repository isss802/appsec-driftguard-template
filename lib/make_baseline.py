#!/usr/bin/env python3
"""検知の基準 baseline/objects.json（config レベルのオブジェクト一覧）を作る。

  python3 lib/make_baseline.py <config_id> [section]

version の内容（HCL）側の baseline は、別途 akamai terraform export-appsec で
./baseline に書き出す（README のクイックスタート参照）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect  # noqa: E402


def main(argv):
    if len(argv) < 2:
        print("usage: python3 lib/make_baseline.py <config_id> [section]", file=sys.stderr)
        return 2
    config_id = argv[1]
    section = argv[2] if len(argv) > 2 else "default"
    objs = detect.live_objlists(config_id, section)   # 取得失敗時は例外で中断
    # 稼働版（staging / production に今載っている版）も記録する。これが無いと
    # 「古い版を activate し直すだけ」のロールバックを検知できない。
    objs[detect.ACTIVATION_KEY] = detect.live_activation(config_id, section)
    os.makedirs("baseline", exist_ok=True)
    with open("baseline/objects.json", "w", encoding="utf-8") as f:
        json.dump(objs, f, ensure_ascii=False, indent=2)
    act = objs[detect.ACTIVATION_KEY]
    print("wrote baseline/objects.json "
          f"(custom_rules={len(objs['custom_rules'])}, rate_policies={len(objs['rate_policies'])}, "
          f"staging={act['staging']}, production={act['production']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
