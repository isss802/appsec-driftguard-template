#!/usr/bin/env bash
# 実 config に対する結合テスト。可逆な drift を注入して二段検知を確認し、
# trap で必ず後片付けする（rule / clone 版のリーク防止）。
# 使い方: CONFIG_NAME=... CONFIG_ID=... SECTION=default bash tests/live_integration.sh
set -uo pipefail
cd "$(dirname "$0")/.."

CONFIG_NAME="${CONFIG_NAME:?set CONFIG_NAME}"
CONFIG_ID="${CONFIG_ID:?set CONFIG_ID}"
SECTION="${SECTION:-default}"
BASE=tests/live_baseline
OBJS=tests/live_baseline_objs.json
fails=0
RID=""; CLONEV=""; RP_ID=""; RP_ORIG=""

cleanup() {
  # 何があっても注入物を消す
  [ -n "$RID" ] && akamai appsec delete-custom-rule --section "$SECTION" --config "$CONFIG_ID" --custom-rule "$RID" >/dev/null 2>&1
  if [ -n "$CLONEV" ]; then
    # 変更した rate policy を戻す（版が消える前に）／版を削除
    [ -n "$RP_ID" ] && [ -n "$RP_ORIG" ] && akamai appsec modify-rate-policy "@$RP_ORIG" --section "$SECTION" --config "$CONFIG_ID" --rate-policy "$RP_ID" --version "$CLONEV" >/dev/null 2>&1
    akamai appsec delete-config-version --section "$SECTION" --config "$CONFIG_ID" --version "$CLONEV" >/dev/null 2>&1
  fi
  rm -f /tmp/dg_it_rule.json /tmp/dg_rp_orig.json /tmp/dg_rp_mod.json 2>/dev/null
}
trap cleanup EXIT

run_detect() {  # 引数: [--current DIR]
  python3 lib/detect.py --baseline "$BASE" --baseline-objs "$OBJS" \
    --config-name "$CONFIG_NAME" --config-id "$CONFIG_ID" --section "$SECTION" "$@"
}

echo "== baseline 構築 =="
akamai terraform --section "$SECTION" export-appsec --tfworkpath "$BASE" "$CONFIG_NAME" >/dev/null 2>&1
terraform fmt "$BASE/modules/security" >/dev/null 2>&1
python3 -c "import sys;sys.path.insert(0,'lib');import detect,json;\
json.dump(detect.live_objlists($CONFIG_ID,'$SECTION'),open('$OBJS','w'),ensure_ascii=False,indent=2)"
# baseline 構築の成否を検証（空 baseline で偽 PASS を防ぐ）
n=$(find "$BASE/modules/security" -name '*.tf' 2>/dev/null | wc -l | tr -d ' ')
if [ "$n" -lt 1 ]; then echo "  FATAL: baseline が空（export 失敗）"; exit 1; fi
echo "  baseline: $n tf ファイル"

echo "== T1: 無ドリフト → exit 0 =="
run_detect >/dev/null; [ $? -eq 0 ] && echo "  PASS" || { echo "  FAIL"; fails=$((fails+1)); }

echo "== T2: 未使用ルール追加（config-object 経路）→ exit 10 で検知 =="
printf '%s' '{ "name": "DRIFTGUARD-IT-DELETEME", "tag": ["DGIT"], "conditions": [ { "type": "requestMethodMatch", "positiveMatch": true, "value": ["PATCH"] } ] }' > /tmp/dg_it_rule.json
RID=$(akamai appsec create-custom-rule --section "$SECTION" --config "$CONFIG_ID" --file /tmp/dg_it_rule.json --json 2>/dev/null | jq -r '.id // empty')
if [ -z "$RID" ]; then echo "  FAIL: rule 作成失敗（偽 PASS を防ぐため FAIL 扱い）"; fails=$((fails+1)); else
  out=$(run_detect); code=$?
  if [ "$code" -eq 10 ] && echo "$out" | grep -q "$RID"; then echo "  PASS (検知: $RID)"; else echo "  FAIL (code=$code)"; fails=$((fails+1)); fi
  akamai appsec delete-custom-rule --section "$SECTION" --config "$CONFIG_ID" --custom-rule "$RID" >/dev/null 2>&1; RID=""
fi

echo "== T3: 版内容の変更（version-content 経路）→ exit 10 で検知 =="
RP_ID=$(akamai appsec rate-policies --section "$SECTION" --config "$CONFIG_ID" --json 2>/dev/null | jq -r '.ratePolicies[0].id')
LATEST=$(akamai appsec configs --section "$SECTION" --json 2>/dev/null | jq -r --arg n "$CONFIG_NAME" '.. | objects | select(.name?==$n) | .latestVersion')
CLONEV=$(akamai appsec clone --section "$SECTION" --config "$CONFIG_ID" --version "$LATEST" --json 2>/dev/null | jq -r '.version')
if [ -z "$RP_ID" ] || [ -z "$CLONEV" ]; then echo "  FAIL (rate policy/clone 取得失敗＝path#1 未検証。無言SKIPにしない)"; fails=$((fails+1)); else
  akamai appsec rate-policy --section "$SECTION" --config "$CONFIG_ID" --rate-policy "$RP_ID" --version "$CLONEV" --json 2>/dev/null > /tmp/dg_rp_orig.json
  RP_ORIG=/tmp/dg_rp_orig.json
  jq '.averageThreshold = (.averageThreshold + 1000)' /tmp/dg_rp_orig.json > /tmp/dg_rp_mod.json
  akamai appsec modify-rate-policy @/tmp/dg_rp_mod.json --section "$SECTION" --config "$CONFIG_ID" --rate-policy "$RP_ID" --version "$CLONEV" >/dev/null 2>&1
  cur=$(mktemp -d)
  akamai terraform --section "$SECTION" export-appsec --tfworkpath "$cur" "$CONFIG_NAME" >/dev/null 2>&1
  terraform fmt "$cur/modules/security" >/dev/null 2>&1
  out=$(run_detect --current "$cur"); code=$?
  if [ "$code" -eq 10 ] && echo "$out" | grep -q "export-diff"; then echo "  PASS (version-content 経路が発火)"; else echo "  FAIL (code=$code, version-content 未発火)"; fails=$((fails+1)); fi
  # 版削除（RP は版ごと消える）
  akamai appsec delete-config-version --section "$SECTION" --config "$CONFIG_ID" --version "$CLONEV" >/dev/null 2>&1; CLONEV=""
fi

echo "== T4: 後片付け後は再び無ドリフト → exit 0 =="
run_detect >/dev/null; [ $? -eq 0 ] && echo "  PASS" || { echo "  FAIL (後片付け後に drift 残存)"; fails=$((fails+1)); }

echo "== 結果: $fails 件 FAIL =="
exit $fails
