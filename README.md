# appsec-driftguard

> **このテンプレートについて**: 公開用のコードのみ。実 config の `baseline/` は `.gitignore` 済みで含まれない。デプロイ時は自分の **private** repo でこのコードを使い、`baseline/` を作って（`git add -f baseline` 等で）意図的に commit する。ドリフト Issue には実 config の中身が載るため、運用 repo は private にすること。

Akamai Security Config（App & API Protector）の out-of-band 変更（Akamai Control Center = ACC 側の手動変更）を
GitHub Actions で検知し、差分＋取り込み用 Terraform を載せた Issue を立てる仕組み。Terraform 運用時の drift-gate 設計を CI に落としたもの。

## 検知の考え方（二段。実測に基づく）

1. **版の内容 — export-diff**
   `akamai terraform export-appsec` は決定的（同一 config を2回 export すると
   `terraform fmt` 後に完全一致）。commit 済みの baseline export と、いま再 export した
   ものを突き合わせれば、版に入っている変更（rate policy のフィールド、policy に
   割り当てられた custom rule、WAF mode 等）を本物の差分として拾える。

2. **config レベルのオブジェクト — 一覧 diff**
   未使用（policy に未割り当て）の custom rule 定義は、版の export に出ない
   （config レベルで、版番号も上がらない）。`terraform plan` にも出ない。
   そのため custom rules / rate policies の API 一覧を baseline と突き合わせ、
   一覧側の増減・変更を拾う。

この2つを合わせて初めて「気づく」が塞がる。版番号の突き合わせ（precondition）だけでは
新規オブジェクトを取りこぼす。

## 構成

- `lib/adopt.py` — 検知結果を Issue 本文（差分＋取り込み用 Terraform サンプル）に変換。
- `lib/detect.py` — 検知の核。純関数 `classify()` が全判定を持ち、live 依存
  （akamai CLI / terraform fmt）は `main()` に隔離。exit 2 = drift あり、0 = clean。
- `tests/test_detect.py`（43）／`tests/test_adopt.py`（10）— 純関数の単体テスト。
- `tests/live_integration.sh` — 実 config に対する結合テスト（可逆・後片付けつき）。
- `baseline/` — commit する基準。`modules/security/*.tf`（fmt 済み export）＋ `objects.json`。
- `.github/workflows/drift-detect.yml` — 毎時＋手動。drift があれば Issue を立てる（差分＋取り込み用 Terraform 付き）。
- `.github/workflows/apply.yml` — main への merge で apply。staging 自動、production は
  Environment 承認必須（本番反映の人間ゲート）＋ drift-gate（precondition）。

## 運用フロー

- drift-detect が ACC 変更を検知 → **Issue を自動で立てる**。本文に「分かりやすい差分」と
  「それを手元の .tf に取り込むためのサンプル Terraform（＋新規は import コマンド）」を載せる。
- 人が Issue を読み、採用なら提示された HCL を手元の config に反映して apply、棄却なら ACC を
  元に戻す。落ち着いたら baseline を更新して Issue を閉じる。
- ツールは「確実に気づかせる＋取り込みの下書きを渡す」までを担い、reconcile は人が判断する
  （手動 Terraform 運用に合わせ、PR の自動生成・自動 apply は前提にしない）。
- 本番反映を CI で回したい場合のみ `apply.yml`（staging 自動 / production 承認）を使う。

## 既知の限界（正直に）

- **未割り当ての config レベル定義**は `.tf` 差分に現れない。detect は一覧 diff で
  「あること」は検知し、Issue 本文に import コマンド付きのサンプルを出す。
- **版の不変性**: active/pending な版は直接編集できない。編集は新しい版で行う
  （ACC の UI・provider・CLI いずれも同じ）。
- **検知側（`lib/detect.py` ＋ 二段検知）は完動・テスト済み**（detect 43＋adopt 10 の単体、live 結合 4）。
  一方 **`apply.yml` と `terraform/drift-gate.tf` は雛形**で、単体では動かない。
  利用者の terraform root（export した modules 一式＋provider＋backend 設定）に
  `terraform/drift-gate.tf` の precondition を統合して初めて「版のズレを apply 時に止める」
  安全性が成立する。この雛形だけを `terraform init` しても provider/backend/modules が
  無く失敗する。本番 apply は不可逆で影響が大きく（Akamai 認証を CI に置く・本番反映）、
  Environment 承認・precondition・最小権限クレデンシャルを揃えて運用側の承認で有効化する。
- **検知は cron 周期**。緊急変更にはラグが出る。日常の plan と併用する。

## 公開安全（機密はリポジトリに置かない）

このリポジトリはパブリック公開を前提に、機密・実データを一切コードに含めない。
外から `secrets` / `vars` で引き込む。

GitHub 側で設定するもの:

- **Secret `EDGERC`**: Akamai の `.edgerc`（認証）。ワークフローが実行時に書き出す。
  最小権限（対象 config の read／必要な activate のみ）のクレデンシャルにする。
- **Variable `APPSEC_CONFIG_NAME`** / **`APPSEC_CONFIG_ID`**: 対象 config の名前と ID。
- **Environments** `staging`（自動）／`production`（Required reviewers を付ける＝本番の人間承認）。

リポジトリに入らないもの（`.gitignore` 済み）:

- `tests/live_baseline/`・`tests/live_baseline_objs.json`（実 config の export＝実ホスト名/ID/ルールを含む）。
- `*.tfstate` / `*.tfplan` / `.terraform/`。

`baseline/`（検知の基準）は commit するが、これは **公開してよい範囲の config か** を必ず確認してから入れる（WAF ルールのロジックが読める）。機微なら private のままにする。

## baseline の作り方

```bash
akamai terraform --section default export-appsec --tfworkpath ./baseline "<config 名>"
terraform fmt ./baseline/modules/security
python3 -c "import sys;sys.path.insert(0,'lib');import detect,json;\
json.dump(detect.live_objlists(<config id>,'default'),open('baseline/objects.json','w'),ensure_ascii=False,indent=2)"
git add baseline && git commit -m "appsec baseline"
```
