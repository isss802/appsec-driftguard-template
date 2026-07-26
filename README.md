# appsec-driftguard

Akamai **App & API Protector**（AppSec / WAF）の Security Configuration を Terraform で
管理していると、Akamai Control Center（以下 ACC）から手作業で設定が変わることがあります
（攻撃対応の緊急変更、サポート作業など）。すると Terraform が把握している状態と実体がズレます。
これを **ドリフト（drift）** と呼びます。

**appsec-driftguard** は、そのドリフトを GitHub Actions で検知し、
「何がどう変わったか」と「それを Terraform に取り込むためのサンプルコード」を
**Issue で通知**する仕組みです。Terraform を手動で運用しているチームでも、
プルリクエストや自動反映を前提にせず「気づいて、必要なら取り込む」だけで運用できます。

---

## 仕組み

Akamai の設定変更には2種類あり、片方だけを見ると取りこぼします。そこで検知を2段構えにします。

```mermaid
flowchart LR
  ACC[ACC で手動変更] --> CFG[Security Config]
  CFG --> D1[① export の差分<br/>版に入った変更]
  CFG --> D2[② API 一覧の差分<br/>未割り当ての定義など]
  D1 --> J{ドリフト?}
  D2 --> J
  J -- あり --> ISSUE[Issue を作成<br/>差分 + 取り込み用 Terraform]
  J -- なし --> NOOP[何もしない]
```

**① 版の内容を比べる（export の差分）**
`akamai terraform export-appsec` で現在の設定を HCL（Terraform の設定言語）として書き出し、リポジトリに保存した
基準（baseline）と比べます。export は決定的（同じ設定を2回書き出すと一致する）なので、
差分がそのまま「変わった箇所」になります。rate policy の値、ポリシーに割り当てた custom rule、
WAF mode などはここで拾えます。

**② config レベルのオブジェクト一覧を比べる（API の差分）**
ポリシーに割り当てていない custom rule の定義などは、版の export に出ません
（`terraform plan` にも出ません）。そこで custom rules / rate policies の一覧を API で取得し、
baseline と比べます。

この2つを合わせることで、「版に入る変更」も「版に出ない定義」も検知できます。

---

## 通知される Issue

ドリフトを検知すると、次の内容の Issue が自動で立ちます。

- 何がどう変わったかの差分
- それを手元の Terraform に取り込むためのサンプル `resource` ブロック（`jsonencode` 込み）
- 新規オブジェクトを Terraform の管理下に入れる `terraform import` コマンド

読んだ人が、採用するならサンプルを `.tf` に反映して `terraform apply`、
不要なら ACC 側を元に戻します。落ち着いたら baseline を更新して Issue を閉じます。

---

## 前提

- **Akamai CLI**（本体）＋プラグイン `appsec` / `terraform`
  （検知ワークフローは CI 内で自動導入します。**CLI 本体・プラグイン・Terraform はすべて版を固定**しています。
  プラグインを `akamai install`（＝常に最新）任せにすると export 出力が変わって baseline と食い違い、
  偽ドリフトを招くため。版は `drift-detect.yml` の `CLI_VER` / `TF_PLUGIN_VER` / `APPSEC_PLUGIN_VER` で管理します）
- **Terraform**（`terraform fmt` / 反映で使用）
- **Python 3**
- **`.edgerc`** に `[default]` セクション（このテンプレートは section=`default` を前提。
  別名にする場合はワークフローと baseline 作成コマンドの section を合わせてください）

## クイックスタート

1. このリポジトリを、**自分の private なリポジトリ**にコピーします。
   （ドリフト Issue には設定の中身が載るため、運用リポジトリは private にしてください。）

2. GitHub のリポジトリ設定で次を登録します。

   | 種別 | 名前 | 内容 |
   |---|---|---|
   | Secret | `EDGERC` | Akamai の `.edgerc`（API 認証情報） |
   | Variable | `APPSEC_CONFIG_NAME` | 対象 Security Config の名前 |
   | Variable | `APPSEC_CONFIG_ID` | 対象 Security Config の ID |

3. 検知の基準（baseline）を作って commit します。

   ```bash
   # 版の内容（HCL）と、config レベルのオブジェクト一覧の2つを baseline に保存する
   akamai terraform export-appsec --tfworkpath ./baseline "<config 名>"
   terraform fmt ./baseline/modules/security
   python3 lib/make_baseline.py <config id>          # → baseline/objects.json
   git add -f baseline && git commit -m "add baseline"
   ```

   `baseline/` は `.gitignore` 済みです（実データを誤って公開しないため）。
   自分の private リポジトリで運用するときだけ、`-f` を付けて意図的に commit します。
   **baseline を作らずにワークフローを回すと、検知は clean 扱いせず異常終了（赤）します**
   （設定ミスを見逃さないための挙動）。必ず先に baseline を commit してください。

4. Actions の **appsec-drift-detect** を実行します（毎時自動、または手動）。
   ドリフトがあれば Issue が立ちます。無ければ何もしません。

---

## 含まれるもの

| パス | 役割 |
|---|---|
| `lib/detect.py` | 検知の本体（2段の差分判定） |
| `lib/adopt.py` | 検知結果を Issue 本文（差分＋取り込み用 Terraform）に変換 |
| `lib/make_baseline.py` | baseline の `objects.json` を作るヘルパー |
| `.github/workflows/drift-detect.yml` | 検知して Issue を立てるワークフロー |
| `.github/workflows/apply.yml` | Terraform を反映するワークフロー（任意・下記参照） |
| `terraform/drift-gate.tf` | 反映前に「稼働版が想定どおりか」を確認する例 |
| `tests/` | 単体テストと、実 config に対する結合テスト |

`apply.yml` と `terraform/drift-gate.tf` は、承認付きで Terraform を反映したいチーム向けの
**テンプレート**です。使う場合は自分の Terraform 構成一式と、GitHub の Environments
（staging / production の承認者）を用意してください。本番反映は影響が大きいため、
承認を必須にすることを前提にしています。

---

## テスト

```bash
python3 tests/test_detect.py     # 検知ロジック
python3 tests/test_adopt.py      # Issue / Terraform 生成
```

実 config に対する結合テスト（可逆・実行後に自動で後片付け）:

```bash
CONFIG_NAME="<config 名>" CONFIG_ID="<config id>" bash tests/live_integration.sh
```

---

## 知っておくべきこと

- **ドリフト Issue には設定の中身（WAF ルール等）が載ります。** 運用リポジトリは必ず private に。
  この公開テンプレートには実データを含めていません（`baseline/` は `.gitignore` 済み）。
- ポリシーに未割り当ての定義など、一部は `.tf` の差分には現れません。その分は Issue に
  サンプルコードと `import` コマンドを添えます。
- Akamai の version は、いちど有効化すると編集できません。変更は新しい version を作って行います。
  反映する version を `latest_version` に任せず明示するのが安全です（外部で作られた版まで拾わないため）。
- 検知は cron 周期で走るので、変更から通知までにラグがあります。
- **open な drift Issue が1件でも残っていると、次のドリフトは新しい Issue を作りません**
  （毎時の重複を防ぐため）。対応が済んだら Issue を閉じてください。閉じ忘れると通知が止まります。
- private リポジトリにコピー後、**Actions を有効化**し、ワークフローが Issue を作れるよう
  権限（`issues: write`。Org で GITHUB_TOKEN を read-only に絞っている場合は要確認）を整えてください。

---

## 設定

- 検知の頻度: `.github/workflows/drift-detect.yml` の `schedule` の cron を変更。
- 対象 config: `APPSEC_CONFIG_NAME` / `APPSEC_CONFIG_ID`（Variable）。
- 認証: `EDGERC`（Secret）。最小権限のクレデンシャルを推奨します。
