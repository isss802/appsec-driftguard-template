# drift-gate の実体（apply.yml が参照する precondition）。
# 実 config の terraform 構成（export した modules 一式）と合わせて使う。
# ここは activation リソースに「基準 version との突き合わせ」を足す最小例。
#
# 検証済みの挙動:
#   - expected_*_version は「今その環境に載っているはずの版（基準）」。CI の gate ジョブが
#     承認/審査の前に読んで -var で渡す。activate する新版そのものと突き合わせない。
#   - 基準と live がズレていれば plan の時点で止まる（precondition, exit 1）。
#   - activate する版は latest_version 任せにせず明示（外部で作られた版を拾わないため）。

variable "expected_staging_version" {
  type        = number
  description = "staging に載っているはずの版（gate が承認前に読んだ現在値）"
}

variable "expected_prod_version" {
  type        = number
  description = "production に載っているはずの版（gate が承認前に読んだ現在値）"
}

variable "target_staging_version" {
  type        = number
  description = "staging に activate する版（terraform apply が作った版）"
  default     = null
}

data "akamai_appsec_configuration" "this" {
  name = var.config_name
}

variable "config_name" {
  type = string
}

resource "akamai_appsec_activations" "staging" {
  count               = var.target_staging_version == null ? 0 : 1
  config_id           = data.akamai_appsec_configuration.this.config_id
  version             = var.target_staging_version
  network             = "STAGING"
  notification_emails = var.notification_emails

  lifecycle {
    precondition {
      condition     = data.akamai_appsec_configuration.this.staging_version == var.expected_staging_version
      error_message = "AppSec drift: staging の version=${data.akamai_appsec_configuration.this.staging_version} が想定(${var.expected_staging_version})とズレています。中身を確認してから apply してください。"
    }
  }
}

# 本番は「今 production に載っている版が基準どおりか」だけを止める非ブロッキング／ブロッキングの要。
# activate する本番版は運用に応じて別途指定する（ここでは gate のみ）。
resource "terraform_data" "prod_gate" {
  lifecycle {
    precondition {
      condition     = data.akamai_appsec_configuration.this.production_version == var.expected_prod_version
      error_message = "AppSec drift: production の version=${data.akamai_appsec_configuration.this.production_version} が想定(${var.expected_prod_version})とズレています。"
    }
  }
}

variable "notification_emails" {
  type    = list(string)
  default = []
}
