module "this" {
  source      = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.19.2"
  namespace   = "gp-ops"
  environment = "dev"
  name        = "cf-rotate"
}

#############################################################################
# Rotation Lambda
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${module.this.id}"
  retention_in_days = 7
}

module "cf_rotate" {
  source = "../"

  # only necessary to pass the credentials needed for the secrets that this lambda will rotate
  api_token              = var.api_token
  api_key                = var.api_key
  api_email              = var.api_email
  api_origin_key         = var.api_origin_key
  api_tunnel_service_key = var.api_tunnel_service_key

  cloudwatch_log_group_arn  = aws_cloudwatch_log_group.lambda.arn
  cloudtrail_log_group_name = var.cloudtrail_log_group_name
  secret_prefix             = "${module.this.id}/cloudflare/*"
  context                   = module.this.context
}

#############################################################################
# Cloudflare API Token
resource "aws_secretsmanager_secret" "cf_dns_token" {
  name = "${module.this.id}/cloudflare/dns_api_token3"
  tags = module.this.tags
}

resource "aws_secretsmanager_secret_rotation" "cf_dns_token" {
  secret_id           = aws_secretsmanager_secret.cf_dns_token.id
  rotation_lambda_arn = module.cf_rotate.lambda.arn

  rotation_rules {
    automatically_after_days = 1
  }
}

resource "aws_secretsmanager_secret_version" "cf_dns_token" {
  secret_id = aws_secretsmanager_secret.cf_dns_token.id
  secret_string = jsonencode({
    "Type" : "apiToken",
    "Attributes" : {
      "Name" : "${module.this.id}-cf-dns-token",
      "Policies" : [
        { "effect" : "allow",
          "permission_groups" : [
            { "id" : "4755a26eedb94da69e1066d98aa820be", "name" : "DNS Write" }
          ],
      "resources" : { "com.cloudflare.api.account.zone.${var.zone_id}" : "*" } }],
      "ValidDays" : 7
  } })
  version_stages = ["CFINIT"]
}

#############################################################################
# Cloudflare Tunnel Service key

resource "aws_secretsmanager_secret" "cf_tunnel_service_key" {
  name = "${module.this.id}/cloudflare/tunnel_service_key3"
  tags = module.this.tags
}

resource "aws_secretsmanager_secret_rotation" "cf_tunnel_service_key" {
  secret_id           = aws_secretsmanager_secret.cf_tunnel_service_key.id
  rotation_lambda_arn = module.cf_rotate.lambda.arn

  rotation_rules {
    automatically_after_days = 1
  }
}

resource "aws_secretsmanager_secret_version" "cf_tunnel_service_key" {
  secret_id = aws_secretsmanager_secret.cf_tunnel_service_key.id
  secret_string = jsonencode({
    "Type" : "tunnelServiceKey",
    "Attributes" : {
      "KeyValue" : ""
  } })
  version_stages = ["CFINIT"]
}

#############################################################################
# Cloudflare Argo Tunnel Token

resource "aws_secretsmanager_secret" "cf_argo_tunnel_token" {
  name = "${module.this.id}/cloudflare/argo_tunnel_token3"
  tags = module.this.tags
}

resource "aws_secretsmanager_secret_rotation" "cf_argo_tunnel_token" {
  secret_id           = aws_secretsmanager_secret.cf_argo_tunnel_token.id
  rotation_lambda_arn = module.cf_rotate.lambda.arn

  rotation_rules {
    automatically_after_days = 1
  }
}

resource "aws_secretsmanager_secret_version" "cf_argo_tunnel_token" {
  secret_id = aws_secretsmanager_secret.cf_argo_tunnel_token.id
  secret_string = jsonencode({
    "Type" : "argoTunnelToken",
    "Attributes" : {
      "Hostname" : var.hostname,
      "ValidityDays" : 7,
      "TunnelServiceKeyArn" : aws_secretsmanager_secret.cf_tunnel_service_key.arn,
      "ZoneId" : var.zone_id
  } })
  version_stages = ["CFINIT"]
}
