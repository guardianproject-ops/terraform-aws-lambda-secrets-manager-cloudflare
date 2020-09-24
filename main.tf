data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#########################################################################################
# IAM resources

data "aws_iam_policy_document" "lambda" {
  statement {
    effect = "Allow"
    sid    = "SecretsManagerActions"

    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]
    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.secret_prefix}"
    ]
    condition {
      test     = "StringEquals"
      variable = "secretsmanager:resource/AllowRotationLambdaArn"
      values   = [module.lambda.function_arn]

    }
  }
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      var.cloudwatch_log_group_arn
    ]
  }
}

data "aws_iam_policy_document" "other_secrets" {
  statement {
    effect = "Allow"
    sid    = "SecretsManagerActions"

    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue"
    ]
    resources = var.api_tunnel_service_key_arns
  }
}

resource "aws_iam_policy" "lambda" {
  name        = module.this.id
  description = "Allow rotation of cloudflare secrets"
  policy      = data.aws_iam_policy_document.lambda.json
}

resource "aws_iam_role_policy_attachment" "lambda" {
  role       = module.lambda.role_name
  policy_arn = aws_iam_policy.lambda.arn
}

resource "aws_iam_policy" "other_secrets" {
  count       = length(var.api_tunnel_service_key_arns) > 0 ? 1 : 0
  name        = module.this.id
  description = "Allow secret read access to other secrets"
  policy      = data.aws_iam_policy_document.other_secrets.json
}
resource "aws_iam_role_policy_attachment" "other_secrets" {
  count      = length(var.api_tunnel_service_key_arns) > 0 ? 1 : 0
  role       = module.lambda.role_name
  policy_arn = aws_iam_policy.other_secrets[0].arn
}

#########################################################################################
# Lambda resources

module "lambda" {
  source = "git::https://github.com/claranet/terraform-aws-lambda.git?ref=tags/v1.2.0"

  function_name = module.this.id
  description   = "Rotates Cloudflare secrets via AWS SecretsManager"
  handler       = "rotate.lambda_handler"
  runtime       = "python3.7"
  timeout       = 300

  // Specify a file or directory for the source code.
  source_path = "${path.module}/lambda/"

  // Add additional trusted entities for assuming roles (trust relationships).
  trusted_entities = ["secretsmanager.amazonaws.com"]

  // Add environment variables.
  environment = {
    variables = {
      CF_API_TOKEN          = var.api_token
      CF_API_KEY            = var.api_key
      CF_API_EMAIL          = var.api_email
      CF_API_CERTKEY        = var.api_origin_key
      CF_TUNNEL_SERVICE_KEY = var.api_tunnel_service_key
    }
  }

  tags = module.this.tags
}

resource "aws_lambda_alias" "default" {
  name             = "default"
  description      = "Use latest version as default"
  function_name    = module.lambda.function_name
  function_version = "$LATEST"
}

resource "aws_lambda_permission" "secretsmanager" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.function_name
  principal     = "secretsmanager.amazonaws.com"
  statement_id  = "AllowExecutionFromSecretsManager1"
}


#########################################################################################
# Cloudwatch metric

module "label_cw" {
  source     = "git::https://github.com/cloudposse/terraform-null-label.git?ref=tags/0.19.2"
  context    = module.this.context
  attributes = ["cw", "failed-rotations"]
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  count = var.create_cloudwatch_log_metric ? 1 : 0

  name           = module.label_cw.id
  pattern        = "{ ($.eventSource = secretsmanager.amazonaws.com) && ($.eventName = RotationFailed) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = var.cloudwatch_metric_name
    namespace = var.cloudwatch_metric_namespace
    value     = 1
  }
}
