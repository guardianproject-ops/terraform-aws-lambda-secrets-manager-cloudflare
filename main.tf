data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "null_resource" "lambda" {
  triggers = {
    build_number = var.build_number
  }
  provisioner "local-exec" {
    command = "cd ${path.module} && make artifact"
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/artifacts/lambda"
  output_path = "${path.module}/artifacts/lambda-${null_resource.lambda.triggers.build_number}.zip"
  depends_on  = [null_resource.lambda]
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "lambda" {
  name               = module.this.id
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = module.this.tags
}

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
      values   = [aws_lambda_function.default.arn]

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
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda.arn
}

resource "aws_iam_policy" "other_secrets" {
  count       = length(var.api_tunnel_service_key_arns) > 0 ? 1 : 0
  name        = module.this.id
  description = "Allow secret read access to other secrets"
  policy      = data.aws_iam_policy_document.other_secrets.json
}

resource "aws_iam_role_policy_attachment" "other_secrets" {
  count = length(var.api_tunnel_service_key_arns) > 0 ? 1 : 0

  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.other_secrets[0].arn
}

resource "aws_iam_role_policy_attachment" "lambda_eni" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaENIManagementAccess"
}

resource "aws_lambda_function" "default" {
  function_name    = module.this.id
  filename         = data.archive_file.lambda_zip.output_path
  handler          = "rotate.lambda_handler"
  role             = aws_iam_role.lambda.arn
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.7"
  timeout          = 300
  tags             = module.this.tags

  environment {
    variables = {
      CF_API_TOKEN          = var.api_token
      CF_API_KEY            = var.api_key
      CF_API_EMAIL          = var.api_email
      CF_API_CERTKEY        = var.api_origin_key
      CF_TUNNEL_SERVICE_KEY = var.api_tunnel_service_key
    }
  }
}

resource "aws_lambda_permission" "secretsmanager" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.default.function_name
  principal     = "secretsmanager.amazonaws.com"
  statement_id  = "AllowExecutionFromSecretsManager1"
}

resource "aws_lambda_alias" "default" {
  name             = "default"
  description      = "Use latest version as default"
  function_name    = aws_lambda_function.default.function_name
  function_version = "$LATEST"
}
