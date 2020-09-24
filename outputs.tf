output "lambda" {
  value = module.lambda

  depends_on = [
    # the policy must be attached before the lambda is usable
    aws_iam_role_policy_attachment.lambda,
    # secretsmanager must have permission before the lambda is usable
    aws_lambda_permission.secretsmanager
  ]
}

output "cloudwatch_metric_name" {
  value = var.cloudwatch_metric_name
}

output "cloudwatch_metric_namespace" {
  value = var.cloudwatch_metric_namespace
}
