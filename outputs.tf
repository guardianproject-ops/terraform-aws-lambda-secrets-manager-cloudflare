output "lambda" {
  description = "the lambda resource output"
  value       = aws_lambda_function.default
}

output "cloudwatch_metric_name" {
  value = var.cloudwatch_metric_name
}

output "cloudwatch_metric_namespace" {
  value = var.cloudwatch_metric_namespace
}
