
output "cf_dns_token_arn" {
  value = aws_secretsmanager_secret.cf_dns_token.arn
}
output "cf_tunnel_service_key_arn" {
  value = aws_secretsmanager_secret.cf_tunnel_service_key.arn
}


output "cf_argo_tunnel_token_arn" {
  value = aws_secretsmanager_secret.cf_argo_tunnel_token.arn
}