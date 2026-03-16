output "api_gateway_url" {
  description = "Agent proxy endpoint (API Gateway)"
  value       = aws_apigatewayv2_api.locksmith.api_endpoint
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.locksmith.function_name
}

output "lightsail_ip" {
  description = "Lightsail static IP (browser proxy)"
  value       = aws_lightsail_static_ip.locksmith.ip_address
}

output "lightsail_instance_name" {
  description = "Lightsail instance name"
  value       = aws_lightsail_instance.locksmith.name
}

output "dynamodb_nonces_table" {
  description = "DynamoDB nonces table name"
  value       = aws_dynamodb_table.nonces.name
}

output "dynamodb_audit_table" {
  description = "DynamoDB audit table name"
  value       = aws_dynamodb_table.audit.name
}

output "kms_key_id" {
  description = "KMS key ID for envelope encryption"
  value       = aws_kms_key.locksmith.key_id
}

output "kms_key_arn" {
  description = "KMS key ARN"
  value       = aws_kms_key.locksmith.arn
}
