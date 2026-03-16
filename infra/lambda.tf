# Lambda function — agent API proxy
resource "aws_lambda_function" "locksmith" {
  function_name = "locksmith-proxy-${var.environment}"
  role          = aws_iam_role.lambda.arn
  handler       = "lambda.handler"
  runtime       = "nodejs20.x"
  timeout       = 30
  memory_size   = 256

  filename         = "${path.module}/../dist/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/../dist/lambda.zip")

  environment {
    variables = {
      ENVIRONMENT        = var.environment
      DYNAMODB_TABLE     = aws_dynamodb_table.nonces.name
      AUDIT_TABLE        = aws_dynamodb_table.audit.name
      KMS_KEY_ID         = aws_kms_key.locksmith.key_id
      AWS_REGION_DEPLOY  = var.aws_region
      ENTRA_TENANT_ID    = var.entra_tenant_id
      ENTRA_CLIENT_ID    = var.entra_client_id
    }
  }

  depends_on = [aws_iam_role_policy.lambda]
}

# API Gateway v2 (HTTP API) — agent ingress
resource "aws_apigatewayv2_api" "locksmith" {
  name          = "locksmith-${var.environment}"
  protocol_type = "HTTP"
  description   = "Locksmith agent credential proxy"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.locksmith.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.locksmith.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.locksmith.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.locksmith.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId    = "$context.requestId"
      ip           = "$context.identity.sourceIp"
      method       = "$context.httpMethod"
      path         = "$context.path"
      status       = "$context.status"
      responseTime = "$context.responseLatency"
    })
  }
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.locksmith.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.locksmith.execution_arn}/*/*"
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/locksmith-${var.environment}"
  retention_in_days = 90
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/locksmith-proxy-${var.environment}"
  retention_in_days = 90
}
