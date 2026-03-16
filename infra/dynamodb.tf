# DynamoDB table for nonce-to-credential mapping
resource "aws_dynamodb_table" "nonces" {
  name         = "locksmith-nonces-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # TTL auto-deletes expired nonces
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Encrypt at rest with our KMS key
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.locksmith.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "locksmith-nonces"
  }
}

# DynamoDB table for audit log
resource "aws_dynamodb_table" "audit" {
  name         = "locksmith-audit-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.locksmith.arn
  }

  tags = {
    Name = "locksmith-audit"
  }
}
