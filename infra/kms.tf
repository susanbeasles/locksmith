# KMS key for envelope encryption of credentials
resource "aws_kms_key" "locksmith" {
  description             = "Locksmith credential envelope encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "LambdaDecrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "locksmith" {
  name          = "alias/locksmith-${var.environment}"
  target_key_id = aws_kms_key.locksmith.key_id
}

data "aws_caller_identity" "current" {}
