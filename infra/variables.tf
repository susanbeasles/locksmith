variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "lightsail_instance_size" {
  description = "Lightsail instance bundle (nano_3_0 = $5/mo, micro_3_0 = $10/mo)"
  type        = string
  default     = "nano_3_0"
}

variable "lightsail_availability_zone" {
  description = "Lightsail AZ"
  type        = string
  default     = "us-east-1a"
}

variable "entra_tenant_id" {
  description = "Microsoft Entra ID tenant ID"
  type        = string
  sensitive   = true
}

variable "entra_client_id" {
  description = "Locksmith Entra app registration client ID"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "Domain for the locksmith proxy"
  type        = string
  default     = "locksmith.internal.sonarmd.com"
}

variable "nonce_ttl_default" {
  description = "Default nonce TTL in seconds"
  type        = number
  default     = 900
}
