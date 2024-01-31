variable "darktrace_cloud_security_aws_account_id" {
  type        = string
  description = "Darktrace AWS Account ID"
}

variable "darktrace_cloud_security_tags" {
  type        = map(any)
  description = "Common tags to add to resources"
  default     = null
}

variable "is_organization_admin_account" {
  type        = bool
  description = "Applies resources required for the Organization admin account when set to true"
  default     = false
}

variable "setup_cloudtrail" {
  type        = bool
  description = "Setup CloudTrail for Darktrace/Cloud"
  default     = false
}

variable "autoconfigure_cloudtrail" {
  type        = bool
  description = "Configure event selectors on CloudTrail for Darktrace/Cloud"
  default     = false
}

variable "darktrace_cloud_security_external_id" {
  type        = string
  description = "Unique value used to identify your Darktrace/Cloud tenant"
  sensitive   = true
}

variable "existing_cloudtrail_name" {
  type        = string
  description = "Existing CloudTrail Name"
  default     = null
}

variable "existing_cloudtrail_bucket_name" {
  type        = string
  description = "Existing CloudTrail Bucket Name"
  default     = null
}
