variable "darktrace_cloud_security_tags" {
  type        = map(any)
  description = "Common tags to add to resources"
  default     = null
}

variable "darktrace_cloud_security_core_iam_role_arn" {
  type        = string
  description = "ARN of Darktrace/Cloud Core IAM Policy"
}

variable "existing_cur_report_name" {
  type        = string
  description = "Existing CUR Report Name"
  default     = null
}

variable "existing_cur_bucket_name" {
  type        = string
  description = "Existing CUR Bucket Name"
  default     = null
}

variable "existing_cur_bucket_prefix" {
  type        = string
  description = "Existing CUR Bucket Prefix"
  default     = null
}
