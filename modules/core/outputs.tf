output "darktrace_cloud_security_core_iam_role_arn" {
  value       = aws_iam_role.default.arn
  description = "ARN of Darktrace/Cloud Core IAM Policy"
}
