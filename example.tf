variable "darktrace_cloud_security_external_id" {
  type        = string
  description = "Unique value used to identify your Darktrace/Cloud tenant"
}

module "darktrace_cloud_security_core" {
  source = "./modules/core"

  darktrace_cloud_security_aws_account_id = ""
  darktrace_cloud_security_external_id    = var.darktrace_cloud_security_external_id
}

module "darktrace_cloud_security_flow_logs" {
  source = "./modules/flow-logs"

  darktrace_cloud_security_core_iam_role_arn = module.darktrace_cloud_security_core.darktrace_cloud_security_core_iam_role_arn
}

module "darktrace_cloud_security_costing" {
  source = "./modules/costing"

  darktrace_cloud_security_core_iam_role_arn = module.darktrace_cloud_security_core.darktrace_cloud_security_core_iam_role_arn
}

module "darktrace_cloud_security_respond" {
  source = "./modules/respond"

  darktrace_cloud_security_core_iam_role_arn = module.darktrace_cloud_security_core.darktrace_cloud_security_core_iam_role_arn
}
