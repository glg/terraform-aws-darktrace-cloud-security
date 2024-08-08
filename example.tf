variable "darktrace_cloud_security_external_id" {
  type        = string
  description = "Unique value used to identify your Darktrace/Cloud tenant"
}

module "darktrace_cloud_security_core" {
  source  = "darktrace/darktrace-cloud-security/aws//modules/core"
  version = "1.0.0"

  darktrace_cloud_security_aws_account_id = ""
  darktrace_cloud_security_external_id    = var.darktrace_cloud_security_external_id
}

module "darktrace_cloud_security_flow_logs" {
  source                                     = "darktrace/darktrace-cloud-security/aws//modules/flow-logs"
  version                                    = "1.0.0"
  darktrace_cloud_security_core_iam_role_arn = module.darktrace_cloud_security_core.darktrace_cloud_security_core_iam_role_arn
}

module "darktrace_cloud_security_costing" {
  source                                     = "darktrace/darktrace-cloud-security/aws//modules/costing"
  version                                    = "1.0.0"
  darktrace_cloud_security_core_iam_role_arn = module.darktrace_cloud_security_core.darktrace_cloud_security_core_iam_role_arn
}

module "darktrace_cloud_security_respond" {
  source                                     = "darktrace/darktrace-cloud-security/aws//modules/respond"
  version                                    = "1.0.0"
  darktrace_cloud_security_core_iam_role_arn = module.darktrace_cloud_security_core.darktrace_cloud_security_core_iam_role_arn
}
