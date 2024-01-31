#
# IAM
#

resource "aws_iam_role" "default" {
  name        = "DarktraceCloudRespondRole"
  description = "Darktrace/Cloud RESPOND Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.darktrace_cloud_security_core_iam_role_arn
        }
      }
    ]
  })

  managed_policy_arns = [aws_iam_policy.default.arn]
  tags                = var.darktrace_cloud_security_tags
}

resource "aws_iam_policy" "default" {
  name        = "DarktraceCloudRespondPolicy"
  description = "Darktrace/Cloud RESPOND Managed Policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ModifyInstanceAttribute",
          "ec2:DescribeInstances",
          "ec2:DeleteSecurityGroup",
          "ec2:DisassociateIamInstanceProfile",
          "ec2:AssociateIamInstanceProfile",
          "ec2:DescribeIamInstanceProfileAssociations",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:DetachUserPolicy",
          "iam:DetachRolePolicy",
          "iam:ListEntitiesForPolicy",
          "iam:PassRole",
          "lambda:PutFunctionConcurrency",
          "lambda:GetFunctionConcurrency",
          "lambda:DeleteFunctionConcurrency"
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.darktrace_cloud_security_tags
}
