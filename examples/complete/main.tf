provider "aws" {
  region = var.region
}

module "ecr" {
  #checkov:skip=CKV_AWS_136:ECR repositories can be encrypted using KMS through variable
  source = "../../"

  encryption_configuration = var.encryption_configuration

  context = module.context.self
}
