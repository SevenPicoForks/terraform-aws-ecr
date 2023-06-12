provider "aws" {
  region = var.region
}

module "ecr" {
  source = "../../"

  encryption_configuration = {
    encryption_type = "KMS"
    kms_key         = ""
  } #var.encryption_configuration

  context = module.context.self
}
