provider "aws" {
  region = "us-east-2"
}

module "ecr" {
  #checkov:skip=CKV_AWS_136:ECR repositories can be encrypted using KMS through variable
  source       = "../../"
  namespace    = "eg"
  stage        = "dev"
  name         = "app"
  use_fullname = false
  image_names  = ["redis", "nginx"]
}
