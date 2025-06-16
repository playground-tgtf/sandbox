terraform {
  backend "local" {
    path = "/Users/suresh/workspace/service/s3b/terraform.tfstate"
  }
}

data "aws_caller_identity" "current" {}