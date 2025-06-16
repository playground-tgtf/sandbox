terraform {
    required_providers {
      aws = {
        source = "hashicorp/aws"
        version = ">=4.35.0"
      }
      random = {
        source = "hashicorp/random"
        version = "3.7.2"
      }
    }
    required_version = "1.5.7"
}

provider "aws" {
    region = local.region
    profile = "default"
}