resource "random_id" "bucket" {
  byte_length = 4
}

locals {
  bucket_name = "s3-prod-bucket-${random_id.bucket.hex}"
  region      = "ap-southeast-2"
  env         = "production"
  account_id      = data.aws_caller_identity.current.account_id
  noncurrent_days = local.env == "production" ? 65 : 18
  retention = local.env == "production" ? 2 : 1
}

module "s3-bucket" {
  source                   = "terraform-aws-modules/s3-bucket/aws"
  version                  = "4.10.1"
  bucket                   = local.bucket_name
  force_destroy            = true
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  expected_bucket_owner    = local.account_id
 
  versioning = {
    status     = true
    mfa_delete = false
  }

  tags = {
    Owner = "Anton"
    Env   = local.env
  }

  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = "GOVERNANCE"
        days = local.retention
      }
    }
  }

  lifecycle_rule = [
    {
      id      = "default_rule"
      enabled = true

      filter = {
        prefix = ""
      }

      transition = [
        {
          days          = 60
          storage_class = "INTELLIGENT_TIERING"
        },
        {
          days          = 365
          storage_class = "GLACIER_IR"
        },
        {
          days          = 1095
          storage_class = "DEEP_ARCHIVE"
        }
      ],
      noncurrent_version_expiration = {
        days = local.noncurrent_days
      }
      }
  ]
} 

#https://github.com/terraform-aws-modules/terraform-aws-s3-bucket/blob/master/main.tf