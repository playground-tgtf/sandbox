locals {
  account_id      = data.aws_caller_identity.current.account_id
}

locals {
  bucket_name     = "s3-${lower(var.env)}-${local.account_id}"
  region          = "ap-southeast-2"
  noncurrent_days = var.env == "production" ? 65 : 18
  retention       = var.env == "production" ? 2 : 1
  env             = var.env
  #noncurrent_days = local.env == "production" ? 65 : 18
  #retention       = local.env == "production" ? 2 : 1
}

module "int02_bucket" {
  source                                = "../../../../module/s3"
  create_bucket                         = true
  attach_deny_insecure_transport_policy = true
  attach_allow_iam_roles_policy         = true
  bucket                                = "suresh-int01"
  force_destroy                         = true
  control_object_ownership              = true
  object_ownership                      = "BucketOwnerPreferred"
  expected_bucket_owner                 = local.account_id

  versioning = {
    status     = true
    mfa_delete = false
  }

  bucket_additional_tags = {
    Name             = "suresh-int01"
    ApplicationOwner = "sureshanand.kumar@resolutionlife.com.au"
    AppSupportGroup  = "RLSA_Life_Integration_Support"
    AppApproverGroup = "RLSA_Reslife_Integration_Approver"
    Criticality      = "2"
  }
  mandatory_tags = {
    Application        = "SSIS"
    CostCenter         = "50107"
    Function           = "File_Services"
    Environment        = local.env
    DataClassification = "Confidential"
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
      id      = "default_lifecycle"
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