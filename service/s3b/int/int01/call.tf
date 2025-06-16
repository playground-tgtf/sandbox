resource "random_id" "bucket" {
  byte_length = 4
}

locals {
  bucket_name     = "s3-int-bucket-${random_id.bucket.hex}"
  region          = "ap-southeast-2"
  account_id      = data.aws_caller_identity.current.account_id
  env             = "INT"
  noncurrent_days = local.env == "production" ? 65 : 18
  retention       = local.env == "production" ? 2 : 1
}

module "int01_bucket" {
  source                                = "../../../../module/s3"
  create_bucket                         = true
  attach_deny_insecure_transport_policy = true
  attach_allow_iam_roles_policy         = true
  bucket                                = local.bucket_name
  force_destroy                         = true
  control_object_ownership              = true
  object_ownership                      = "BucketOwnerPreferred"
  expected_bucket_owner                 = local.account_id

  versioning = {
    status     = true
    mfa_delete = false
  }

  bucket_additional_tags = {
    Name             = local.bucket_name
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

module "int02_bucket" {
  source                                = "git::https://github.com/playground-tgtf/modules.git//s3?ref=v1.0.0"
  create_bucket                         = true
  attach_deny_insecure_transport_policy = true
  attach_allow_iam_roles_policy         = true
  bucket                                = "suresh-int02"
  force_destroy                         = true
  control_object_ownership              = true
  object_ownership                      = "BucketOwnerPreferred"
  expected_bucket_owner                 = local.account_id

  versioning = {
    status     = true
    mfa_delete = false
  }

  bucket_additional_tags = {
    Name             = "suresh-int02"
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

module "int03_bucket" {
  source                                = "git::https://github.com/playground-tgtf/modules.git//s3?ref=v1.0.0"
  create_bucket                         = true
  attach_deny_insecure_transport_policy = true
  attach_allow_iam_roles_policy         = true
  bucket                                = "suresh-int03"
  force_destroy                         = true
  control_object_ownership              = true
  object_ownership                      = "BucketOwnerPreferred"
  expected_bucket_owner                 = local.account_id

  versioning = {
    status     = true
    mfa_delete = false
  }

  bucket_additional_tags = {
    Name             = "suresh-int03"
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




# "git::https://github.com/playground-tgtf/modules.git//S3?ref=v1.0.0"



