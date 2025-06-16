variable "aws_region" {
  type        = string
  default     = "ap-southeast-2"
  description = "sydney region"
}

variable "create_bucket" {
  description = "Controls if S3 bucket should be created"
  type        = bool
  default     = true
}

variable "attach_deny_insecure_transport_policy" {
  description = "Controls if S3 bucket should have deny non-SSL transport policy attached"
  type        = bool
  default     = false
}

variable "attach_additional_custom_policy" {
  description = "Controls if S3 bucket should have an additional bucket policy attached (set to `true` to use value of `additional_custom_policy` as bucket policy)"
  type        = bool
  default     = false
}

variable "attach_public_policy" {
  description = "Controls if a user defined public bucket policy will be attached (set to `false` to allow upstream to apply defaults to the bucket)"
  type        = bool
  default     = true
}

variable "attach_allow_vpc_endpoints_policy" {
  description = "Whether to attach a policy that controls access via VPC Endpoints. (Must set `allowed_vpce_ids` variable to be effective)"
  type        = bool
  default     = false
}

variable "attach_allow_iam_roles_policy" {
  description = "Whether to attach a policy that controls access via IAM Roles. (Must set `allowed_iam_role_arns` variable to be effective)"
  type        = bool
  default     = false
}

variable "allowed_vpce_ids" {
  description = "List of VPC Endpoint IDs to provide the bucket access to (Applicable only when `attach_allow_vpc_endpoints_policy` is set to `true`)"
  type        = list(string)
  default     = []
}

variable "allowed_iam_role_arns" {
  description = "List of IAM Role ARNs to provide the bucket access to (Applicable only when `attach_allow_iam_roles_policy` is set to `true`)"
  type        = list(string)
  default     = []
}

variable "bucket" {
  description = "this should be unique project and account name with in the region(Optional, Forces new resource) The name of the bucket. If omitted, Terraform will assign a random, unique name."
  type        = string
  validation {
    condition     = can(regex("[0-9A-Fa-f]+", var.bucket))
    error_message = "Specify a non-empty string!"
  }
}

variable "bucket_prefix" {
  description = "(Optional, Forces new resource) Creates a unique bucket name beginning with the specified prefix. Conflicts with bucket."
  type        = string
  default     = null
}

variable "additional_custom_policy" {
  description = "(Optional) A valid bucket policy JSON document. Note that if the policy document is not specific enough (but still valid), Terraform may view the policy as constantly changing in a terraform plan. In this case, please make sure you use the verbose/specific version of the policy. For more information about building AWS IAM policy documents with Terraform, see the AWS IAM Policy Document Guide."
  type        = string
  default     = null
}

variable "block_public_acls" {
  description = "Whether Amazon S3 should block public ACLs for this bucket. (Applicable only when `attach_public_policy` is set to `true`)"
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "Whether Amazon S3 should block public bucket policies for this bucket. (Applicable only when `attach_public_policy` is set to `true`)"
  type        = bool
  default     = true
}

variable "ignore_public_acls" {
  description = "Whether Amazon S3 should ignore public ACLs for this bucket. (Applicable only when `attach_public_policy` is set to `true`)"
  type        = bool
  default     = true
}

variable "restrict_public_buckets" {
  description = "Whether Amazon S3 should restrict public bucket policies for this bucket. (Applicable only when `attach_public_policy` is set to `true`)"
  type        = bool
  default     = true
}

variable "versioning" {
  description = "Map containing versioning configuration."
  type        = map(string)
  default     = {}
}

variable "server_side_encryption_configuration" {
  description = "Map containing server-side encryption configuration."
  type        = any
  default     = {}
}

#not so important and left as default


variable "attach_require_latest_tls_policy" {
  description = "Controls if S3 bucket should require the latest version of TLS"
  type        = bool
  default     = false
}

variable "attach_deny_incorrect_encryption_headers_policy" {
  description = "Controls if S3 bucket should require to deny any incorrect encryption request to place objects"
  type        = bool
  default     = false
}

variable "attach_elb_log_delivery_policy" {
  description = "Controls if S3 bucket should have ELB log delivery policy attached"
  type        = bool
  default     = false
}

variable "attach_lb_log_delivery_policy" {
  description = "Controls if S3 bucket should have ALB/NLB log delivery policy attached"
  type        = bool
  default     = false
}

variable "force_destroy" {
  description = "(Optional, Default:false ) A boolean that indicates all objects should be deleted from the bucket so that the bucket can be destroyed without error. These objects are not recoverable."
  type        = bool
  default     = false
}

variable "default_s3_content" {
   description = "The default content of the s3 bucket upon creation."
   type = set(string)
   default = []
}

variable "object_lock_configuration" {
  description = "Map containing S3 object locking configuration."
  type        = any
  default     = {}
}

variable "object_lock_enabled" {
  description = "Whether S3 bucket should have an Object Lock configuration enabled."
  type        = bool
  default     = false
}

variable "lifecycle_rule" {
  description = "List of maps containing configuration of object lifecycle management."
  type        = any
  default = [
    {
      id      = "default_lifecycle"
      enabled = true
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
      ]
    }
  ]
}

variable "acceleration_status" {
  description = "(Optional) Sets the accelerate configuration of an existing bucket. Can be Enabled or Suspended."
  type        = string
  default     = null
}

variable "request_payer" {
  description = "(Optional) Specifies who should bear the cost of Amazon S3 data transfer. Can be either BucketOwner or Requester. By default, the owner of the S3 bucket would incur the costs of any data transfer. See Requester Pays Buckets developer guide for more information."
  type        = string
  default     = null
}

variable "acl" {
  description = "(Optional) The canned ACL to apply. Conflicts with `grant`"
  type        = string
  default     = null
}

variable "cors_rule" {
  description = "List of maps containing rules for Cross-Origin Resource Sharing."
  type        = any
  default     = []
}


variable "logging" {
  description = "Map containing access bucket logging configuration."
  type        = map(string)
  default     = {}
}

variable "grant" {
  description = "An ACL policy grant. Conflicts with `acl`"
  type        = any
  default     = []
}

# this is required for versioning and server side encryption
variable "expected_bucket_owner" {
  description = "The account ID of the expected bucket owner"
  type        = string
  default     = null
}


variable "intelligent_tiering" {
  description = "Map containing intelligent tiering configuration."
  type        = any
  default     = {}
}

# below variable might be useful in future aspects.

# variable "environment" {
#   type        = string
#   description = "environment if exist"
#   default     = ""
# }

# variable "website" {
#   description = "Map containing static web-site hosting or redirect configuration."
#   type        = any # map(string)
#   default     = {}
# }


# variable "owner" {
#   description = "Bucket owner's display name and ID. Conflicts with `acl`"
#   type        = map(string)
#   default     = {}
# }

# variable "replication_configuration" {
#   description = "Map containing cross-region replication configuration."
#   type        = any
#   default     = {}
# }

variable "control_object_ownership" {
  description = "Whether to manage S3 Bucket Ownership Controls on this bucket."
  type        = bool
  default     = false
}

variable "object_ownership" {
  description = "Object ownership. Valid values: BucketOwnerEnforced, BucketOwnerPreferred or ObjectWriter. 'BucketOwnerEnforced': ACLs are disabled, and the bucket owner automatically owns and has full control over every object in the bucket. 'BucketOwnerPreferred': Objects uploaded to the bucket change ownership to the bucket owner if the objects are uploaded with the bucket-owner-full-control canned ACL. 'ObjectWriter': The uploading account will own the object if the object is uploaded with the bucket-owner-full-control canned ACL."
  type        = string
  default     = "ObjectWriter"
}

## Tags section start ##
variable "mandatory_tags" {
  description = "A mapping of mandatory tags to assign to all the resources."
  type = object({
    CostCenter         = string
    DataClassification = string
    Application        = string
    Environment        = string
    Function           = string
  })
  nullable = false
}

variable "bucket_additional_tags" {
  description = "(Optional) A mapping of additional tags to assign to the bucket."
  type        = map(string)
  default     = {}
}
## Tags section end ##