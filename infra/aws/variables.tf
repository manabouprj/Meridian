variable "prefix" {
  type    = string
  default = "meridian"
}
variable "region" {
  description = "Region for data and compute (data residency), e.g. me-central-1"
  type        = string
  default     = "me-central-1"
}
variable "bedrock_region" {
  description = <<-EOT
    Region whose bedrock-runtime endpoint the agents call. Default: the data-residency region, so model traffic uses the
    in-VPC bedrock-runtime endpoint. From me-central-1, Claude Sonnet 5.5 is offered through GLOBAL cross-region inference
    only (Bedrock may route to any supported commercial region). To pin processing to one geography, call a region in
    that geography with a geographic profile (eu. / us.) - that traffic then leaves the VPC (NAT) or needs inter-region
    private connectivity.
  EOT
  type        = string
  default     = "me-central-1"
}
variable "bedrock_fast_model" {
  description = "Inference profile (or model) id for triage/tuning, from `aws bedrock list-inference-profiles --region <bedrock_region>`, e.g. global.anthropic.claude-haiku-4-5-<version>"
  type        = string
}
variable "bedrock_deep_model" {
  description = "Inference profile (or model) id for investigation/hunting, e.g. global.anthropic.claude-sonnet-5-5-<version>"
  type        = string
}
variable "bedrock_model_arns" {
  description = "ARNs the agents may invoke (least privilege): the inference profiles AND the foundation models they route to (any region for global profiles)."
  type        = list(string)
  default = [
    "arn:aws:bedrock:*:*:inference-profile/*anthropic.claude-haiku-4-5*",
    "arn:aws:bedrock:*:*:inference-profile/*anthropic.claude-sonnet-5-5*",
    "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5*",
    "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-5-5*",
  ]
}
variable "image" {
  description = "Container image in ECR, e.g. <acct>.dkr.ecr.<region>.amazonaws.com/meridian:1.0.0"
  type        = string
}
variable "vpc_cidr" {
  type    = string
  default = "10.70.0.0/16"
}
variable "certificate_arn" {
  description = "ACM certificate for the internal HTTPS listener of the API"
  type        = string
}
variable "lake_retention_days" {
  description = "S3 Object Lock retention for the lake (WORM)"
  type        = number
  default     = 365
}
variable "object_lock_mode" {
  description = "GOVERNANCE (admins with bypass can delete) or COMPLIANCE (nobody can, until retention ends)"
  type        = string
  default     = "GOVERNANCE"
}
variable "nat_gateway" {
  description = "Create a NAT gateway for egress to vendor SaaS APIs (EDR, IdP, intel feeds). False = VPC endpoints only."
  type        = bool
  default     = true
}
variable "tags" {
  type    = map(string)
  default = { product = "meridian", data_classification = "confidential" }
}
variable "public_url" {
  description = "HTTPS URL users reach MERIDIAN on, used for SSO redirects and links"
  type        = string
  default     = ""
}
variable "oidc_issuer" {
  description = "OIDC issuer for sign-in (Entra ID, Okta, Cognito ...)"
  type        = string
  default     = ""
}
variable "oidc_client_id" {
  type    = string
  default = ""
}

variable "client_cidrs" {
  description = "Networks allowed to reach the internal ALB on 443 (corporate ranges, VPN, the edge proxy). Empty = the VPC only."
  type        = list(string)
  default     = []
}

variable "syslog_cidrs" {
  description = "Networks allowed to send syslog to the syslog service on 5514/tcp+udp. Empty = the VPC only."
  type        = list(string)
  default     = []
}

variable "cloudtrail_account_ids" {
  description = "Accounts whose CloudTrail trails may write into the landing bucket (organisation management account for an org trail). Empty = this account."
  type        = list(string)
  default     = []
}
variable "lodestar_url" {
  description = "LODESTAR base URL the scheduler pushes SOC findings to (https://..., private address recommended). Empty = integration off."
  type        = string
  default     = ""
  validation {
    condition     = var.lodestar_url == "" || startswith(var.lodestar_url, "https://")
    error_message = "lodestar_url must be an https:// URL (the push is signed but its content is confidential)."
  }
}
variable "lodestar_org" {
  description = "LODESTAR organisation key (?org=); required when LODESTAR serves several organisations"
  type        = string
  default     = ""
}
variable "lake_expire_days" {
  description = "Delete lake events this many days after they were written (rotation). 0 = keep forever. Must be >= lake_retention_days: WORM retention is the minimum, this is the end of life."
  type        = number
  default     = 0
  validation {
    condition     = var.lake_expire_days == 0 || var.lake_expire_days >= var.lake_retention_days
    error_message = "lake_expire_days must be 0 (keep) or at least lake_retention_days (WORM data cannot be deleted earlier)."
  }
}
variable "lake_expire_days_by_class" {
  description = "Per-OCSF-class end of life, overriding lake_expire_days, e.g. { \"4001\" = 400, \"3002\" = 2555 } keeps network flows ~13 months and authentication 7 years."
  type        = map(number)
  default     = {}
  validation {
    condition     = alltrue([for k, v in var.lake_expire_days_by_class : v == 0 || v >= var.lake_retention_days])
    error_message = "Every per-class expiry must be 0 or at least lake_retention_days."
  }
}
variable "extra_secrets" {
  description = "Additional secrets to create for API pull collectors or other sources, e.g. [\"okta-token\", \"o365-client-secret\"]. Each is exposed to the containers as MERIDIAN_<NAME> (upper case, - becomes _) and referenced in the config as $${MERIDIAN_OKTA_TOKEN}."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for s in var.extra_secrets : can(regex("^[a-z0-9-]{3,40}$", s))])
    error_message = "extra_secrets names: lower case letters, digits and -, 3-40 characters."
  }
}
variable "landing_writer_sources" {
  description = "Source keys that will write straight into the landing bucket from outside MERIDIAN (Fluent Bit, Vector, Cribl, Firehose, an on-premises collector through IAM Roles Anywhere). One managed policy per source is created, allowing writes only under <source>/ with the lake KMS key; attach it to the shipper's role."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for s in var.landing_writer_sources : can(regex("^[a-z0-9_-]{2,40}$", s))])
    error_message = "landing_writer_sources: source keys (a-z, 0-9, _ and -)."
  }
}
