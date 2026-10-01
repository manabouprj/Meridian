variable "prefix" {
  description = "Short name prefix (3-10 lowercase letters/digits)"
  type        = string
  default     = "meridian"
}
variable "location" {
  description = "Azure region for data and compute (data residency)"
  type        = string
  default     = "uaenorth"
}
variable "foundry_location" {
  description = "Region of the Foundry resource that holds the Claude deployments. Claude is not offered in UAE North; with DataZoneStandard this must be a US region (inference is processed in the US data zone)."
  type        = string
  default     = "eastus2"
}
variable "image" {
  description = "Container image, e.g. <acr>.azurecr.io/meridian:1.0.0"
  type        = string
}
variable "acr_id" {
  description = "Resource id of the Azure Container Registry holding the image (AcrPull is granted to the workload identity)"
  type        = string
}
variable "vnet_cidr" {
  type    = string
  default = "10.60.0.0/16"
}
variable "lake_retention_days" {
  description = "WORM retention for the lake container (immutability policy)"
  type        = number
  default     = 365
}
variable "model_deployments" {
  description = <<-EOT
    Claude deployments in Microsoft Foundry (deployment name => model). Residency rules, verified against the Foundry
    documentation (October 2026):
      * version "2" = Hosted on Azure (prompts and outputs processed on Azure infrastructure).
        Version "1" = Hosted on Anthropic infrastructure (may be processed outside Azure) - do not use for regulated data.
      * sku "DataZoneStandard" (US data zone) is offered only for the Azure-hosted claude-sonnet-5, claude-sonnet-5-5,
        claude-opus-4-8, claude-opus-5 and claude-opus-5-5. foundry_location must then be a US region (e.g. eastus2).
      * claude-haiku-4-5 is GlobalStandard only (processed in any Azure region) - cheaper triage, weaker residency.
    The default pins both tiers to the US data zone with Sonnet 5.5. Confirm names and versions in your model catalog.
  EOT
  type = map(object({
    format   = string
    name     = string
    version  = string
    sku      = string
    capacity = number
  }))
  default = {
    "meridian-fast" = { format = "Anthropic", name = "claude-sonnet-5-5", version = "2", sku = "DataZoneStandard", capacity = 50 }
    "meridian-deep" = { format = "Anthropic", name = "claude-sonnet-5-5", version = "2", sku = "DataZoneStandard", capacity = 50 }
  }
  validation {
    condition     = alltrue([for d in values(var.model_deployments) : contains(["DataZoneStandard", "GlobalStandard"], d.sku)])
    error_message = "Claude deployments in Foundry support DataZoneStandard (US) or GlobalStandard only."
  }
  validation {
    condition     = alltrue([for d in values(var.model_deployments) : d.version != "1"])
    error_message = "Version \"1\" is hosted on Anthropic infrastructure (processing may leave Azure). Use the Azure-hosted version (\"2\")."
  }
}
variable "enable_adx" {
  description = "Deploy Azure Data Explorer for large estates (otherwise DuckDB queries the lake directly)"
  type        = bool
  default     = false
}
variable "postgres_admin_login" {
  type    = string
  default = "meridianadmin"
}
variable "tags" {
  type    = map(string)
  default = { product = "meridian", data_classification = "confidential" }
}
variable "public_url" {
  description = "HTTPS URL users reach MERIDIAN on (through Application Gateway / Front Door), used for SSO redirects and links"
  type        = string
  default     = ""
}
variable "oidc_client_id" {
  description = "Entra app registration (client id) for MERIDIAN sign-in"
  type        = string
  default     = ""
}

variable "deployer_cidrs" {
  description = "Public egress IPs/CIDRs of the machine running Terraform, allowed to reach Key Vault. Leave empty when Terraform runs inside the VNet (recommended)."
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
variable "syslog_receiver" {
  description = "Run the TLS syslog receiver (Container App, TCP 6514 on the environment's internal IP). Put the PEM certificate and key into Key Vault secrets syslog-tls-cert / syslog-tls-key first. Container Apps has no UDP ingress: senders use TCP+TLS (rsyslog, syslog-ng, NXLog om_ssl)."
  type        = bool
  default     = false
}
