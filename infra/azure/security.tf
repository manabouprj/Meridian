data "azurerm_client_config" "current" {}

# One user-assigned identity for every MERIDIAN workload (no keys anywhere)
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${var.prefix}"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags
}

locals {
  app_roles = {
    lake_rw   = { scope = azurerm_storage_account.lake.id, role = "Storage Blob Data Contributor" }
    queue     = { scope = azurerm_storage_account.lake.id, role = "Storage Queue Data Message Processor" }
    queue_put = { scope = azurerm_storage_account.lake.id, role = "Storage Queue Data Message Sender" } # poison queue
    kv        = { scope = azurerm_key_vault.kv.id, role = "Key Vault Secrets User" }
    foundry   = { scope = azurerm_cognitive_account.foundry.id, role = "Azure AI User" }
    acr       = { scope = var.acr_id, role = "AcrPull" }
  }
}

resource "azurerm_role_assignment" "app" {
  for_each             = local.app_roles
  scope                = each.value.scope
  role_definition_name = each.value.role
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_key_vault" "kv" {
  name                       = "kv-${var.prefix}-${random_string.sfx.result}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  # Terraform writes secrets through the data plane. Run it from a runner inside the VNet (recommended), or list the
  # runner's public egress IPs in deployer_cidrs: public access is then enabled ONLY for those addresses.
  public_network_access_enabled = length(var.deployer_cidrs) > 0
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.deployer_cidrs
  }
  tags = var.tags
}

# The identity running Terraform needs data-plane rights to create the secret placeholders and the database URL
resource "azurerm_role_assignment" "deployer_kv" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Secrets are created empty here and set by the operator (az keyvault secret set ...) - never in Terraform state
resource "azurerm_key_vault_secret" "placeholders" {
  for_each = toset(concat(["meridian-api-keys", "meridian-session-secret", "meridian-ingest-secret", "meridian-ingest-tokens",
    "meridian-edl-token", "meridian-metrics-token", "meridian-agent-tokens", "oidc-client-secret", "lodestar-webhook-secret"],
    [for s in var.extra_secrets : "meridian-${s}"],
  var.syslog_receiver ? ["syslog-tls-cert", "syslog-tls-key"] : []))
  name         = each.key
  value        = "set-me"
  key_vault_id = azurerm_key_vault.kv.id
  lifecycle { ignore_changes = [value] }
  depends_on = [azurerm_role_assignment.deployer_kv]
}

resource "azurerm_key_vault_secret" "db_url" {
  name         = "meridian-database-url"
  value        = "postgresql+psycopg://${var.postgres_admin_login}:${random_password.pg.result}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/meridian?sslmode=require"
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [azurerm_role_assignment.deployer_kv]
}

# ---------------- private endpoints
locals {
  endpoints = {
    blob    = { id = azurerm_storage_account.lake.id, sub = "blob", zone = "blob" }
    dfs     = { id = azurerm_storage_account.lake.id, sub = "dfs", zone = "dfs" }
    queue   = { id = azurerm_storage_account.lake.id, sub = "queue", zone = "queue" }
    vault   = { id = azurerm_key_vault.kv.id, sub = "vault", zone = "vault" }
    foundry = { id = azurerm_cognitive_account.foundry.id, sub = "account", zone = "foundry" }
  }
}

resource "azurerm_private_endpoint" "pe" {
  for_each            = local.endpoints
  name                = "pe-${var.prefix}-${each.key}"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.pe.id
  private_service_connection {
    name                           = "psc-${each.key}"
    private_connection_resource_id = each.value.id
    subresource_names              = [each.value.sub]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "dns"
    private_dns_zone_ids = each.key == "foundry" ? [azurerm_private_dns_zone.z["foundry"].id, azurerm_private_dns_zone.z["cogsvc"].id] : [azurerm_private_dns_zone.z[each.value.zone].id]
  }
  tags = var.tags
}

resource "azurerm_log_analytics_workspace" "platform" {
  # platform / container logs only (small, short retention) - security telemetry lives in the lake
  name                = "log-${var.prefix}"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 2
  tags                = var.tags
}
