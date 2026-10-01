# ---------------- Microsoft Foundry: models for the agents (Claude in Foundry), private endpoint, Entra auth only
resource "azurerm_cognitive_account" "foundry" {
  name                          = "aif-${var.prefix}-${random_string.sfx.result}"
  location                      = var.foundry_location
  resource_group_name           = azurerm_resource_group.rg.name
  kind                          = "AIServices"
  sku_name                      = "S0"
  custom_subdomain_name         = "aif-${var.prefix}-${random_string.sfx.result}"
  local_auth_enabled            = false # Entra ID (managed identity) only - no API keys
  public_network_access_enabled = false
  project_management_enabled    = true
  identity { type = "SystemAssigned" }
  network_acls { default_action = "Deny" }
  tags = var.tags
}

resource "azurerm_cognitive_account_project" "meridian" {
  name                 = "meridian"
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  location             = var.foundry_location
  identity { type = "SystemAssigned" }
}

resource "azurerm_cognitive_deployment" "models" {
  for_each             = var.model_deployments
  name                 = each.key
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  model {
    format  = each.value.format
    name    = each.value.name
    version = each.value.version
  }
  sku {
    name     = each.value.sku
    capacity = each.value.capacity
  }
}
