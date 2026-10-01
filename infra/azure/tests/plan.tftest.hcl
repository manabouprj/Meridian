# Offline plan test with mocked providers: `tofu test` / `terraform test` (no credentials, nothing created).
mock_provider "azurerm" {
  mock_resource "azurerm_resource_group" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian" }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.Network/virtualNetworks/vnet-meridian" }
  }
  mock_resource "azurerm_subnet" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.Network/virtualNetworks/vnet-meridian/subnets/snet" }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net" }
  }
  mock_resource "azurerm_storage_account" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.Storage/storageAccounts/stmeridian" }
  }
  mock_resource "azurerm_storage_container" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.Storage/storageAccounts/stmeridian/blobServices/default/containers/lake" }
  }
  mock_resource "azurerm_key_vault" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.KeyVault/vaults/kv-meridian", vault_uri = "https://kv-meridian.vault.azure.net/" }
  }
  mock_resource "azurerm_cognitive_account" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.CognitiveServices/accounts/aif-meridian" }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-meridian", principal_id = "22222222-2222-2222-2222-222222222222", client_id = "33333333-3333-3333-3333-333333333333" }
  }
  mock_resource "azurerm_postgresql_flexible_server" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-meridian" }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.OperationalInsights/workspaces/log-meridian" }
  }
  mock_resource "azurerm_container_app_environment" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.App/managedEnvironments/cae-meridian" }
  }
  mock_resource "azurerm_eventhub_namespace" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.EventHub/namespaces/evhns-meridian" }
  }
  mock_resource "azurerm_eventgrid_system_topic" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.EventGrid/systemTopics/egt-meridian" }
  }
  mock_resource "azurerm_kusto_cluster" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-meridian/providers/Microsoft.Kusto/clusters/adxmeridian" }
  }
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id = "00000000-0000-0000-0000-000000000000"
      object_id = "11111111-1111-1111-1111-111111111111"
    }
  }
}
mock_provider "random" {}

variables {
  lodestar_url     = "https://lodestar.internal.example"
  prefix           = "meridian"
  location         = "uaenorth"
  foundry_location = "eastus2"
  image            = "acrmeridian.azurecr.io/meridian:1.0.0"
  acr_id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acrmeridian"
  public_url       = "https://meridian.example"
  oidc_client_id   = "00000000-0000-0000-0000-000000000000"
}

run "plan" {
  command = plan

  assert {
    condition     = azurerm_cognitive_account.foundry.local_auth_enabled == false
    error_message = "Foundry must not allow key authentication"
  }
  assert {
    condition     = azurerm_storage_account.lake.shared_access_key_enabled == false && azurerm_storage_account.lake.public_network_access == "Disabled"
    error_message = "the lake account must be keyless and private"
  }
  assert {
    condition     = azurerm_key_vault.kv.public_network_access_enabled == false
    error_message = "Key Vault stays private unless deployer_cidrs is set"
  }
  assert {
    condition     = azurerm_storage_container_immutability_policy.lake_worm.immutability_period_in_days == 365
    error_message = "the lake must be WORM for the retention period"
  }
}

run "syslog_receiver_and_rotation" {
  command = plan
  variables {
    syslog_receiver           = true
    lake_expire_days_by_class = { "4001" = 400 }
  }
  assert {
    condition     = one(azurerm_container_app.role["syslog"].ingress).transport == "tcp" && one(azurerm_container_app.role["syslog"].ingress).exposed_port == 6514
    error_message = "TLS syslog listens on TCP 6514"
  }
  assert {
    condition     = contains(keys(azurerm_key_vault_secret.placeholders), "syslog-tls-cert") && contains(keys(azurerm_key_vault_secret.placeholders), "meridian-ingest-tokens")
    error_message = "syslog TLS and ingest-token secrets exist in Key Vault"
  }
  assert {
    condition     = length([for r in azurerm_storage_management_policy.tiering.rule : r if r.name == "lake-expire-cls-4001"]) == 1
    error_message = "per-class expiry rule"
  }
}
