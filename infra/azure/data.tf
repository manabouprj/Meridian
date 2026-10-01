resource "random_string" "sfx" {
  length  = 6
  special = false
  upper   = false
}

# ---------------- security data lake (ADLS Gen2, private, WORM on the lake container)
resource "azurerm_storage_account" "lake" {
  name                              = "st${var.prefix}${random_string.sfx.result}"
  resource_group_name               = azurerm_resource_group.rg.name
  location                          = var.location
  account_tier                      = "Standard"
  account_replication_type          = "ZRS"
  account_kind                      = "StorageV2"
  is_hns_enabled                    = true
  min_tls_version                   = "TLS1_2"
  shared_access_key_enabled         = false
  public_network_access             = "Disabled"
  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
  tags = var.tags
}

resource "azurerm_storage_container" "landing" {
  name                  = "landing"
  storage_account_id    = azurerm_storage_account.lake.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "lake" {
  name                  = "lake"
  storage_account_id    = azurerm_storage_account.lake.id
  container_access_type = "private"
}

resource "azurerm_storage_container_immutability_policy" "lake_worm" {
  storage_container_resource_manager_id = azurerm_storage_container.lake.id
  immutability_period_in_days           = var.lake_retention_days
  protected_append_writes_all_enabled   = false
}

resource "azurerm_storage_management_policy" "tiering" {
  storage_account_id = azurerm_storage_account.lake.id
  rule {
    name    = "lake-tiering"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["lake/events/"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_cold_after_days_since_modification_greater_than    = 90
        tier_to_archive_after_days_since_modification_greater_than = 400
      }
    }
  }
  # Rotation: one rule per OCSF class so log types can have different lifetimes. The container's immutability
  # policy still blocks deletion inside the WORM period, which the variable validation makes the minimum.
  dynamic "rule" {
    for_each = { for c, d in local.lake_expiry : c => d if d > 0 }
    content {
      name    = "lake-expire-cls-${rule.key}"
      enabled = true
      filters {
        blob_types   = ["blockBlob"]
        prefix_match = ["lake/events/cls=${rule.key}/"]
      }
      actions {
        base_blob {
          delete_after_days_since_modification_greater_than = rule.value
        }
      }
    }
  }
  rule {
    name    = "landing-expiry"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["landing/"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 7
        delete_after_days_since_modification_greater_than       = 90
      }
    }
  }
}

resource "azurerm_storage_queue" "landing" {
  name               = "meridian-landing"
  storage_account_id = azurerm_storage_account.lake.id
}

# Messages delivered more than 5 times are parked here by the workers (Storage Queues have no native DLQ)
resource "azurerm_storage_queue" "poison" {
  name               = "meridian-landing-poison"
  storage_account_id = azurerm_storage_account.lake.id
}

# BlobCreated in the landing container -> storage queue -> ingestion workers (KEDA scales on queue length)
resource "azurerm_eventgrid_system_topic" "lake" {
  name                = "egt-${var.prefix}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  source_resource_id  = azurerm_storage_account.lake.id
  topic_type          = "Microsoft.Storage.StorageAccounts"
  identity { type = "SystemAssigned" }
  tags = var.tags
}

resource "azurerm_role_assignment" "eg_queue_sender" {
  scope                = azurerm_storage_account.lake.id
  role_definition_name = "Storage Queue Data Message Sender"
  principal_id         = azurerm_eventgrid_system_topic.lake.identity[0].principal_id
}

resource "azurerm_eventgrid_system_topic_event_subscription" "landing" {
  name                 = "landing-to-queue"
  system_topic         = azurerm_eventgrid_system_topic.lake.name
  resource_group_name  = azurerm_resource_group.rg.name
  included_event_types = ["Microsoft.Storage.BlobCreated"]
  subject_filter {
    subject_begins_with = "/blobServices/default/containers/landing/"
  }
  delivery_identity { type = "SystemAssigned" }
  storage_queue_endpoint {
    storage_account_id = azurerm_storage_account.lake.id
    queue_name         = azurerm_storage_queue.landing.name
  }
  depends_on = [azurerm_role_assignment.eg_queue_sender]
}

# ---------------- Event Hubs: Defender XDR streaming API, Entra / Azure diagnostic settings -> Capture (Avro) -> landing
resource "azurerm_eventhub_namespace" "ehn" {
  name                         = "evhns-${var.prefix}-${random_string.sfx.result}"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.rg.name
  sku                          = "Standard"
  capacity                     = 2
  auto_inflate_enabled         = true
  maximum_throughput_units     = 10
  local_authentication_enabled = true # diagnostic settings use the namespace authorization rule
  minimum_tls_version          = "1.2"
  tags                         = var.tags
}

resource "azurerm_eventhub" "telemetry" {
  for_each          = toset(["mde", "entra", "azure-activity"])
  name              = each.key
  namespace_id      = azurerm_eventhub_namespace.ehn.id
  partition_count   = 4
  message_retention = 1
  capture_description {
    enabled             = true
    encoding            = "Avro"
    interval_in_seconds = 60
    size_limit_in_bytes = 104857600
    skip_empty_archives = true
    destination {
      name                = "EventHubArchive.AzureBlockBlob"
      archive_name_format = "${each.key}/{Namespace}/{EventHub}/{PartitionId}/{Year}/{Month}/{Day}/{Hour}/{Minute}/{Second}"
      blob_container_name = azurerm_storage_container.landing.name
      storage_account_id  = azurerm_storage_account.lake.id
    }
  }
}

# ---------------- operational store: PostgreSQL Flexible Server (private access)
resource "random_password" "pg" {
  length  = 32
  special = false
}

resource "azurerm_postgresql_flexible_server" "pg" {
  name                          = "psql-${var.prefix}-${random_string.sfx.result}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = var.location
  version                       = "16"
  delegated_subnet_id           = azurerm_subnet.pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.z["postgres"].id
  public_network_access_enabled = false
  administrator_login           = var.postgres_admin_login
  administrator_password        = random_password.pg.result
  sku_name                      = "GP_Standard_D2ds_v5"
  storage_mb                    = 65536
  backup_retention_days         = 35
  geo_redundant_backup_enabled  = true
  zone                          = "1"
  high_availability { mode = "ZoneRedundant" }
  tags       = var.tags
  depends_on = [azurerm_private_dns_zone_virtual_network_link.z]
}

resource "azurerm_postgresql_flexible_server_database" "meridian" {
  name      = "meridian"
  server_id = azurerm_postgresql_flexible_server.pg.id
}

# ---------------- optional Azure Data Explorer (large estates)
resource "azurerm_kusto_cluster" "adx" {
  count                         = var.enable_adx ? 1 : 0
  name                          = "adx${var.prefix}${random_string.sfx.result}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.rg.name
  public_network_access_enabled = false
  sku {
    name     = "Standard_E8ads_v5"
    capacity = 2
  }
  identity { type = "SystemAssigned" }
  tags = var.tags
}

resource "azurerm_kusto_database" "meridian" {
  count               = var.enable_adx ? 1 : 0
  name                = "meridian"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  cluster_name        = azurerm_kusto_cluster.adx[0].name
  hot_cache_period    = "P31D"
  soft_delete_period  = "P400D"
}

locals {
  ocsf_classes = ["0", "1001", "1007", "2004", "3001", "3002", "3005", "4001", "4002", "4003", "4009", "6003"]
  lake_expiry  = { for c in local.ocsf_classes : c => lookup(var.lake_expire_days_by_class, c, var.lake_expire_days) }
}
