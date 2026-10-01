# ---------------- Azure Container Apps: api, worker (KEDA on the landing queue), agents, scheduler
resource "azurerm_container_app_environment" "env" {
  name                           = "cae-${var.prefix}"
  location                       = var.location
  resource_group_name            = azurerm_resource_group.rg.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.platform.id
  infrastructure_subnet_id       = azurerm_subnet.apps.id
  internal_load_balancer_enabled = true
  zone_redundancy_enabled        = true
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
  tags = var.tags
}

locals {
  env_common = {
    MERIDIAN_CONFIG        = "/app/config/examples/azure.yaml"
    MERIDIAN_CLOUD         = "azure"
    AZURE_CLIENT_ID        = azurerm_user_assigned_identity.app.client_id
    FOUNDRY_RESOURCE       = azurerm_cognitive_account.foundry.custom_subdomain_name
    MERIDIAN_LAKE_ROOT     = "abfss://lake@${azurerm_storage_account.lake.name}.dfs.core.windows.net"
    MERIDIAN_LANDING_ROOT  = "abfss://landing@${azurerm_storage_account.lake.name}.dfs.core.windows.net"
    MERIDIAN_QUEUE_ACCOUNT = azurerm_storage_account.lake.name
    MERIDIAN_LOG_FORMAT    = "json"
    AZURE_TENANT_ID        = data.azurerm_client_config.current.tenant_id
    MERIDIAN_PUBLIC_URL    = var.public_url
    OIDC_CLIENT_ID         = var.oidc_client_id
    LODESTAR_URL           = var.lodestar_url
    LODESTAR_ORG           = var.lodestar_org
  }
  secrets = merge({
    "meridian-database-url"   = "MERIDIAN_DATABASE_URL"
    "meridian-api-keys"       = "MERIDIAN_API_KEYS"
    "meridian-session-secret" = "MERIDIAN_SESSION_SECRET"
    "meridian-ingest-secret"  = "MERIDIAN_INGEST_SECRET"
    "meridian-edl-token"      = "MERIDIAN_EDL_TOKEN"
    "meridian-metrics-token"  = "MERIDIAN_METRICS_TOKEN"
    "meridian-agent-tokens"   = "MERIDIAN_AGENT_TOKENS"
    "oidc-client-secret"      = "OIDC_CLIENT_SECRET"
    "lodestar-webhook-secret" = "LODESTAR_WEBHOOK_SECRET"
    "meridian-ingest-tokens"  = "MERIDIAN_INGEST_TOKENS"
  }, { for s in var.extra_secrets : "meridian-${s}" => upper(replace("MERIDIAN_${s}", "-", "_")) })
  syslog_secrets = { "syslog-tls-cert" = "MERIDIAN_SYSLOG_TLS_CERT", "syslog-tls-key" = "MERIDIAN_SYSLOG_TLS_KEY" }
  roles = merge({
    api       = { args = ["serve", "--host", "0.0.0.0", "--port", "8090"], min = 2, max = 4, cpu = 1.0, mem = "2Gi", ingress = true }
    worker    = { args = ["worker"], min = 1, max = 10, cpu = 1.0, mem = "2Gi", ingress = false }
    agents    = { args = ["agents"], min = 1, max = 4, cpu = 0.5, mem = "1Gi", ingress = false }
    scheduler = { args = ["scheduler"], min = 1, max = 1, cpu = 0.5, mem = "1Gi", ingress = false }
    collector = { args = ["collect"], min = 1, max = 1, cpu = 0.25, mem = "0.5Gi", ingress = false }
    }, var.syslog_receiver ? {
    syslog = { args = ["syslog", "--source", "syslog", "--port", "0", "--tls-port", "6514"], min = 2, max = 4, cpu = 0.5, mem = "1Gi", ingress = false }
  } : {})
}

resource "azurerm_container_app" "role" {
  for_each                     = local.roles
  name                         = "ca-${var.prefix}-${each.key}"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }
  registry {
    server   = split("/", var.image)[0]
    identity = azurerm_user_assigned_identity.app.id
  }
  dynamic "secret" {
    for_each = each.key == "syslog" ? merge(local.secrets, local.syslog_secrets) : local.secrets
    content {
      name                = secret.key
      key_vault_secret_id = "${azurerm_key_vault.kv.vault_uri}secrets/${secret.key}"
      identity            = azurerm_user_assigned_identity.app.id
    }
  }
  template {
    min_replicas = each.value.min
    max_replicas = each.value.max
    container {
      name   = each.key
      image  = var.image
      args   = each.value.args
      cpu    = each.value.cpu
      memory = each.value.mem
      dynamic "env" {
        for_each = local.env_common
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = each.key == "syslog" ? merge(local.secrets, local.syslog_secrets) : local.secrets
        content {
          name        = env.value
          secret_name = env.key
        }
      }
      dynamic "liveness_probe" {
        for_each = each.value.ingress ? [1] : []
        content {
          transport = "HTTP"
          port      = 8090
          path      = "/healthz"
        }
      }
      dynamic "readiness_probe" {
        for_each = each.value.ingress ? [1] : []
        content {
          transport = "HTTP"
          port      = 8090
          path      = "/readyz"
        }
      }
    }
    # The ingestion worker scales on the landing queue with KEDA (azure-queue) using the workload identity.
    # Add the rule after the first apply (azurerm does not yet expose identity-based scale-rule auth):
    #   az containerapp update -g rg-<prefix> -n ca-<prefix>-worker --scale-rule-name landing-queue \
    #     --scale-rule-type azure-queue --scale-rule-metadata accountName=<lake account> queueName=meridian-landing queueLength=20 \
    #     --scale-rule-identity <id-<prefix> resource id>
  }
  dynamic "ingress" { # TLS syslog (RFC 5425) on the environment's internal IP, TCP 6514; TLS ends in the receiver
    for_each = each.key == "syslog" ? [1] : []
    content {
      external_enabled = false
      transport        = "tcp"
      exposed_port     = 6514
      target_port      = 6514
      traffic_weight {
        latest_revision = true
        percentage      = 100
      }
    }
  }
  dynamic "ingress" {
    for_each = each.value.ingress ? [1] : []
    content {
      external_enabled = false # reachable on the VNet only; publish via Application Gateway WAF / Front Door Premium + Private Link
      target_port      = 8090
      transport        = "http"
      traffic_weight {
        latest_revision = true
        percentage      = 100
      }
    }
  }
  tags       = var.tags
  depends_on = [azurerm_role_assignment.app]
}
