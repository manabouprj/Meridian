# Deploy on Microsoft Azure + Microsoft Foundry

Target architecture: [../LLD-azure.md](../LLD-azure.md). Complete [PREREQUISITES.md](PREREQUISITES.md) first.

**Elapsed time:** about 1 day of hands-on work, plus approvals and the export configuration. Each step ends with a **Verify** check.

## Step 0: set variables

```bash
export ARM_SUBSCRIPTION_ID=<subscription-id>      # required by the azurerm provider
export PREFIX=meridian                            # 3-10 lowercase letters/digits
export LOCATION=uaenorth                          # data residency region
export FOUNDRY_LOCATION=eastus2                   # region where your Claude models are offered
export ACR=<your-acr-name>
az login && az account set --subscription "$ARM_SUBSCRIPTION_ID"
```

**Verify:** `az account show --query name -o tsv` prints the intended subscription.

## Step 1: register resource providers (once per subscription)

```bash
for ns in Microsoft.App Microsoft.CognitiveServices Microsoft.DBforPostgreSQL Microsoft.EventHub Microsoft.EventGrid \
          Microsoft.KeyVault Microsoft.Storage Microsoft.OperationalInsights Microsoft.Network Microsoft.ManagedIdentity Microsoft.Kusto; do
  az provider register --namespace $ns; done
```

**Verify:** `az provider show -n Microsoft.App --query registrationState -o tsv` prints `Registered` (repeat for the others).

## Step 2: build and push the image

```bash
az acr build --registry $ACR --image meridian:1.0.1 .
```

**Verify:** `az acr repository show-tags -n $ACR --repository meridian -o tsv` lists `1.0.1`.

## Step 3: Entra ID app registrations and groups

### 3a. Console SSO app

```bash
CONSOLE_APP=$(az ad app create --display-name "MERIDIAN Console" --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "https://<public-url>/auth/callback" --query appId -o tsv)
az ad app update --id $CONSOLE_APP --set groupMembershipClaims=SecurityGroup
az ad sp create --id $CONSOLE_APP
OIDC_SECRET=$(az ad app credential reset --id $CONSOLE_APP --display-name meridian --years 1 --query password -o tsv)
```

### 3b. MCP API app

This app is only needed for Foundry Agent Service or other remote MCP clients. Create it and expose it as `api://<appId>`, with one app role per scope set:

```bash
MCP_APP=$(az ad app create --display-name "MERIDIAN MCP" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad app update --id $MCP_APP --identifier-uris "api://$MCP_APP"
az ad app update --id $MCP_APP --app-roles @infra/azure/mcp-app-roles.json
az ad sp create --id $MCP_APP
```

### 3c. Security groups

Create (or reuse) four groups: SOC viewers, SOC analysts, SOC responders and SOC admins. Record their object IDs for `role_map`.

**Verify:**

* `az ad app show --id $CONSOLE_APP --query groupMembershipClaims` prints `"SecurityGroup"`;
* `az ad app show --id $MCP_APP --query "appRoles[].value"` lists `Lake.Read`, `Context.Read`, `Cases.Write` and `Response.Request`.

## Step 4: configure Terraform

```bash
cd infra/azure
cp terraform.tfvars.example terraform.tfvars
```

Set these values in `terraform.tfvars`:

* `prefix`, `location`, `foundry_location`, `image` (`<acr>.azurecr.io/meridian:1.0.1`), `acr_id`;
* `public_url` and `oidc_client_id` (`$CONSOLE_APP`);
* `model_deployments`: the format, name and version exactly as shown in your Foundry model catalog;
* `deployer_cidrs`: your runner's egress IP, for example `["203.0.113.10/32"]`. The VNet does not exist yet, so the first apply reaches Key Vault through this narrow allow-list.

Also enable the `backend "azurerm" {}` block (PREREQUISITES section 4).

**Verify:** `terraform init` succeeds and `terraform validate` prints `Success!`.

## Step 5: plan and apply

```bash
terraform plan -out tf.plan      # review the resource list: everything lands in rg-$PREFIX (Foundry in $FOUNDRY_LOCATION)
terraform apply tf.plan
terraform output
```

* Apply usually takes 20-30 minutes; PostgreSQL HA and the private endpoints are the slowest parts.
* If the Foundry deployment step fails with a model or format error, correct `model_deployments` from the model catalog and apply again.

**Verify:**

* `terraform output api_fqdn` returns an internal FQDN;
* `az containerapp list -g rg-$PREFIX --query "[].name" -o tsv` lists the api, worker, agents, scheduler and collector apps (and syslog when `syslog_receiver = true`).

## Step 6: set the secrets

```bash
KV=$(terraform output -raw key_vault)
gen() { python -c "import secrets; print(secrets.token_urlsafe(32))"; }
az keyvault secret set --vault-name $KV --name meridian-api-keys      --value "admin:$(gen),responder:$(gen),analyst:$(gen)"
az keyvault secret set --vault-name $KV --name meridian-session-secret --value "$(gen)$(gen)"
az keyvault secret set --vault-name $KV --name meridian-ingest-secret  --value "$(gen)"
az keyvault secret set --vault-name $KV --name meridian-ingest-tokens  --value "none"   # or "source:<token>,..." (LOG-00 §4.4)
az keyvault secret set --vault-name $KV --name meridian-edl-token      --value "$(gen)"
az keyvault secret set --vault-name $KV --name meridian-metrics-token  --value "$(gen)"
az keyvault secret set --vault-name $KV --name meridian-agent-tokens   --value "none:$(gen):lake:read"   # replace when remote agents are used
az keyvault secret set --vault-name $KV --name oidc-client-secret      --value "$OIDC_SECRET"
az keyvault secret set --vault-name $KV --name lodestar-webhook-secret --value "<from LODESTAR, or $(gen)>"   # same value as LODESTAR_WEBHOOK_SECRET_<ORG>; set lodestar_url / lodestar_org in tfvars (INT-00 §7)
```

* Keep a copy of the API keys in your privileged-access vault.
* `meridian-database-url` was generated by Terraform; do not change it.

**Restart the apps** so they read the new values:

```bash
for r in api worker agents scheduler; do
  az containerapp revision restart -g rg-$PREFIX -n ca-$PREFIX-$r \
    --revision $(az containerapp revision list -g rg-$PREFIX -n ca-$PREFIX-$r --query "[?properties.active].name | [0]" -o tsv); done
```

**Verify:** `az containerapp exec -g rg-$PREFIX -n ca-$PREFIX-api --command "python -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8090/readyz').read())\""` prints `"ready": true` with no `placeholder_secrets`.

## Step 7: worker autoscaling (KEDA queue rule)

```bash
az containerapp update -g rg-$PREFIX -n ca-$PREFIX-worker \
  --scale-rule-name landing-queue --scale-rule-type azure-queue \
  --scale-rule-metadata accountName=$(terraform output -raw lake_account) queueName=meridian-landing queueLength=20 \
  --scale-rule-identity $(az identity show -g rg-$PREFIX -n id-$PREFIX --query id -o tsv)
```

**Verify:** `az containerapp show -g rg-$PREFIX -n ca-$PREFIX-worker --query "properties.template.scale.rules[].name"` lists `landing-queue`.

## Step 8: application configuration

The image ships `config/examples/azure.yaml`. For your organisation, edit a copy:

* `org`;
* `security.oidc.role_map` (group object ID -> role);
* `security.mcp_scope_map`;
* `response`;
* `notify`.

Then rebuild the image with that file as `/app/config/examples/azure.yaml`, or mount it from an Azure Files share and point `MERIDIAN_CONFIG` at it.

Context files (`assets.csv`, `identities.csv`, `intel/`) follow the same path. Refresh them with a pipeline job and restart the worker app.

**Verify:** the next step's `doctor` shows your organisation name and the expected number of sources.

## Step 9: health check and model evaluation

```bash
az containerapp exec -g rg-$PREFIX -n ca-$PREFIX-api --command "python -m meridian doctor"
az containerapp exec -g rg-$PREFIX -n ca-$PREFIX-agents --command "python -m meridian eval"
```

**Verify:**

* `doctor` shows no FAIL lines. A WARN for `context` is expected until the CMDB is loaded.
* `eval` reports `accuracy >= 80%` using the Foundry deployments. The runs page shows the provider `anthropic_foundry`, not `degraded`.

## Step 10: console access and SSO

1. Publish the api app's internal FQDN through your edge: Application Gateway WAF in a hub VNet, or Front Door Premium with Private Link. Use your `public_url` hostname and certificate.
2. Browse to `https://<public-url>/` and sign in with Entra ID.

**Verify:**

* members of the responder group land on the console with the responder role (`/api/me`);
* users outside the mapped groups are refused.

## Step 11: onboard sources

Follow [ONBOARD-SOURCES.md](ONBOARD-SOURCES.md). Start with Entra ID and Defender XDR (Event Hubs), then syslog and push sources.

**Verify:** `/metrics` shows `meridian_source_last_batch_age_seconds` below 300 for each onboarded source.

## Step 12: end-to-end test

1. Push a test event that triggers a rule. For example, use the IOC rule with an indicator from your intel feed:

   ```bash
   python scripts/push_events.py --url https://<public-url> --source proxy \
     --line "CEF:0|Zscaler|NSS|6|1|blocked|5|src=10.1.2.3 suser=test.user@<domain> dhost=<an IOC domain> request=http://<an IOC domain>/x"
   ```

   Run this from a host that can reach the console. `MERIDIAN_INGEST_SECRET` must be set in your shell.
2. Within about 2 minutes:
   * the alert appears;
   * it is triaged with an agent note;
   * if the severity is high enough, a case opens.
3. Request and approve a `block_indicator` action from the case, as a different responder.
4. Check the containment path: `curl -u edl:<edl-token> https://<public-url>/edl/domain.txt` lists the domain.

**Verify:**

* the case timeline shows triage, the approval, and the execution (dry run, or listed for the EDL);
* `meridian verify-audit` (run through `az containerapp exec`) prints `valid`.

## Step 13: tighten after go-live

* Remove `deployer_cidrs` (set it to `[]`) and run further applies from a runner inside the VNet or a peered hub.
* Lock the lake immutability policy if your retention policy requires it (irreversible: get legal approval first).
* Configure the alerts listed in [../OPERATIONS.md](../OPERATIONS.md) section 4 in Azure Monitor. Scrape `/metrics` with Azure Monitor managed Prometheus.

## Optional: Azure Data Explorer and Foundry Agent Service

* **ADX** (estates above about 100 GB/day): set `enable_adx = true`, then complete the post-apply steps in LLD-azure §5.3.
* **Foundry Agent Service:** follow LLD-azure §7. Grant the Foundry project's identity the MCP app roles it needs; MERIDIAN keeps the approvals.
