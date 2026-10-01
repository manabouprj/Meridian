# Prerequisites

Complete this checklist before starting a cloud runbook. Most delays come from approvals (model access, app registrations, firewall changes), not from the deployment itself, so start those first.

## 1. Decisions (record them in your change ticket)

| Decision | Options | Guidance |
| --- | --- | --- |
| Cloud | Azure + Foundry, or AWS + Bedrock | Use the cloud where your security tooling and identity already live. Both are fully specified |
| Region (data residency) | For example UAE North / me-central-1 | The lake, database and compute stay here |
| Model region / inference mode | In-region, data-zone or global cross-region inference | **A DPO / legal decision.** In the Middle East, Claude is available through cross-region inference: data is stored in-region, but inference may run in other regions |
| Query engine | DuckDB (< 100 GB/day), Athena (AWS), Azure Data Explorer (Azure, > 100 GB/day) | See HLD section 12 and the cost model |
| Retention | Lake WORM days (default 365); landing 90 days | Match your logging policy and PCI DSS 10.5.1 |
| Object Lock / immutability mode | GOVERNANCE (default) or COMPLIANCE / locked policy | COMPLIANCE cannot be shortened, even by administrators. Needs legal approval |
| Response actions to enable | isolate, revoke, disable, block, AWS key and instance, SOAR | All start in dry-run mode |
| Network exposure of the console | Internal only, via corporate WAN/VPN, or via an edge (Front Door / App Gateway WAF / CloudFront + WAF) | The reference deployments are private |

## 2. Accounts and permissions

### Azure

* **Subscription** with quota for: Container Apps (consumption), PostgreSQL Flexible Server (D-series), Event Hubs Standard, Storage, Key Vault and, optionally, Azure Data Explorer.
* **Deployer identity** (a person or CI service principal) with Owner, or Contributor + User Access Administrator, on the target subscription or resource group. The Terraform creates role assignments, and grants the deployer Key Vault Secrets Officer on the vault.
* **Microsoft Foundry:**
  * Claude models available in your chosen `foundry_location`;
  * enough deployment quota (tokens per minute) for the fast and deep models;
  * the model terms accepted in the Foundry portal.
* **Entra ID:** rights to create two app registrations (console SSO and the MCP API) and security groups for the SOC roles.

### AWS

* **A dedicated security-tooling account** (recommended: the Organizations delegated administrator or log-archive pattern), with administrator access for the deployer.
* **Amazon Bedrock model access** granted in `bedrock_region` for the chosen Claude models (Bedrock console: Model access).
* **An ACM certificate** in `region` for the internal load balancer hostname.
* **For an organisation CloudTrail:** access to the management account (or delegated administrator) to point the trail at the landing bucket.

## 3. Tools on the deployment workstation or CI runner

| Tool | Version | Check |
| --- | --- | --- |
| Terraform (or OpenTofu) | >= 1.9 | `terraform version` |
| Azure CLI (Azure path) | 2.60+ | `az version` |
| AWS CLI (AWS path) | v2 | `aws --version` |
| Docker with buildx | 24+ | `docker buildx version` |
| Python | 3.11 or 3.12 | `python --version` |
| Git | any | `git --version` |

**Azure: Key Vault access for Terraform.** Key Vault has no public access, and Terraform writes the secret placeholders through the data plane. The VNet is created by the same Terraform, so the **first** apply uses `deployer_cidrs` (your runner's egress IP, opened only on Key Vault). Later applies run from a runner inside the VNet or a peered hub, with `deployer_cidrs = []`.

## 4. Remote Terraform state (before the first apply)

**Azure.** Create a storage account and container for state, then enable the `backend "azurerm" {}` block in `infra/azure/versions.tf`:

```bash
terraform init \
  -backend-config="resource_group_name=<state-rg>" \
  -backend-config="storage_account_name=<statestorage>" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=meridian.tfstate" \
  -backend-config="use_azuread_auth=true"
```

**AWS.** Create an S3 bucket (versioned, encrypted), then enable the `backend "s3" {}` block in `infra/aws/versions.tf`:

```bash
terraform init \
  -backend-config="bucket=<state-bucket>" \
  -backend-config="key=meridian/terraform.tfstate" \
  -backend-config="region=<region>" \
  -backend-config="use_lockfile=true"
```

## 5. Information to collect

| Item | Used in |
| --- | --- |
| CMDB export (CSV: `asset_id, name, asset_type, business_service, owner, criticality, exposure, tags, aliases, ips`) | Enrichment, crown-jewel gating |
| Identity export (CSV: `identity_id, display_name, upn, email, sam, entra_object_id, aliases, privileged, department`) | Enrichment, privileged-user tagging |
| Threat-intel feeds (CSV / STIX 2.1 / TXT) | IOC matching |
| SOC group IDs: viewer, analyst, responder, admin | `security.oidc.role_map` |
| Firewall and proxy syslog source IPs | `syslog_cidrs` (AWS), the listener ACL (Azure) |
| Corporate client CIDRs for the console | `client_cidrs` (AWS), edge configuration (Azure) |
| Teams workflow URL / Slack webhook | Approval notifications |
| LODESTAR URL, org key and webhook secret (optional) | CISO reporting |
| Daily volume per source (GB/day) | Sizing, budget, cost model |

## 6. Change and security approvals

* Architecture review: HLD, LLD for your cloud, SECURITY.md.
* DPO sign-off on model inference residency and data minimisation.
* Firewall change requests: syslog to MERIDIAN, EDL pull from MERIDIAN, and the console route.
* SOC process change: approval duties for responders (four-eyes), on-call for platform alerts.
