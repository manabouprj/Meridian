# MERIDIAN - Operations guide and runbook

## 1. Day-one onboarding checklist

| # | Step | Azure | AWS | Done when |
| --- | --- | --- | --- | --- |
| 1 | Build and push the image | `docker build`, push to ACR | `docker buildx --platform linux/arm64`, push to ECR | Image tag in tfvars |
| 2 | Apply Terraform | `infra/azure` | `infra/aws` | `terraform apply` clean |
| 3 | Set secrets | `az keyvault secret set` (8 secrets; the database URL is generated) | `aws secretsmanager put-secret-value` (8 secrets) | `/readyz` = 200 with no `placeholder_secrets` |
| 4 | Worker autoscale | KEDA rule command (LLD-azure 6) | Created by Terraform | Worker scales on queue length |
| 5 | SSO | Console app registration, groups to `role_map` | OIDC app in your IdP | Analyst can sign in; roles correct |
| 6 | Exports | Defender XDR streaming, Entra and Activity diagnostics to Event Hubs | Org CloudTrail to landing; Security Lake (opt.) | Batches visible in `landing/` |
| 7 | Network logs | Syslog VM/ACI or existing collector | NLB to the `syslog` service | `firewall/` batches arriving |
| 8 | Context | Assets, identities, intel CSV/STIX | Same | `meridian doctor` shows counts > 0 |
| 9 | Model | Foundry deployments, quota | Bedrock model access, ARNs | `meridian doctor` shows the provider; step 10 makes the first live model calls |
| 10 | Evaluate | `meridian eval` | `meridian eval` | Accuracy >= 0.8 on the golden set (add your own labelled alerts) |
| 11 | Response | Defender / Graph permissions; EDL in firewalls | Tags `meridian-containable=true`, quarantine SGs | Dry-run approvals show correct requests |
| 12 | Notifications and LODESTAR | Teams workflow URL, LODESTAR URL and secret | Slack webhook, LODESTAR | Test notification received; LODESTAR shows SOC findings |

## 2. Routine operations

| Frequency | Task | How |
| --- | --- | --- |
| Continuous | Watch alerts | See the alerts table in section 4 |
| Daily | Review cases awaiting approval and degraded runs | Console: Cases, Approvals, Runs |
| Daily | Verify the audit chain | `meridian verify-audit` (scheduled job) |
| Weekly | Review the tuning agent's proposals and noisy rules | Console: Runs (tune); edit `config/rules/*.yml`; `meridian rules --check` |
| Weekly | Sample 50 auto-closed alerts | Analyst review; add misses to the golden set |
| Monthly | Refresh CMDB and identity exports, rotate API keys and tokens | Pipeline / Key Vault / Secrets Manager |
| Per change | Rule, mapper, prompt or model change | PR, CI (tests, rules check, eval), deploy |

## 3. Configuration changes

* Rules: add Sigma YAML to `config/rules/`, run `meridian rules --check`, and deploy. Correlations pick up new rules on the next scheduler cycle.
* New source:
  1. Add an entry to `sources:` with `key`, `format`, `prefix` and, for `json`, a `field_map`.
  2. Point the export at `landing/<prefix>/`.
  3. Check with `meridian query`.
* Model change: update the deployment / model id, run `meridian eval`, and roll out only if accuracy holds.
* Budgets: `agents.daily_budget_usd` and `agents.run_budget_usd`. Set `model.pricing` so that spend is measured correctly.

## 4. Alerts and runbooks

| Alert | Likely cause | Action |
| --- | --- | --- |
| Silent source (`meridian_source_last_batch_age_seconds` > expected interval, or -1) | Export stopped, credentials expired, network change | Check the sender (diagnostic setting, streaming API, trail, syslog path); this is a detection failure (PCI DSS 10.7), so treat it as P2 |
| Reject ratio > 1% (`meridian_ingest_rejected_24h` / `meridian_ingest_events_24h`) | Sender changed its format, wrong `format` or `timezone` on the source | `meridian map-test` on a fresh sample; fix `patterns` / `field_map`; `meridian replay --prefix <source>/` (LOG-00 §9) |
| API collector failing (`meridian_pull_last_run_ok` = 0 for two intervals) | Expired credential, throttling, API change | Collector logs; rotate the `extra_secrets` value; `meridian pull --source <key>` to test |
| Poison queue (Azure) / DLQ (AWS) > 0 | A batch the mapper cannot parse, or a lake write failure | Read the worker logs for the key. Fix the mapper or the source config, then `meridian replay --prefix <key>` and clear the parked message |
| Landing queue age > 15 min | Workers down or under-scaled | Check worker tasks / replicas, the autoscale rule and the store connectivity (`/readyz`) |
| Heartbeat age > 300 s (`meridian_heartbeat_age_seconds`) | A background role crashed or is stuck | Restart the role; check logs; for the scheduler confirm that only one replica runs |
| Degraded agent runs > 0 | Budget reached or model endpoint failing | Check spend in Runs; check the Foundry / Bedrock quota and health; raise the budget only with approval |
| `/readyz` 503 with `placeholder_secrets` | A secret was never set | Set the listed secrets and restart |
| LODESTAR push failing (`meridian_lodestar_last_push_age_seconds` > 7200, or `meridian_lodestar_last_push_status` not 2xx) | Secret mismatch, wrong org key, network path, clock skew | INT-00 §9 troubleshooting table; no data is lost, the next accepted push carries the full state |
| Approvals pending > 4 h | Responders not notified or not available | Check the Teams/Slack webhook and the on-call rota |
| Audit chain BROKEN | Database rows modified | Treat as a security incident: preserve a DB snapshot, compare with exported chain heads, investigate DB admin access |
| Athena scanned bytes spike | Rule or hunt without class or time filters | Find the query id in the audit log; tighten the rule; the workgroup cutoff caps damage |

## 5. Backup and restore

* Store: PITR to a new server or cluster, then update `MERIDIAN_DATABASE_URL` / `MERIDIAN_DB_HOST` and restart.
* Lake: immutable; nothing to restore within retention. Rebuild a lost store's alerts from the lake by replaying the landing data that is still retained (`meridian replay`).
* Configuration: git is the source of truth for rules and config; secrets are in Key Vault / Secrets Manager.

## 6. Upgrades

1. Read the release notes and run the test suite and `meridian eval` against the new version in staging.
2. Database schema: tables are created if missing at start-up. Additive changes need no migration step; any destructive change will ship with a migration script and a note.
3. Deploy in this order: scheduler (stop), worker, agents, api, scheduler (start). Older workers can process batches during the rollout because ingestion is idempotent.

## 7. Capacity signals

| Signal | Scale |
| --- | --- |
| Queue length per worker > 50 sustained | More workers (automatic up to the maximum), then larger tasks |
| Triage backlog (`meridian_work_items{kind="triage",status="queued"}`) growing | More agents replicas; check model quota (TPM) |
| Console latency | More api replicas; move hunts to the deep tier or off-peak |
| Correlation runtime approaching 5 min | ADX (Azure) or narrower rule classes; increase the interval only as a last resort |
