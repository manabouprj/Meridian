# MERIDIAN 1.0.0 - Pre-release peer review

An independent reviewer audited the code, Terraform and documentation before release. They verified each finding with a reproduction or by reading the code against the provider documentation. All findings below are fixed in 1.0.0. Each fix has a regression test or an automated check where one is possible.

Further validation added during the review:

* The test suite runs on PostgreSQL 16, not just SQLite (`MERIDIAN_TEST_PG`). It now runs in CI as well.
* Both Terraform stacks pass `validate` against the real provider schemas (azurerm 5.7.0, aws 6.48.0) and an offline `plan` with mocked providers (`infra/*/tests/plan.tftest.hcl`). The mocked plan found one more defect (R-21).
* `terraform fmt` normalised seven files that would have failed the CI format check.

## Findings and resolutions

| ID | Severity | Area | Finding | Resolution | Evidence |
| --- | --- | --- | --- | --- | --- |
| R-01 | Critical | Response | Four-eyes bypass: a responder could request containment over MCP and approve it on the console, because the two paths recorded different identity strings | Canonical identities (`meridian/identity.py`) compared on every decision. Requests made with a human token are stored under the canonical identity, and user JWTs on MCP are treated as people | `test_four_eyes_holds_across_mcp_and_console_identities`; reviewer probe now returns 403 |
| R-02 | High | Lake | Concurrent DuckDB queries on one shared connection could return another caller's rows | Execute and fetch serialised with a lock | Reviewer race probe: 0 cross-results |
| R-03 | High | Audit | The hash chain could fork under concurrent writers | Process lock plus a PostgreSQL transaction-scoped advisory lock | 6 processes × 60 writes on PostgreSQL: chain valid (360) |
| R-04 | High | Azure | The poison-queue path needed queue send rights; a 403 would crash-loop the worker | Storage Queue Data Message Sender role; parking failures are logged and never stop the worker; per-message failures no longer stop the drain | `test_azure_queue_parks_poison_messages`, `test_failed_batch_is_recorded_and_replay_is_idempotent` |
| R-05 | High | Ingest | Azure Activity source options were not passed to the mapper (zero events) | Options nested under `settings:`; top-level mapper keys are also accepted | `test_azure_activity_source_maps_through_the_pipeline` |
| R-06 | High | AWS | Internal ALB listened on 443 behind a security group that only allowed 8090 | Dedicated ALB security group (443 from `client_cidrs`); app accepts 8090 only from the ALB | Mocked plan |
| R-07 | High | AWS | Syslog rule used protocol `-1` with ports (invalid; would open all ports) | Separate TCP and UDP rules on 5514 from `syslog_cidrs` | Mocked plan asserts no `-1` ingress |
| R-08 | High | AWS | KMS key had no grants for CloudWatch Logs, S3 notifications or CloudTrail | Explicit key policy; landing bucket policy for CloudTrail; TLS-only bucket policies | `validate` + mocked plan |
| R-09 | High | Azure | Terraform could not write Key Vault secrets (private vault, no data-plane role for the deployer) | Key Vault Secrets Officer for the deployer; optional `deployer_cidrs`; VNet runner documented | Mocked plan |
| R-10 | Medium | Ingest | Timestamps with UTC offsets landed in the wrong date/hour partition | All timestamps normalised to UTC before partitioning | Unit check; full suite |
| R-11 | Medium | Store | Long attacker-controlled values (entities, titles) failed PostgreSQL length limits and crash-looped the scheduler | Truncating string type for all non-key columns; per-alert error isolation | PostgreSQL suite |
| R-12 | Medium | Detection | Correlation catch-up after downtime was a fixed 10 minutes | Persisted cursor; catch-up from the last evaluated time (up to 24 h) | `test_scheduler_cycle_isolates_failures_and_persists_state` |
| R-13 | Medium | Scheduler | An unreachable LODESTAR crashed the scheduler, and restarts re-sent approval notifications | Each scheduler step isolated; notified approvals persisted | Same test |
| R-14 | Medium | Syslog | A failed flush lost the buffered lines; no flush on shutdown | Lines restored on failure (bounded, drops counted); SIGTERM handled with a final flush | `test_syslog_buffer_keeps_lines_when_storage_fails`; live UDP/TCP + SIGTERM smoke test |
| R-15 | Medium | Response | Hex-only domains (`bad.cafe`) were classified as IPs; `::ffff:10.x` passed the internal-range check | Classification by parsing; IPv4-mapped, reserved and unspecified addresses refused | `test_indicator_validation_edge_cases` |
| R-16 | Medium | AWS | Console hunts ran in the api task, which has no model permissions (silent degraded mode) | Hunts are queued to the agents service; `GET /api/hunt/{id}` returns the result | `test_hunts_are_queued_for_the_agents_service` |
| R-17 | Medium | Agents | 600 s work lease shorter than the longest run (duplicate investigations across replicas) | 3600 s lease plus a wall-clock limit per run (600 s fast, 1800 s deep) | Full suite |
| R-18 | Medium | AWS | S3 writes requested the AWS-managed key instead of the bucket's customer-managed key | SSE header removed so the bucket default (CMK with bucket key) applies | Code review |
| R-19 | Low | Response | SOAR webhook URL (may contain a token) stored in results visible to viewers | URL redacted to scheme and host | Code review |
| R-20 | Low | Docs | Several documentation claims did not match the code (health check path, metric label, wall-clock limit, case auditing, approval TTL, ADX wiring) | Code fixed where the claim was the right behaviour (wall-clock limit, case-change audit, TTL setting); docs corrected otherwise (ADX post-apply steps documented) | This document |
| R-21 | High | AWS | Security group names began with `sg-`, which AWS rejects (found by the mocked plan) | Names changed to `<prefix>-alb/-app/-db/-vpce` | Mocked plan |

## Additional hardening made during documentation review

* `/readyz` returns 503 while any secret still holds a Terraform placeholder or an `.env.example` value. The AWS ALB health check uses `/readyz`.
* Heartbeats for worker, agents and scheduler appear in `/readyz` and as `meridian_heartbeat_age_seconds`.
* `meridian replay --prefix` re-processes landing batches after a mapper or rule fix.
* In degraded mode (budget exhausted or model down), triage never auto-closes alerts.
* Cross-account AWS response through a member-account role (`role_arn`, 15-minute session).
* `meridian demo --serve` prints one-time sign-in keys.

## Residual items (not defects, to confirm at deployment)

* The Claude model deployment format, name and version in the Foundry model catalog; Claude model ids or inference profiles and the exact IAM actions for the Bedrock endpoint in use.
* AgentCore Gateway target configuration and Cedar action names for the gateway version in use.
* ADX private endpoint and data connection (post-apply steps in LLD-azure §5.3).
* Vendor adapters (Defender, Graph, AWS) and model providers have been tested against stubs and recorded responses, not live tenants. Run the onboarding checklist (OPERATIONS.md) in a non-production tenant first.

## Second review: production readiness (executive review cycle)

A second, independent review assessed whether MERIDIAN can replace a SIEM on day one. Its verdict and phased plan are in EXECUTIVE_REVIEW.md. The items below were cheap to fix and material to readiness, so they were fixed in this release:

| ID | Area | Finding | Resolution | Evidence |
| --- | --- | --- | --- | --- |
| R-22 | AI policy | Auto-close relied only on the model's confidence; a severity-5 alert could be auto-closed | Auto-close also requires rule severity <= 2 (configurable) and never applies to crown-jewel assets | `test_auto_close_is_gated_by_rule_severity_and_crown_jewels` |
| R-23 | HA | A second scheduler replica would duplicate notifications and pushes | Lease-based leader lock in the store | `test_scheduler_leader_lock_and_source_health` |
| R-24 | Compliance | No detection of silent log sources (PCI DSS 10.7) | `meridian_source_last_batch_age_seconds` per source; runbook alert | Same test; OPERATIONS.md §4 |
| R-25 | Reporting | Coverage sent to LODESTAR was hard-coded at 100% | Coverage measured from sources that delivered data in the last 24 h | `test_lodestar_coverage_is_measured_not_assumed` |
| R-26 | API | Interactive API docs (`/docs`, `/openapi.json`) were public | Opt-in with `MERIDIAN_API_DOCS=1` | `test_interactive_api_docs_are_off_by_default` |
| R-27 | Container | The Dockerfile health check could never fail (it ended with an unconditional exit 0) | Removed; health checks are defined per role (Compose, ALB, Container Apps probes) | Review |
| R-28 | Agents | The tune agent was defined but could not be triggered | `meridian tune --rule <id>` (proposals only, never applied automatically) | `test_tune_agent_recommends_without_applying` |
| R-29 | Docs | The HLD migration plan (weeks) and the 0.5 FTE estimate contradicted the evidence | HLD aligned to the 9-15 month phased plan and the TCO model | This document |
| R-30 | AWS ops | The runbooks assumed ECS Exec, which was not enabled | One-off tasks (`aws ecs run-task`) with new Terraform outputs | DEPLOY-AWS.md step 8 |

Capability gaps that remain (content breadth, connectors, analyst UX, schema migrations, compaction, AI evidence on your own alerts) are planned in the phased implementation. They are not defects.

## Third review: build documents and the LODESTAR integration

Writing the build documents (AZ-00, AWS-00) against the PHALANX layout, and the integration document (INT-00) against a running LODESTAR, exposed the gaps below. All were fixed in this release.

| ID | Area | Finding | Resolution | Evidence |
| --- | --- | --- | --- | --- |
| R-31 | Residency (Azure) | Foundry deployments defaulted to Global Standard, so inference could run in any Azure geography | Default is Sonnet 5.5, Azure-hosted (version 2), Data Zone Standard (US); Terraform refuses version 1 and any SKU other than DataZoneStandard / GlobalStandard | `infra/azure/variables.tf` validations; `tofu test`; check 5 of `verify_deployment.py azure` |
| R-32 | Residency (AWS) | The Bedrock client used a plain model id, which has no in-region offer in me-central-1 | Global inference profile ids (`bedrock_fast_model`, `bedrock_deep_model`) called through the bedrock-runtime VPC endpoint; IAM covers profile and foundation-model ARNs | `test_bedrock_provider_uses_the_private_runtime_endpoint`; check 9 of `verify_deployment.py aws` |
| R-33 | AI governance | Nothing proved that the agent which ran was the agent that was approved | SHA-256 fingerprint of each agent's definition recorded on every run and in the audit chain; `meridian baseline` prints the approved set | `test_constitution_fingerprint_is_recorded_and_sensitive_to_change` |
| R-34 | AI governance | No way to stop an agent quickly | Kill switch: `meridian halt`, `POST /api/agents/<name>/halt` (responder); resume is admin only; a halted agent falls back to the deterministic analyst and never auto-closes | `test_kill_switch_halts_agents_and_keeps_triage_running` |
| R-35 | Assurance | Deployed controls could only be checked by reading the console | `scripts/verify_deployment.py` runs 12 read-only checks per cloud; a check that cannot run is a FAIL | `tests/test_verify_deployment.py` |
| R-36 | Integration | IP addresses and cloud accounts were sent to LODESTAR as `asset_id`, and the first host seen was reported instead of the most important | Entity mapping: devices, accounts and resources to `asset_id` (most critical by the shared CMDB), users to `user_id`, IPs to `entity_keys` only | `test_payload_shape_and_identity_mapping`, `test_most_critical_asset_is_reported` |
| R-37 | Integration | Confirmed incidents did not reach LODESTAR's Today list | `actively_exploited_in_env` set for malicious, unresolved cases | Live run: phishing case on Today with FS-01 (INT-00 §9) |
| R-38 | Integration | KPI name `sources_silent` did not match LODESTAR's `log_sources_silent`; MTTR was not sent | Renamed; `mttr_hours` added | `test_payload_validates_against_lodestar_model` (CI job `lodestar-contract`) |
| R-39 | Integration | The scheduler advanced its push cursor even when LODESTAR rejected the push | Cursor advances only after a 2xx; status and age exported as `meridian_lodestar_last_push_status` / `_age_seconds` | `test_lodestar_push_cursor_only_advances_after_success`, `test_metrics_and_mcp_gate` |
| R-40 | Integration | Terraform created the webhook secret but never set the LODESTAR URL or organisation, so the integration could not be switched on without editing task definitions | `lodestar_url` (https only) and `lodestar_org` variables on both clouds | `tofu validate`; INT-00 §7 |

## Fourth review: log ingestion for hybrid estates

Writing LOG-00 checked every documented ingestion method against the code. The gaps below were closed in this release.

| ID | Area | Finding | Resolution | Evidence |
| --- | --- | --- | --- | --- |
| R-41 | Windows | No mapper for Windows Security, System, Sysmon or PowerShell events, so on-premises servers without an EDR were invisible and the `process_creation` rules could not use them | `windows` mapper for NXLog, Winlogbeat, Fluent Bit (map) and rendered XML; Sysmon `UtcTime` preferred; naive times take the source `timezone`; DTDs and entities refused; two new rules (privileged group add, event log cleared) | `test_windows_mapper_reads_every_common_shipper_shape`, `test_demo_on_premises_storyline_is_detected_from_windows_and_syslog` |
| R-42 | Syslog | Only CEF lines were understood; plain syslog, LEEF and Linux auth messages were rejected and lost from the lake | `syslog` mapper: RFC 5424 / 3164 headers, CEF and LEEF routing, JSON payloads, built-in sshd / sudo / user patterns, user `patterns`; unrecognised lines kept as OCSF Base Event (class 0) | `test_syslog_routes_cef_leef_patterns_and_keeps_the_rest`, `test_structured_syslog_records_from_journald_and_vector` |
| R-43 | Time | ISO timestamps with fractional seconds and a non-UTC offset lost the offset (events misplaced by hours) | Fractional-second trimming keeps the offset | `test_iso_offsets_with_fractions_are_honoured` |
| R-44 | Syslog transport | TLS syslog relied on an external terminator | Native TLS (RFC 5425) with optional mutual TLS; PEM from the vault held in memory; Azure TLS syslog Container App (`syslog_receiver`) | `test_tls_syslog_receiver_with_mutual_tls`; Terraform test |
| R-45 | Push | Log shippers cannot compute HMAC, so the push endpoint was usable only by custom code; gzip bodies were refused | Source-bound tokens, gzip with a decompression cap, NDJSON, and a Splunk HEC-compatible endpoint | `test_token_push_gzip_and_hec` |
| R-46 | SaaS | No way to collect APIs that cannot push (Microsoft 365 Management Activity, Okta, GitHub) | API pull collector (`meridian collect`) with OAuth2, pagination, two-step expansion and safe cursors; `extra_secrets` in Terraform | `test_pull_collector_*`, `test_pull_auth_secrets_must_be_environment_references` |
| R-47 | Retention | The lake was WORM and tiered but never expired, so storage grew forever and log types could not have different lifetimes; the processed-batch ledger also grew forever | `lake_expire_days` and `lake_expire_days_by_class` (validated against WORM) on both clouds; daily housekeeping of the ledger and finished work items | Terraform tests; `test_housekeeping_removes_old_ledger_rows_only` |
| R-48 | Onboarding and operations | No way to preview normalisation before go-live; no reject-rate metric; on AWS no least-privilege way for external shippers to write the landing bucket | `meridian map-test`; `meridian_ingest_*_24h` and `meridian_pull_last_run_ok` metrics; per-source `landing_writer_sources` policies | `test_map_test_previews_normalisation`; Terraform test |
