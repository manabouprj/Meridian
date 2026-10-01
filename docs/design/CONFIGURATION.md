# Configuration reference

MERIDIAN reads one YAML file:

* `$MERIDIAN_CONFIG`, or `config/meridian.yaml` by default;
* reference cloud files: `config/examples/azure.yaml` and `config/examples/aws.yaml`.

Values may reference environment variables as `${VAR}` or `${VAR:-default}`. Secret-like keys **must** be references, and the loader refuses literal secrets. Run `meridian doctor` after every change.

## `org`

| Key | Default | Purpose |
| --- | --- | --- |
| `name` | Your Organisation | Shown in the console and given to the agents as context |
| `industry` | banking | Free text; shapes agent reasoning (for example "ports and logistics") |
| `crown_jewels` | [] | Business services the agents should treat as most critical. Asset-level crown jewels come from the CMDB CSV (criticality 5 or a `crown_jewel` tag) |

## `cloud`

`local` | `azure` | `aws`. This selects the cloud-specific defaults. The storage, queue and engine settings below still decide what is used.

## `lake`

| Key | Default | Purpose |
| --- | --- | --- |
| `root` | `data/lake` | Parquet lake: a local path, `s3://bucket[/prefix]` or `abfss://container@account.dfs.core.windows.net[/prefix]` |
| `landing` | `data/landing` | Landing zone for raw batches (same URL forms) |
| `query_engine` | `duckdb` | `duckdb`, `athena` or `adx` |
| `max_window_days` | 400 | Longest time window any query may cover |
| `athena` | - | `{database, table, workgroup}` (AWS) |
| `adx` | - | `{cluster_uri, database, table}` (Azure Data Explorer) |

## `queue`

| `type` | Keys | Notes |
| --- | --- | --- |
| `local` | - | Scans the landing zone; single host only |
| `sqs` | `url`, `landing_prefix` | S3 notifications to SQS (EventBridge and SNS envelopes also accepted) |
| `azure` | `account`, `name`, `container`, `landing_prefix`, `max_attempts` (5) | Event Grid to Storage Queue; poison messages go to `<name>-poison` |

## `store`

`url`: a SQLAlchemy URL.

* **Production:** `postgresql+psycopg://user:password@host:5432/meridian?sslmode=require`, provided through `MERIDIAN_DATABASE_URL`, or built automatically on AWS from the Aurora secret.
* **Local:** empty, which means SQLite under `data/`.

`ledger_days` (120) and `work_days` (30): how long the processed-batch ledger and finished work items are kept before the scheduler's daily housekeeping removes them. Alerts, cases, approvals, agent runs and the audit chain are never removed by housekeeping.

## `sources`

One entry per data source. A batch is matched to a source by its landing key prefix.

| Key | Required | Purpose |
| --- | --- | --- |
| `key` | yes | Source name (tags, metrics, ingest URL `/api/ingest/<key>`) |
| `format` | yes | Mapper: `syslog`, `cef`, `leef`, `windows`, `mde`, `entra`, `cloudtrail`, `ocsf`, `json` |
| `prefix` | no | Landing prefix if it differs from `key` (for example `AWSLogs` for CloudTrail) |
| `settings` | for `json` | `class_uid`, or `class_field` + `class_map`; `field_map` (`column: dotted.path`) |
| `settings.timezone` | no | Zone for naive timestamps (`+04:00`, `Asia/Dubai`); RFC 3164 syslog and NXLog `EventTime` need it |
| `settings.patterns` | no (`syslog`) | List of `{app, match, class_uid, activity_name, status, ...}`; regex named groups must be column names |
| `settings.keep_unparsed` / `keep_unmapped` | no | Default true: unrecognised syslog lines / Windows events are kept as OCSF Base Events (class 0) |
| `push` | no | `false` refuses HTTPS push for this source |
| `pull` | no | API collector block: `url`, `auth`, `params`, `records`, `paginate`, `expand`, `cursor`, `interval_minutes`, `max_pages` (LOG-00 §4.5) |

## `detections`

| Key | Default | Purpose |
| --- | --- | --- |
| `paths` | `[config/rules]` | Rule folders (YAML, Sigma-compatible) |
| `disabled` | [] | Rule ids to skip |
| `correlation_interval_minutes` | 5 | Scheduler cadence for correlation rules |

## `context`

| Key | Purpose |
| --- | --- |
| `assets` | CMDB CSV with columns `asset_id, name, asset_type, business_service, owner, criticality, exposure, tags, aliases, ips` (LODESTAR format). Criticality 5 or a `crown_jewel` tag marks a crown jewel; `exposure: internet` marks internet-facing |
| `identities` | Identity CSV with columns `identity_id, display_name, upn, email, sam, entra_object_id, aliases, privileged, department` |
| `intel_dir` | Threat-intel folder: `*.csv` (value, type, source, severity, expires), STIX 2.1 `*.json`, `*.txt` |

## `agents`

| Key | Default | Purpose |
| --- | --- | --- |
| `daily_budget_usd` | 50 | Above this spend per UTC day, triage runs in degraded (deterministic) mode |
| `run_budget_usd` | 2 | Maximum spend for a single agent run |
| `policy.auto_close_benign_min_confidence` | 0.8 | Minimum model confidence for auto-closing a benign alert |
| `policy.auto_close_max_severity` | 2 | Only alerts whose rule severity is at or below this may auto-close |
| `policy.auto_close_crown_jewels` | false | If false, alerts touching crown-jewel assets always go to a human |
| `policy.case_min_severity` | 3 | Suspicious/malicious alerts at or above this open or join a case |
| `policy.investigate_min_severity` | 4 | Cases at or above this (or malicious) are investigated |
| `policy.case_window_hours` | 24 | Alerts sharing a user or device within this window join one case |
| `limits.max_rows` | 200 | Rows per MCP tool call |
| `limits.max_window_minutes` | 43200 | Longest window per MCP tool call (30 days) |

**Setting `daily_budget_usd`.** Allow alerts per day x about $0.04 (fast tier), plus investigations x about $0.35 (deep tier), plus headroom. See `scripts/cost_model.py`.

## `model`

| Key | Purpose |
| --- | --- |
| `provider` | `anthropic_foundry`, `anthropic_bedrock`, `bedrock_converse`, `foundry_openai` or `scripted` |
| `resource` | Foundry resource (custom sub-domain) for the Foundry providers |
| `region` | Bedrock region |
| `fast` / `deep` | `{deployment: <name>}` (Foundry) or `{model: <model id or inference profile>}` (Bedrock) |
| `pricing` | `{model_or_deployment: [usd_per_million_input, usd_per_million_output]}` for spend tracking and budgets |

## `response`

| Key | Default | Purpose |
| --- | --- | --- |
| `dry_run` | true | Global default: executors describe the request instead of calling the API |
| `allowed_actions` | all | Actions agents may request |
| `approval_ttl_hours` | 24 | Pending approvals expire after this |
| `actions.<action>` | - | Per-action overrides: `dry_run`, `block_ttl_days`, `quarantine_security_group`, `role_arn`, `region`, `soar_webhook_url`, `soar_webhook_secret`, `mde_base`, `graph_base` |

## `notify`

`slack_webhook_url`, `teams_workflow_url` and `console_url`. These carry approval requests and critical cases; they never include raw events.

## `lodestar`

`url`, `org` and `webhook_secret`. The scheduler pushes cases and measured health (coverage, MTTD, open incidents) hourly.

## `security`

| Key | Default | Purpose |
| --- | --- | --- |
| `require_auth` | true | Keep true outside local development |
| `secure_cookies` | true | Session cookies only over HTTPS |
| `oidc.issuer` / `client_id` / `client_secret` / `redirect_uri` | - | Console SSO (Entra ID, Okta, Cognito, ...) |
| `oidc.audience` | - | Audience for REST bearer JWTs |
| `oidc.mcp_audience` | - | Audience for MCP bearer JWTs (Foundry Agent Service, AgentCore) |
| `oidc.role_map` | {} | `{group or app role: viewer / analyst / responder / admin}` |
| `oidc.role_claims` | [groups, roles] | Claims searched for role mapping |
| `oidc.default_role` | - | Optional role for authenticated users without a mapping (leave unset in production) |
| `mcp_scope_map` | {} | `{app role or group: [lake:read, context:read, cases:read, cases:write, response:request]}` |
