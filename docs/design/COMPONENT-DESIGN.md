# Component design

The code is organised as one Python package (`meridian/`, about 6,300 lines) with clear module boundaries. Each section below covers a module's responsibility, its interfaces, its key behaviour, how it fails, and how to extend it.

```
meridian/
  config.py        settings loader (YAML + ${ENV}), secret guard
  ocsf.py          OCSF-flat schema, event builder, timestamp normalisation
  mappers/         source format -> OCSF events (syslog, cef, leef, windows, mde, entra, cloudtrail, ocsf, json)
  ingest/          landing zone, work notifications (local / SQS / Azure Queue), pipeline, syslog receiver (UDP/TCP/TLS),
                   HTTPS push (HMAC, source tokens, Splunk HEC), API pull collector
  lake/            object stores (local / S3 / ADLS), Parquet writer, QuerySpec compiler, engines
  detect/          Sigma parser, streaming detector, correlation runner
  context/         assets, identities, threat intel; enrichment
  store/           operational store (SQLAlchemy Core): alerts, cases, approvals, runs, queue, audit, locks
  mcp_servers/     toolbox (the security boundary) + four MCP servers
  agents/          agent definitions, runtime loop, model providers, orchestrator (policy)
  response/        action registry, target validation, approval decision and execution
  api/             FastAPI app: console, REST, MCP mounts, ingest, EDL, metrics; auth (keys, sessions, OIDC)
  integrations.py  LODESTAR hand-off, Slack / Teams notifications
  identity.py      canonical identities (four-eyes)
  runtime.py       wiring: lazily builds every component from settings
  cli.py           roles and operator commands
  doctor.py        configuration and connectivity checks
  demo/            fictional estate generator (Kestrel Logistics)
```

## 1. Configuration (`config.py`)

* **Responsibility.** Load one YAML file (`$MERIDIAN_CONFIG` or `config/meridian.yaml`), resolve `${VAR}` and `${VAR:-default}`, and produce a typed `Settings` object.
* **Guard.** A key that looks like a secret (secret, password, token, api_key, access_key, private_key, connection_string, sas) must be an `${ENV}` reference, or loading fails.
* **Database URL.** On AWS it is built from the Aurora managed secret (`MERIDIAN_DB_CREDENTIALS`) and `MERIDIAN_DB_HOST`, so password rotation needs no configuration change.
* **Failure handling.** `ConfigError` stops start-up with a precise message; `meridian doctor` explains the fix.

## 2. Schema (`ocsf.py`)

* **Responsibility.** Define the 42 columns and 11 classes, and build events.
  * `event(class_uid, time=, source=, raw=, **fields)` rejects unknown fields.
  * Timestamps (ISO-8601 with any offset, epoch seconds or milliseconds, nanosecond strings) are normalised to UTC.
* **Extension.** Add a column to `COLUMNS`, the Glue table (`infra/aws/data.tf`) and the ADX schema (`python scripts/gen_adx_schema.py`).

## 3. Mappers (`mappers/`)

* **Interface.** `mapper(record, settings) -> list[event]`. A mapper returns `[]` for records it does not handle, and raises for malformed ones; the pipeline counts those as rejected without failing the batch.

| Mapper | Input | Notes |
| --- | --- | --- |
| `syslog` | RFC 5424 / 3164 lines, or structured records (journald, Vector, Fluent Bit) | Routes CEF, LEEF and Windows JSON; built-in sshd / sudo / useradd / usermod patterns plus `settings.patterns`; unrecognised lines kept as class 0 (`keep_unparsed`) |
| `cef` | CEF lines (syslog) | Common CEF extension keys mapped; severity normalised |
| `leef` | LEEF 1.0 / 2.0 | Custom delimiters; `sev` 1-10 normalised |
| `windows` | NXLog JSON, Winlogbeat, Fluent Bit (`event_data_as_map`), rendered XML, XML-to-JSON | Security, System, Sysmon, PowerShell 4104, Defender AV; `settings.timezone` for naive times; other IDs kept as class 0 (`keep_unmapped`); DTD/entities refused |
| `mde` | Defender XDR streaming / Advanced Hunting tables | Process, network, file, logon, alert tables |
| `entra` | Entra ID sign-in and audit logs | Risk, MFA, conditional access |
| `cloudtrail` | CloudTrail records | `Records` arrays unwrapped |
| `ocsf` | Nested OCSF (Security Lake, OCSF producers) | Flattened |
| `json` | Any JSON | `settings.class_uid` or `class_field` + `class_map`, `field_map` with dotted paths |

* **Extension.** Write `mappers/<name>.py`, register it in `mappers/__init__.py`, and add fixtures to `tests/test_mappers.py`.
* **Preview.** `meridian map-test --file <sample> --format <mapper>` shows classes, populated columns and rejects without storing anything.

## 4. Ingestion (`ingest/`)

* **Landing.** `write_batch` writes gzip JSONL or log batches. `read_batch` reads Avro (Event Hubs Capture `Body`), JSON, JSONL, gzip and line formats.
* **Queues.**

| Queue | Used for | Behaviour |
| --- | --- | --- |
| `LocalQueue` | Local use | Scans for unprocessed keys |
| `SQSQueue` | AWS | S3, EventBridge and SNS envelopes; 900 s visibility |
| `AzureQueue` | Azure | Event Grid `BlobCreated`; messages delivered more than `max_attempts` times are parked in `<queue>-poison` |

  Delivery is at-least-once everywhere, and processing is idempotent.
* **Pipeline** (`Pipeline.process(key, force)`):
  1. resolve the source by prefix;
  2. read the batch and map each record;
  3. remove duplicate `event_uid`s and enrich;
  4. write Parquet;
  5. run streaming rules and upsert alerts;
  6. queue new alerts for triage;
  7. mark the batch processed.

  A failing batch is not acknowledged (cloud) or is recorded as failed (local), so one bad batch never stops the worker.
* **Syslog.** UDP, TCP and TLS (`--tls-port`, optional mutual TLS with `--tls-client-ca`; certificate and key from files or PEM environment variables held in memory). Newline-delimited and RFC 6587 / 5425 octet counting.
* **HTTPS push** (`ingest/push.py`). HMAC or a token bound to one source (`MERIDIAN_INGEST_TOKENS`); gzip with a 64 MB decompressed cap; JSON, NDJSON or lines; Splunk HEC-compatible `/services/collector` endpoints.
* **API pull** (`ingest/pull.py`, role `collect`). Bearer, header, basic or OAuth2 client credentials; link / next-field / header pagination; two-step `expand`; cursor modes `max` and `window`; the cursor advances only after the landing write.
  * The buffer flushes every `--flush` seconds or 20,000 lines.
  * A failed flush keeps the lines (bounded, oldest dropped and counted).
  * SIGTERM triggers a final flush.

## 5. Lake (`lake/`)

* **Stores.**
  * `LocalStore`: atomic writes, path-escape protection.
  * `S3Store`: bucket-default SSE-KMS.
  * `AzureStore`: `overwrite=False`; an existing blob counts as success, which keeps WORM and idempotency compatible.
* **Writer.** Groups events by `(class, UTC day, UTC hour)` and writes zstd Parquet named after the batch hash.
* **Query compiler.** `QuerySpec` has these limits:

| Element | Limit |
| --- | --- |
| Classes, time window, `where` conditions | Up to 25 conditions, 14 operators |
| Fields | Up to 40 |
| `group_by` | Up to 5, plus optional `count_distinct` and `having` |
| Results | Up to 10,000 rows |

  It compiles to:
  * `compile_sql` for DuckDB and Trino: quoted identifiers, `?` parameters, partition predicates on `dt` and `cls`;
  * `compile_kql` for ADX: `declare query_parameters`, bracketed columns.
* **Engines.**
  * `DuckDBEngine`: in-process, UTC, credential chain, serialised by a lock.
  * `AthenaEngine`: `ExecutionParameters`, polling, pagination.
  * `ADXEngine`: `/v1/rest/query` with a managed-identity token.

## 6. Detection (`detect/`)

* **Sigma parser** (`sigma.py`):
  * logsource mapping to OCSF classes, and field mapping from Sigma names;
  * modifiers `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `gt`/`gte`/`lt`/`lte`, `exists`, and wildcards;
  * condition grammar (`and`/`or`/`not`, `1 of`/`all of`, parentheses).

  Unsupported constructs raise `RuleError` at load time.
* **Streaming detector.** Evaluates every event against every applicable rule, and groups matches into alerts by rule + entity + suppression bucket. The alert id is deterministic, so repeats update one alert.
* **Correlation runner.** `event_count` and `value_count` rules compile to aggregate QuerySpecs. They run every 5 minutes over windows ending now, with catch-up from the persisted cursor (up to 24 h) after downtime.

## 7. Context (`context/`)

Loads assets (CMDB CSV), identities (CSV) and threat intel (CSV, STIX 2.1 JSON, TXT), then enriches events:

* tags: `asset:`, `crit:`, `crown_jewel`, `internet_facing`, `identity:`, `privileged_user`, `ioc`;
* `ioc_hits`, which also matches parent domains.

Context is loaded once per process; refreshing it needs a role restart (live reload is a Phase 4 item).

## 8. Operational store (`store/db.py`)

SQLAlchemy Core on PostgreSQL or SQLite. Strings truncate at their declared length. Main operations:

| Area | Operations |
| --- | --- |
| Batches | `batch_done`, `mark_batch`, `source_last_seen` |
| Alerts | `upsert_alert` (merges samples and counts), `related_alerts` |
| Cases | `open_case_for(entities, hours)` groups alerts by shared user or device; `create_case` / `update_case` are audited |
| Approvals | `request_approval` (deduplicated, TTL), `decide_approval` (atomic pending to decided), `expire_approvals` |
| Work queue | `enqueue` (deduplicated), `lease` (optimistic, with lease expiry), `complete` (retry up to max attempts) |
| Cursors and locks | `get_cursor` / `set_cursor`, `try_lock` (leader lease) |
| Audit | `audit` (serialised hash chain), `verify_audit` |

## 9. MCP servers and toolbox (`mcp_servers/`)

* **Toolbox.** Implements every tool. Each call checks the caller's scope (`CALLER` contextvar), validates arguments, applies the row and window caps, labels telemetry results UNTRUSTED, and writes an audit row.
* **`build_servers`.** Registers the tools on four `MCPServer` instances with read-only or write annotations and structured output.
* **Exposure.** The API mounts the servers as stateless streamable HTTP behind `MCPAuth`, which accepts:
  * agent tokens (explicit scopes);
  * API keys (scopes from the role);
  * IdP JWTs (scopes from `mcp_scope_map`). User tokens are treated as people for four-eyes.

## 10. Agents (`agents/`)

* **Definitions.** Each agent has a role, a tool allow-list (glob patterns), limits, a model tier, an output schema and a wall-clock timeout:

| Agent | Turns / tool calls | Tier | Timeout |
| --- | --- | --- | --- |
| Triage | 6 / 8 | fast | 600 s |
| Investigate | 12 / 20 | deep | 1,800 s |
| Hunt | 12 / 20 | deep | 1,800 s |
| Tune | 6 / 8 | fast | 600 s |

* **Runtime loop.**
  1. Send the system prompt and task to the provider.
  2. Execute the allowed tool calls through the ToolHub, truncating results while keeping valid JSON.
  3. Repeat until `submit_result`, which pydantic validates; invalid output goes back to the model for correction.
  4. The run ends `ok`, `failed`, `limit` or `budget`.
* **Providers.**
  * `anthropic_foundry`: Entra token provider.
  * `anthropic_bedrock`: IAM.
  * `bedrock_converse`, `foundry_openai`.
  * `scripted`: the deterministic analyst.
* **Orchestrator.** Applies policy (ADR-007), budgets (daily and per run) and degraded mode. It leases work items (triage, investigate, hunt) with a 3,600 s lease and records every run.

## 11. Response (`response/`)

* **Action registry.** Each action has a target validator and an executor:
  * isolate_device, revoke_sessions, disable_user;
  * block_indicator (internal EDL);
  * aws_deactivate_access_key, aws_quarantine_instance (optional cross-account role);
  * soar_playbook (signed webhook, URL redacted in results).
* **`decide`.** Requires the responder or admin role and enforces four-eyes on canonical identities. The approval moves atomically, then executes once.
* **`execute_approved`.** Merges defaults with per-action settings, dry run first.

## 12. API (`api/`)

FastAPI app providing:

* the console (server-rendered pages, CSRF double-submit);
* the REST API, MCP mounts, signed ingest, the EDL feed, `/healthz`, `/readyz` and `/metrics`.

Authentication: API keys (constant-time comparison), signed session cookies, and OIDC (authorisation code + PKCE, JWKS verification, group-to-role mapping). Interactive API docs are opt-in.

## 13. Roles and scheduling (`cli.py`)

| Role | Loop | Resilience |
| --- | --- | --- |
| `worker` | Drain the queue; back off on errors | Per-message isolation; heartbeat |
| `agents` | Lease and run work items | Wall-clock limits; lease longer than the longest run; heartbeat |
| `scheduler` | Correlations, approval expiry and notifications, LODESTAR push | Leader lock; each step isolated; state persisted |
| `syslog` | Receive and flush | Loss-free buffer; SIGTERM flush |

Operator commands:

* `demo`, `query`, `rules --check`, `hunt`, `eval`;
* `replay --prefix`, `doctor`, `verify-audit`.

## 14. Extension points summary

| To add... | Change | Test |
| --- | --- | --- |
| A data source | Source entry in config (+ mapper if new format) | `tests/test_mappers.py`, `tests/test_pipeline.py` |
| A detection | YAML in `config/rules/` | `meridian rules --check`; unit test with sample events |
| An MCP tool | `Toolbox` method + `build_servers` registration + scope | `tests/test_mcp_security.py` |
| A response action | `ACTIONS` entry with validator and executor | `tests/test_integrations.py` (stubbed API) |
| A model provider | `providers/` class implementing `complete()` | Translation test in `tests/test_agents.py` |
| A query engine | `engines.py` class with `run(spec)` | `tests/test_query.py` |
