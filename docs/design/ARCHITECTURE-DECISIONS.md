# Architecture decision records

Each record states the context, the decision, the alternatives considered and the consequences, including the costs we accept. Status is *Accepted* unless stated otherwise.

## ADR-001 Replace the SIEM layer with a lake + rules + agents, not with agents alone

* **Context.** The goal is to remove the per-GB SIEM licence and its infrastructure. An all-AI design (agents reading raw logs) would be cheaper to build but neither deterministic, testable nor auditable, and it would be very expensive in tokens at enterprise volumes.
* **Decision.** Three layers:
  * an object-storage lake for retention and search;
  * deterministic Sigma-compatible rules for detection;
  * AI agents for triage, investigation and hunting.
* **Alternatives.**
  * A cheaper SIEM tier: lock-in remains.
  * An open-source SIEM (OpenSearch/Wazuh): cluster operations remain.
  * Agents only: rejected for cost and assurance.
* **Consequences.**
  * Detection quality depends on rule content, which must be built (see the executive review, Phase 2).
  * Agent spend scales with alerts, not with log volume.

## ADR-002 Normalise to a flat OCSF schema

* **Context.** Rules, agents and three query engines need one schema. Nested OCSF is verbose for rules and wasteful for columnar pruning.
* **Decision.**
  * OCSF class and activity semantics, flattened into 42 typed columns (`meridian/ocsf.py`).
  * The original record is kept in `raw`.
  * Unknown fields are rejected at mapping time.
* **Consequences.**
  * Some source-specific detail is available only in `raw`.
  * Adding a column is a schema change (Parquet union-by-name and an Athena/Glue update).
  * Email sender/subject and registry columns are future additions.

## ADR-003 Land raw batches first, then process (landing zone pattern)

* **Context.** Streaming straight into a processor loses data when the processor fails, and makes reprocessing impossible.
* **Decision.**
  * All sources land as immutable files: Event Hubs Capture, S3, syslog flush, HTTPS push.
  * An object-created notification queues the work.
  * Processing is idempotent, because the lake file name is derived from the landing key.
* **Consequences.**
  * Detection latency is bounded by batch intervals (about 1 minute plus processing).
  * Replay is free (`meridian replay`).
  * Many small files result, so compaction is a Phase 1 item.

## ADR-004 Sigma-compatible rules, not a custom DSL

* **Decision.** A Sigma subset with explicit errors for unsupported constructs, plus Sigma-style correlation rules.
* **Consequences.**
  * Content is portable to and from other tools.
  * Community rules need field mapping, and some will not load. The import yield must be measured before the content plan relies on it.

## ADR-005 Agents act only through MCP servers with scopes

* **Context.** An LLM given broad credentials is an unacceptable risk: prompt injection through log content is expected.
* **Decision.**
  * Four MCP servers (lake, context, cases, response), each requiring a scope.
  * Tools validate every argument, cap rows and time windows, and label telemetry as untrusted.
  * The same servers serve the built-in runtime (in-process) and managed agents (Foundry Agent Service, AgentCore Gateway) over streamable HTTP.
* **Consequences.** Every new agent capability is a reviewed tool, not a prompt change.

## ADR-006 Response is request-only; humans approve; the platform executes once

* **Decision.**
  * `request_containment` creates a pending approval.
  * A responder approves it under four-eyes rules, with identities compared in canonical form.
  * The decision is atomic, and the executor uses the platform identity.
  * Dry run is the default.
* **Alternatives.** Autonomous containment for high-confidence cases. Rejected for 1.0: insufficient evidence of model calibration, and regulators expect human accountability.
* **Consequences.** Mean time to contain includes human response time; Teams/Slack notifications shorten it.

## ADR-007 Policy, not the model, decides outcomes

* **Decision.**
  * The model returns a validated verdict, confidence and evidence.
  * Configured policy decides what happens next: close, keep, join or open a case, investigate.
  * Auto-close requires a benign verdict at confidence >= 0.8, rule severity <= 2, no crown-jewel asset, and a non-degraded run.
* **Consequences.** Behaviour can be audited and changed without retraining or re-prompting.

## ADR-008 Engine-neutral, injection-safe query compiler

* **Decision.**
  * Agents and rules describe queries as a validated `QuerySpec`.
  * It compiles to DuckDB/Trino SQL or KQL, with an allow-listed field set, bound parameters and quoted identifiers.
* **Consequences.**
  * No free-form SQL from models.
  * Some analyst queries need a richer spec; a search UI is planned for Phase 4.

## ADR-009 Pluggable query engines: DuckDB, Athena, ADX

* **Decision.**
  * DuckDB in-process for small estates and local use.
  * Athena (pay per TB scanned) on AWS.
  * Azure Data Explorer (dedicated cluster) for medium and large Azure estates.
* **Consequences.**
  * DuckDB is serialised per process: no concurrency, and memory-bound.
  * Athena cost depends on query shape: compaction and entity-sorted files are needed at scale.
  * ADX is a fixed monthly cost.

## ADR-010 PostgreSQL as the operational store

* **Decision.** PostgreSQL (Aurora Serverless v2 / Flexible Server, both with HA) holds the operational records:
  * alerts, cases, approvals and runs;
  * the work queue (leases);
  * cursors and locks;
  * the audit chain.

  SQLite is used for local and test only. The suite runs on both.
* **Consequences.**
  * One operational dependency.
  * Schema migrations need a tool (Alembic): planned before the first schema change after 1.0.

## ADR-011 Tamper-evident audit as a hash chain in the store

* **Decision.** Every tool call, decision, execution, case change and login is a row whose hash covers the previous hash. Writers are serialised (process lock plus PostgreSQL advisory lock).
* **Consequences.**
  * A database administrator could rewrite the whole chain.
  * Exporting chain heads daily to a write-once location is the recommended hardening.

## ADR-012 Claude through the customer's cloud (Foundry or Bedrock), with a deterministic fallback

* **Decision.**
  * Claude models are called through Microsoft Foundry (managed identity) or Amazon Bedrock (IAM role): no API keys, private endpoints, the customer's agreements.
  * A fast tier handles triage and tuning; a deep tier handles investigation and hunting. On AWS the fast tier is Haiku 4.5; on Azure both tiers are Sonnet 5.5, because only the Sonnet and Opus Azure-hosted versions are offered in the US Data Zone.
  * Every run records the SHA-256 of the agent's definition (instructions, tools, limits, output schema), so any verdict can be traced to the exact constitution that produced it (`meridian baseline`).
  * A scripted analyst takes over when the budget is exhausted or the model is unavailable.
* **Consequences.**
  * Inference residency depends on regional model availability; UAE workloads use cross-region inference today.
  * Model spend is capped per run and per day.

## ADR-013 One container image, several roles

* **Decision.** One image runs as `api`, `worker`, `agents`, `scheduler` or `syslog`. A singleton scheduler is protected by a lease lock.
* **Consequences.**
  * A simple supply chain and one SBOM.
  * Roles scale independently.

## ADR-014 Configuration as code with secrets only by reference

* **Decision.**
  * One YAML file per deployment.
  * Secret-like keys must be `${ENV}` references; the loader refuses literals.
  * `/readyz` refuses traffic while any secret still holds a placeholder.
* **Consequences.** Secrets live only in Key Vault or Secrets Manager. Configuration can be reviewed in pull requests.
