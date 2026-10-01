# MERIDIAN - Security design and controls

This document lists the security controls of MERIDIAN 1.0.0, the threats they address, the residual risks, and the hardening options for regulated estates. It complements HLD section 8.

## 1. Trust boundaries

| Boundary | Crossed by | Control |
| --- | --- | --- |
| Security controls to landing zone | Exports, syslog, HTTPS push, API pull | Cloud IAM on the landing container / bucket (AWS: per-source writer policies); HMAC + timestamp (300 s window) or a token bound to one source; 10 MB request and 64 MB decompressed caps; syslog over TLS with optional client certificates; pull credentials only as `${ENV}` references from the vault |
| Landing to lake | Ingestion workers | Mappers reject unknown fields; every value is typed; raw record kept only in the `raw` column; Windows XML with DTDs or entities refused |
| Lake to agents | MCP `lake` / `context` tools | Scopes, field allow-list, bound parameters, row / window caps, UNTRUSTED notice |
| Agents to model | Model API (Foundry / Bedrock) | Private endpoint / VPC endpoint, managed identity / IAM, allow-listed deployments / ARNs, per-run and daily budget |
| Agents to response | MCP `response` tool | Request-only: creates a PENDING approval; target validators |
| Humans to platform | Console, API, chat | OIDC SSO with PKCE, roles, signed session cookie, double-submit CSRF token, four-eyes approvals |
| Platform to targets | Response executor in the api service | Executes only approved, unexpired requests, once; dry run by default; AWS tag conditions; cross-account role with a 15-minute session |
| Platform to LODESTAR | Signed webhook | HMAC over `timestamp.body`, `X-Lodestar-Timestamp` header |

## 2. Controls catalogue

### 2.1 Identity, authentication and authorisation

* No secrets in configuration files: the loader rejects literal values for secret-like keys and accepts only `${ENV}` references.
* Workloads authenticate with managed identity (Azure) or task roles (AWS). Foundry local (key) authentication is disabled in the reference Terraform.
* Console roles are viewer < analyst < responder < admin. Only responder and admin may decide approvals; only admin may read the audit log.
* API keys must be at least 16 characters and are compared in constant time. Browser sessions are HMAC-signed cookies with `Secure`, `HttpOnly` and `SameSite=Lax`.
* MCP endpoints accept agent tokens, API keys or IdP JWTs. Each is mapped to explicit scopes, and tools re-check the scope at call time.

### 2.2 Agent safety

* **Least tools.** Each agent role has an allow-list. Triage cannot see case or response tools.
* **Bounded runs.** Turns, tool calls, output tokens, wall-clock time and cost per run are limited, and there is a daily spend ceiling.
* **Structured output.** The run ends only through `submit_result`, which is validated by pydantic. Invalid output is returned to the model for correction within the run limits; a run that never produces valid output ends as `failed` or `limit`, never as a guess.
* **Deterministic policy.** Thresholds in configuration, not the model, decide auto-close, case creation and investigation. Auto-close also requires rule severity <= 2 (the rule's severity, which the model cannot lower) and never applies to crown-jewel assets.
* **Prompt-injection posture.** Telemetry is marked UNTRUSTED, the system prompt instructs the model to treat it as data, and no tool executes anything. The worst case of a successful injection is a wrong verdict or an unnecessary containment *request*, and a human still reviews the request.
* **Degraded mode.** When the budget is exhausted or the model fails, the deterministic analyst takes over. Its results are labelled and never auto-close alerts.
* **Evaluation gate.** `meridian eval` runs the golden set. CI or the release pipeline should block model, prompt or provider changes below the accuracy threshold.

### 2.3 Response safety

* Target validation rejects:
  * private, loopback, link-local and carrier-grade-NAT ranges;
  * IPv4 networks wider than /24 (IPv6 wider than /48);
  * malformed device ids, user names and instance ids.
* Approvals are deduplicated per case, action and target, and expire after 24 hours by default.
* The requester can never approve their own request.
* The decision is an atomic state change (pending and unexpired, then approved), so double clicks and races cannot execute twice.
* Every action is a dry run unless `response.actions.<action>.dry_run: false` is set explicitly.
* AWS policies allow containment only of resources tagged `meridian-containable=true`.

### 2.4 Data protection

* Encryption at rest:
  * ADLS (Microsoft-managed keys plus infrastructure encryption; customer-managed keys optional);
  * S3, SQS, Secrets Manager, CloudWatch and Aurora (KMS customer-managed key with rotation).
* TLS 1.2+ everywhere (ALB policy TLS 1.3/1.2). TLS verification is never disabled.
* The lake is WORM: an Azure container immutability policy, or S3 Object Lock (GOVERNANCE by default, COMPLIANCE optional).
* Data residency: the lake and store stay in the home region. Only the fields an agent asks for are sent to the model, capped at 200 rows per call. Choose a model region that matches your residency rules (for example, keep Foundry / Bedrock in-region where Claude models are available).

### 2.5 Integrity and audit

* The `audit` table is a SHA-256 hash chain covering:
  * every tool call;
  * agent run;
  * approval request and decision;
  * execution;
  * case change;
  * login.
* `meridian verify-audit` detects any modified or deleted row.
* Agent runs keep a truncated transcript (the last 60 messages) for review.

### 2.6 Platform hardening

* Containers run as non-root with a read-only root filesystem, dropped capabilities (Compose) and a slim base image. Dependencies are pinned in `requirements.txt` via pip-compile.
* There are no public data-plane endpoints in the reference deployments. Users reach the console through your edge.
* `/readyz` refuses traffic while any secret still holds a placeholder value.

## 3. Threat model (STRIDE summary)

| Category | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Forged telemetry pushed to `/api/ingest` | HMAC + timestamp + per-source secrets | A compromised sender key; rotate keys and use per-source secrets |
| Spoofing | Stolen agent token used against MCP | Scoped tokens, private network only, audit | Read access to the lake within the token's scopes; prefer IdP JWTs with short lifetimes |
| Tampering | Altering lake history | WORM retention, write-only role for workers, no delete permissions | Administrators with storage-account owner rights could delete an unlocked policy (Azure) or a GOVERNANCE lock (AWS); use a locked policy / COMPLIANCE for regulated retention |
| Tampering | Editing cases or audit rows in the database | Hash chain, DB access only from the app subnet | A DB administrator can rewrite the whole chain; ship daily chain heads to an external log or LODESTAR |
| Repudiation | "I did not approve that" | SSO identity in the approval, audit chain, Teams/Slack notifications | - |
| Information disclosure | Model provider sees security telemetry | In-region models, private endpoints, minimal fields, provider data-use terms | Review the provider's data processing terms (Foundry / Bedrock) with your DPO |
| Information disclosure | Agent output leaks data into notifications | Notifications carry summaries, not raw events | Review Teams/Slack channel membership |
| Denial of service | Log floods or expensive queries | Queue back-pressure, auto-scaling, Athena scan cutoff, query row and window caps, model budgets | Ingestion cost grows with volume (storage, not licence) |
| Elevation of privilege | Prompt injection makes an agent request containment of a critical asset | Request-only, validators, four-eyes human approval, dry run | A human approving without reading; training plus crown-jewel tags in the approval card |

## 4. Recommended hardening for regulated estates

1. Split the Azure workload identity into ingest, agent and api identities, as in the AWS role design.
2. Use customer-managed keys for ADLS and PostgreSQL (Azure) and keep the KMS CMK (AWS).
3. Lock the Azure immutability policy, or use Object Lock COMPLIANCE, after legal approval.
4. Require IdP JWTs (not static agent tokens) for remote MCP clients, with lifetimes under an hour.
5. Export audit chain heads daily to an external, write-once location.
6. Enable Bedrock model invocation logging or Foundry tracing to your own encrypted store, with a retention matching your policy.
7. Run `meridian eval` in the release pipeline, and keep a monthly human review of 50 auto-closed alerts.

## 5. Compliance mapping (indicative)

| Requirement area | MERIDIAN capability |
| --- | --- |
| Log retention and integrity (e.g. UAE NESA IAS, PCI DSS 10, ISO 27001 A.8.15) | WORM lake, hash-chained audit, 365-day default retention |
| Monitoring and detection (ISO 27001 A.8.16, NIST CSF DE.CM) | Streaming and correlation rules, agent triage, metrics |
| Incident response (NIST CSF RS.MA, ISO 27001 A.5.26) | Cases, investigation timeline, approvals, containment |
| Access control (ISO 27001 A.5.15, A.8.2) | SSO, roles, four-eyes, scoped MCP tokens |
| Data residency (UAE PDPL, GDPR) | In-region storage and compute; model region selectable |

This mapping supports, but does not replace, your own control assessment.

## 6. Reporting a vulnerability

Report suspected vulnerabilities privately to the repository owner. Do not open a public issue. Include the version, the configuration involved (without secrets) and reproduction steps.
