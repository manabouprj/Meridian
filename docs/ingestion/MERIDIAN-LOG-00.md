---
file: MERIDIAN-LOG-00-Log-Ingestion-Normalisation-Retention
cover_title: MERIDIAN
kicker: "SIEM-LESS DETECTION AND RESPONSE · LOG INGESTION"
subtitle: "Log ingestion, normalisation, retention and rotation for hybrid estates"
summary: "How on-premises, cloud and SaaS logs reach MERIDIAN: six ingestion paths, from cloud-native exports and syslog over TLS to Windows Event Forwarding with NXLog, Sysmon, log shippers, HTTPS push and API pull. How every record is normalised to one OCSF schema without losing anything, how long each kind of log is kept and how it is rotated, and how to onboard, size and operate each source."
running: "MERIDIAN — LOG INGESTION, NORMALISATION, RETENTION AND ROTATION"
footer: "MERIDIAN SIEM-less Detection and Response · LOG-00 · v{{VERSION}} · {{DATE}}"
cover_meta: {DOCUMENT: LOG-00, VERSION: "{{VERSION}}", PATHS: "6", MAPPERS: "9", DATE: "{{DATE}}"}
---

<h1 class="doc">Getting the logs in</h1>
<p class="lede">Most SIEM projects are decided by ingestion: what can be collected, what it costs, whether it parses, and how long it is kept. This document is MERIDIAN's answer, path by path.</p>

:::box blue What this document is, and how it relates to the others
This is the design and build document for MERIDIAN's ingestion tier in a hybrid estate: Windows and Linux servers, network and OT devices on premises, Azure and AWS platforms, and SaaS applications.

It covers six things: the ingestion paths and when to use each; the Windows and Sysmon design; normalisation; retention and rotation; sizing and operations; and the onboarding procedure.

The platform build is in AZ-00 (Azure) and AWS-00 (AWS); this document adds only what ingestion needs. Where it and the code disagree, the code (`meridian/ingest`, `meridian/mappers`) and Terraform are the truth.
:::

## 1 Why ingestion is where SIEM projects struggle

The same seven problems appear in almost every SIEM programme. MERIDIAN's design starts from them.

{: .red }
| Problem with a conventional SIEM | What it causes | What MERIDIAN does instead |
| --- | --- | --- |
| **Licence priced per GB ingested** | Teams filter out firewall, DNS, flow and endpoint logs to stay under the cap. The data needed in an investigation was never collected | Storage is billed at object-storage prices, with no ingestion licence and no daily cap. Collect everything that has security value; filter for noise, not cost |
| **Parsing at the edge, before storage** | A vendor changes its log format, the parser fails and events are dropped or mis-filed until someone notices | **Land raw first, parse later.** Every batch is stored exactly as received for 90 days. A mapper fix is followed by a replay, so nothing is lost |
| **A different schema per source and per tool** | Rules and queries are written per vendor; migrations rewrite them | One schema: OCSF classes in 42 typed columns. The same columns work in DuckDB, Athena and Azure Data Explorer, and for every agent and rule |
| **Agent sprawl** | A proprietary agent on every server, with its own upgrade cycle | No MERIDIAN agent. Native forwarding (WEF, diagnostic settings, CloudTrail), standard syslog, and any shipper you already run |
| **Retention tied to the licence or to hot storage** | A year of logs is unaffordable; old logs go to an archive that cannot be searched | Retention is a storage setting per log class, enforced by WORM (Object Lock or immutability). Older data moves to cheaper tiers and stays queryable |
| **Silent sources go unnoticed** | A source stops sending and nobody knows until an incident | Per-source freshness, event counts and reject counts are metrics with alerts; LODESTAR reports silent sources as a KRI |
| **Lock-in through formats and forwarders** | Leaving the SIEM means re-plumbing every source | Open formats (Parquet, OCSF), standard protocols, and a Splunk HEC-compatible endpoint so existing senders can be re-pointed |

## 2 Architecture

!fig images/ingestion-light.svg 2.1 Six ways in, one landing zone, one schema. Everything is private and authenticated.

### Design principles

1. **Land raw, then normalise.** Collection never depends on parsing. The landing zone holds each batch exactly as received, compressed and immutable, for 90 days, and the lake can be rebuilt from it.
2. **One schema.** Every record becomes one or more OCSF-flat events. The full original record is kept in the `raw` column for forensics.
3. **Never drop silently.** A record that no mapping recognises is kept as an OCSF Base Event (class 0) with its host, program and message. A record that cannot be read at all is counted as a reject, and rejects are a metric.
4. **Every path is private and authenticated**, and each sender can write only into its own source prefix.
5. **Retention is policy, not price.** WORM for the minimum period, tiering for cost, and a per-class end of life.
6. **No model in the ingestion path.** Ingestion and first-line detection are deterministic, cheap and auditable. Agents see alerts and query results, never the firehose.

### Components

{: .teal }
| Component | Role | Runs as |
| --- | --- | --- |
| Landing zone | Raw batches `<source>/<yyyy>/<mm>/<dd>/<batch>.<ext>`, gzip, 90-day expiry | ADLS Gen2 container / S3 bucket (SSE-KMS) |
| Queue | New-batch notification, at-least-once delivery | Event Grid → Storage queue / S3 event → SQS with a dead-letter queue |
| Ingestion worker | Mapper → enrichment → de-duplication → Parquet → streaming detection | `meridian worker`; scales on queue depth (KEDA / ECS autoscaling) |
| Syslog receiver | UDP, TCP and TLS (RFC 5425) listener, buffered batches to landing | `meridian syslog` (ECS behind your NLB; Container App on Azure) |
| Push endpoint | `/api/ingest/<source>` (HMAC or token) and `/services/collector` (HEC) | The API service, internal only |
| API collector | Polls SaaS and management APIs, with cursors | `meridian collect`: one active replica, lease-locked |
| Lake | OCSF-flat Parquet `events/cls=/dt=/hr=`, WORM, tiered | ADLS / S3; queried by DuckDB, Athena or Azure Data Explorer |

## 3 Choosing an ingestion path

### The six paths

{: .purple }
| Path | Best for | Authentication | Latency |
| --- | --- | --- | --- |
| 1 Cloud-native export to object storage | Azure and AWS platform logs; anything a vendor can export to Blob or S3 | Cloud IAM, inside your tenancy | Minutes (the provider's delivery interval) |
| 2 Streaming capture | High-volume Azure feeds (Event Hubs Capture) and AWS streams (Firehose) | Cloud IAM | 1–5 minutes (capture window) |
| 3 Syslog receiver | Network, security and OT devices, Linux, NXLog CE, log relays | Network allow-list; TLS with optional client certificates | ≤ 30 seconds (flush interval) |
| 4 HTTPS push | Log shippers, custom applications, existing Splunk HEC senders | HMAC signature or a token bound to one source | Seconds |
| 5 API pull | SaaS audit logs exposed only through APIs | OAuth2 client credentials, bearer or basic, held in the vault | Interval (default 5 minutes) plus the API's own delay |
| 6 Shipper to object storage | Kubernetes, large Linux estates, Cribl or Vector pipelines | IAM role limited to one source prefix (AWS); managed identity (Azure) | Shipper batch interval |

### Source catalogue

{: .teal }
| Source | Recommended path | Alternatives | Mapper | Notes |
| --- | --- | --- | --- | --- |
| Windows servers and domain controllers: Security, System, PowerShell | Windows Event Forwarding to a collector (WEC), NXLog CE `om_ssl` → TLS syslog (3) | Fluent Bit `winevtlog` → push (4); NXLog Agent `om_http` → push; Winlogbeat → Logstash → push or S3 | `windows` (through `syslog`) | Section 5. Filter to the event IDs you use at the collector |
| Sysmon | Same as Windows (Sysmon channel in the WEF subscription) | Same | `windows` | Use a maintained Sysmon configuration; image-load and registry events are the volume drivers |
| Windows endpoints with Defender for Endpoint | Defender XDR streaming API → Event Hubs or Storage (1 / 2) | – | `mde` | No Windows forwarding needed for these hosts |
| Linux servers | rsyslog or syslog-ng with TLS → syslog (3) | Fluent Bit or Vector (journald, files) → S3/Blob (6) or push (4) | `syslog` | sshd, sudo and useradd are recognised; auditd through its syslog plugin |
| Network devices (switches, routers, wireless) | UDP syslog to a local relay (rsyslog), relay → TLS syslog (3) | Direct UDP/TCP to the AWS receiver | `syslog` + `patterns` | Add a pattern per message you want as a typed event; the rest is kept as Base Events |
| Firewalls, proxies, WAF, VPN, IPS | CEF or LEEF over syslog (3) | Vendor cloud log export to S3/Blob (1) | `syslog` (CEF/LEEF auto) or `cef` | Palo Alto, Fortinet, Check Point, F5, Zscaler NSS, Netskope |
| OT, port and terminal systems, appliances | CEF/LEEF syslog to a relay in the OT DMZ, relay → TLS syslog (3) | – | `syslog` | UDP syslog crosses one-way gateways (data diodes); TCP and TLS do not |
| Azure: Entra ID, Activity log, resource logs, Defender for Cloud | Diagnostic settings or continuous export → Event Hubs → Capture, or → Storage (1 / 2) | – | `entra`, `json` (field map) | VNet flow logs to Storage; NSG flow logs retire on 30 September 2027 |
| AWS: CloudTrail, VPC Flow Logs, Route 53 Resolver, GuardDuty, ALB/WAF | Organisation trail and service exports to S3 (1) | Security Lake subscriber (OCSF) | `cloudtrail`, `ocsf`, `json` | Partition by account and region; the landing prefix maps to the source |
| AWS CloudWatch Logs (applications, Lambda, EKS) | Subscription filter → Firehose → S3 (2) | – | `json` / `syslog` | |
| Kubernetes and containers | Fluent Bit DaemonSet → S3/Blob (6) or push (4) | Vector | `json` / `syslog` | |
| Microsoft 365 audit | API pull, Management Activity API (5) | Entra and Defender through Event Hubs (1) | `json` (field map) | Two-step API; start the subscription once |
| Okta, GitHub, Google Workspace, Atlassian, Salesforce | API pull (5) | Vendor streaming to S3/Blob where offered (1) | `json` (field map) | Link, next-field and header pagination are supported |
| CrowdStrike, Zscaler and other OCSF producers | Vendor export or Security Lake (1) | Push (4) | `ocsf` | |
| Existing SIEM during migration | Splunk HEC senders → `/services/collector` (4); QRadar/ArcSight forwarders → syslog LEEF/CEF (3) | Log Analytics data export → Storage / Event Hubs (1) | per source | Run side by side, then cut over source by source |
| Custom applications | HTTPS push with HMAC (4) | JSON lines into landing (6) | `json` (field map) | `scripts/push_events.py` signs requests for tests |

:::box amber Do not build on Azure Monitor Agent "direct to store"
The preview that let Azure Monitor Agent send Windows events and syslog straight to Event Hubs or Storage is being retired. New data collection rules could not be created from February 2026, and existing ones stop sending after **31 July 2026**. Microsoft's replacement routes data through Log Analytics first, which brings back per-GB ingestion charges. For Windows and Linux on Azure, use the paths in this document (WEF with NXLog, Fluent Bit, rsyslog), not AMA.
:::

## 4 The six paths in detail

### 4.1 Cloud-native export to object storage

The provider writes files into the landing container or bucket. A storage event puts a message on the queue, and the worker processes the batch.

- **Mapping.** A source is matched by the longest prefix: `{key: cloudtrail, format: cloudtrail, prefix: AWSLogs}`. Envelopes such as Azure `{"records": [...]}`, CloudTrail `{"Records": [...]}` and Graph `{"value": [...]}` are unwrapped automatically.
- **Formats.** JSON, JSON lines and text lines, each optionally gzip-compressed, plus Event Hubs Capture Avro.
- **Cross-account (AWS).** Point or replicate the organisation trail into the landing bucket. Set `cloudtrail_account_ids` so that both the bucket policy and the KMS key policy allow it.

### 4.2 Streaming capture

For feeds that only stream (Defender XDR, Entra, Activity log), send them to an Event Hub with **Capture** to the landing container. Capture writes Avro every 1–5 minutes or every N MB, and MERIDIAN reads the `Body` of each record. On AWS, Kinesis Data Firehose writes gzip JSON to the landing bucket with a buffering hint (for example 5 MB / 60 s).

### 4.3 Syslog receiver

{: .teal }
| Property | Value |
| --- | --- |
| Listeners | `--port` UDP + TCP (default 5514); `--tls-port` TLS (6514 by convention); either can be off (0) |
| Framing | Newline-delimited or octet-counted (RFC 6587 / RFC 5425) |
| Header formats | RFC 5424; RFC 3164 with or without `<PRI>`; ISO-timestamp forwarding formats |
| Payloads | CEF, LEEF 1.0/2.0, JSON (Windows events from NXLog, or generic), plain text |
| TLS | TLS 1.2 or later; certificate and key as files or as PEM in `MERIDIAN_SYSLOG_TLS_CERT` / `_KEY` (held in memory, never written to disk) |
| Mutual TLS | `--tls-client-ca`: only senders with a certificate from that CA can connect |
| Buffering | Flushes every 30 s or 20,000 lines. A storage outage keeps lines in memory (up to 500,000) and retries; lines are capped at 64 KB |
| AWS deployment | ECS service, 2 tasks, UDP and TCP 5514 behind your Network Load Balancer. For TLS, use an NLB TLS listener with an ACM certificate in front of TCP 5514, or run with `--tls-port` |
| Azure deployment | Container App (`syslog_receiver = true`), TCP 6514 with TLS on the environment's internal IP. **Container Apps has no UDP ingress**: UDP senders go through a relay |

**A relay per site** is the recommended pattern for UDP-only devices. rsyslog or syslog-ng on a small VM receives UDP locally and forwards over TLS with a disk queue, so a WAN outage delays data instead of losing it.

rsyslog, forwarding to MERIDIAN over TLS with a client certificate and a disk-assisted queue:

```
global(DefaultNetstreamDriver="gtls"
       DefaultNetstreamDriverCAFile="/etc/pki/meridian/ca.pem"
       DefaultNetstreamDriverCertFile="/etc/pki/meridian/client.pem"
       DefaultNetstreamDriverKeyFile="/etc/pki/meridian/client.key")
action(type="omfwd" target="syslog.meridian.internal.example" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="syslog.meridian.internal.example"
       TCP_Framing="octet-counted" template="RSYSLOG_SyslogProtocol23Format"
       queue.type="LinkedList" queue.filename="meridian_fwd" queue.maxDiskSpace="2g"
       queue.saveOnShutdown="on" action.resumeRetryCount="-1")
```

syslog-ng:

```
destination d_meridian {
  syslog("syslog.meridian.internal.example" transport("tls") port(6514)
    tls(ca-file("/etc/pki/meridian/ca.pem") cert-file("/etc/pki/meridian/client.pem")
        key-file("/etc/pki/meridian/client.key") peer-verify(required-trusted))
    disk-buffer(disk-buf-size(2000000000) reliable(yes)));
};
```

### 4.4 HTTPS push

{: .teal }
| Endpoint | Authentication | Body |
| --- | --- | --- |
| `POST /api/ingest/<source>` | HMAC: `X-Meridian-Timestamp` + `X-Meridian-Signature: sha256=HMAC(secret, "<ts>.<body>")`, 5-minute window; or `Authorization: Bearer <token>` bound to `<source>` | JSON object or array, `{"records": [...]}`, NDJSON, or text lines; `Content-Encoding: gzip` |
| `POST /services/collector[/event]` | `Authorization: Splunk <token>` (or Bearer); the token decides the source | Splunk HEC events (concatenated `{"event": ...}` objects) |
| `POST /services/collector/raw` | Same | Raw lines |
| `GET /services/collector/health` | None | HEC health check |

- **Limits.** 10 MB per request (compressed), 64 MB once decompressed (413 above it), and 100,000 records per request.
- **Tokens.** `MERIDIAN_INGEST_TOKENS = "source:token,..."` (secret `ingest-tokens`; `none` disables tokens). Each token is at least 32 characters and is valid for one source only.
- **HEC.** Indexer acknowledgement is not offered. Senders that require it must turn it off.

Fluent Bit on Windows, pushing Security, System, Sysmon and PowerShell events:

```
[INPUT]
    Name               winevtlog
    Channels           Security,System,Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-PowerShell/Operational
    Interval_Sec       1
    Event_Data_As_Map  true
    DB                 C:\fluent-bit\winevtlog.sqlite

[OUTPUT]
    Name         http
    Match        *
    Host         meridian.internal.example
    Port         443
    URI          /api/ingest/windows
    Format       json_lines
    Header       Authorization Bearer ${MERIDIAN_INGEST_TOKEN}
    Compress     gzip
    tls          On
    tls.verify   On
    tls.ca_file  C:\fluent-bit\ca.pem
```

`Event_Data_As_Map true` is required: without it Fluent Bit sends positional `StringInserts`, which change between Sysmon schema versions and are not mapped.

### 4.5 API pull collector

The collector reads `pull:` blocks in the source configuration. It runs as its own role (`meridian collect`, one active replica, ingestion identity) and writes what it fetched to the landing zone.

{: .teal }
| Option | Values |
| --- | --- |
| `auth` | `bearer {scheme, token}`, `header {name, token}`, `oauth2 {endpoint, client_id, client_secret, scope}`, `basic {username, password}`, `none`. Secrets must be `${ENV}` references (literal secrets fail at load) |
| `params` | Query parameters with `{cursor}`, `{end}` and `{now}` placeholders |
| `records` | Dotted path to the list in the response (`""`, `value`, `items` ...) |
| `paginate` | `link` (RFC 8288 `Link: rel="next"`), `next_field {path}` (for example `@odata.nextLink`), `header {name}` (for example `NextPageUri`), `none` |
| `expand` | Field holding a URL to fetch per item: two-step APIs such as Microsoft 365 `contentUri` |
| `cursor` | `field` (record time), `mode` max or window, `start_minutes`, `max_window_minutes`, `format` (strftime) |
| `interval_minutes`, `max_pages` | Defaults 5 and 50 |
| Secrets | `extra_secrets = ["okta-token"]` in Terraform creates the vault entry and exposes `MERIDIAN_OKTA_TOKEN` |

The cursor advances only after the batches are in the landing zone. HTTP 429 or 5xx ends the run without moving the cursor, and the next run resumes from the same point.

Microsoft 365 Management Activity API (start the subscription once with `/subscriptions/start`):

```
- key: m365
  format: json
  settings: {class_uid: 6003, field_map: {time: CreationTime, user: UserId, api_operation: Operation,
             src_ip: ClientIP, app_name: Workload, resource: ObjectId, status: ResultStatus}}
  pull:
    url: https://manage.office.com/api/v1.0/<tenant-id>/activity/feed/subscriptions/content
    auth: {type: oauth2, endpoint: "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
           client_id: <app id>, client_secret: "${MERIDIAN_O365_CLIENT_SECRET}",
           scope: "https://manage.office.com/.default"}
    params: {contentType: Audit.General, startTime: "{cursor}", endTime: "{end}"}
    paginate: {type: header, name: NextPageUri}
    expand: contentUri
    cursor: {mode: window, start_minutes: 60, max_window_minutes: 1440, format: "%Y-%m-%dT%H:%M:%S"}
    interval_minutes: 5
```

The window is capped at 24 hours because the API refuses longer ranges. It also refuses start times more than 7 days back. If the collector is down for longer than that, the gap cannot be recovered from this API.

### 4.6 Shipper straight to object storage

Fluent Bit, Vector, Cribl, Logstash or NXLog Agent write batches to `<source>/...` in the landing zone.

- **AWS.** Set `landing_writer_sources = ["k8s", "linux"]`. Terraform creates one managed policy per source, allowing `s3:PutObject` under that prefix only, with the lake KMS key. Attach it to the shipper's role: an EKS service account, an EC2 instance role, or IAM Roles Anywhere for on-premises collectors.
- **Azure.** The lake account is keyless and private. In-Azure shippers use a managed identity with Storage Blob Data Contributor on the landing container, over the private endpoint. On-premises shippers should use push (4.4) or syslog (4.3) instead, because shared keys are disabled.

Vector on Linux, journald to the landing bucket:

```
[sources.journal]
type = "journald"

[sinks.meridian]
type = "aws_s3"
inputs = ["journal"]
bucket = "<landing bucket>"
key_prefix = "linux/%Y/%m/%d/"
region = "me-central-1"
compression = "gzip"
encoding.codec = "json"
framing.method = "newline_delimited"
server_side_encryption = "aws:kms"
ssekms_key_id = "<lake KMS key ARN>"
```

With `{key: linux, format: syslog}`, journald records are read with their host (`_HOSTNAME`), program (`SYSLOG_IDENTIFIER`) and message.

## 5 Windows and Sysmon

Windows is the largest and most valuable on-premises source, and the one most often collected badly. The design avoids an agent on every server.

!fig images/flow-log-onprem-light.svg 5.1 Windows Event Forwarding to a collector, NXLog CE to MERIDIAN's TLS syslog receiver.

### Collection design

- **Windows Event Forwarding (WEF).** Built into Windows. Servers send to one or more Windows Event Collectors (WEC) under a source-initiated subscription set by Group Policy. Transport is WinRM (HTTP 5985), encrypted with Kerberos inside the domain. Use one WEC per site or per 2,000–4,000 sources, and two for resilience.
- **On the WEC.** NXLog CE (`im_msvistalog` on `ForwardedEvents` → `to_json()` → `om_ssl` to 6514 with a client certificate). Fluent Bit (`winevtlog` on `ForwardedEvents` → push) is the alternative.
- **Hosts that cannot use WEF** (workgroup servers, DMZ) run NXLog or Fluent Bit locally with the same output.
- **Time zone.** NXLog writes `EventTime` in local time without a zone. Set `timezone` on the source (for example `+04:00` or `Asia/Dubai`). Sysmon's `UtcTime` is always used when present.

NXLog CE on the collector:

```
<Extension json>
    Module  xm_json
</Extension>
<Input wec>
    Module  im_msvistalog
    <QueryXML>
      <QueryList><Query Id="0"><Select Path="ForwardedEvents">*</Select></Query></QueryList>
    </QueryXML>
    Exec    to_json();
</Input>
<Output meridian>
    Module       om_ssl
    Host         syslog.meridian.internal.example
    Port         6514
    CAFile       C:\Program Files\nxlog\cert\ca.pem
    CertFile     C:\Program Files\nxlog\cert\wec01.pem
    CertKeyFile  C:\Program Files\nxlog\cert\wec01.key
</Output>
<Route wec_to_meridian>
    Path  wec => meridian
</Route>
```

### Audit policy prerequisites

{: .amber }
| Setting (Group Policy, Advanced Audit Policy) | Why |
| --- | --- |
| Logon/Logoff: Logon, Account Lockout, Special Logon — success and failure | 4624, 4625, 4740, 4672 |
| Account Logon: Kerberos Authentication Service, Kerberos Service Ticket Operations, Credential Validation (on DCs) | 4768, 4769, 4771, 4776: spraying, Kerberoasting, NTLM use |
| Account Management: User Account Management, Security Group Management | 4720–4738, 4728/4732/4756 |
| Detailed Tracking: Process Creation, plus "Include command line in process creation events" | 4688 with the command line, for hosts without Sysmon or an EDR |
| Object Access: Other Object Access Events | 4698 (scheduled task created) |
| PowerShell: Script Block Logging | 4104 |
| Security log size and retention | Large enough to cover a WEC outage (for example 1 GB on DCs) |

### What is mapped

{: .teal }
| Channel | Event IDs | OCSF class | Used by |
| --- | --- | --- | --- |
| Security | 4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771, 4776 | 3002 Authentication | Spray, brute force, sign-in correlations |
| Security | 4672 | 3005 User Access Management | Hunting |
| Security | 4688 | 1007 Process Activity | All `process_creation` Sigma rules |
| Security | 4720, 4722–4726, 4738, 4740, 4767, 4781 | 3001 Account Change | Account and lockout rules |
| Security | 4728, 4729, 4732, 4733, 4756, 4757 | 3005 User Access Management | `mer-id-ad-priv-group-add` |
| Security / System | 4697, 4698, 4702, 7045 | 6003 API Activity (service, task) | Persistence hunting |
| Security / System | 1102, 104 | 6003 (log cleared, high severity) | `mer-ep-event-log-cleared` |
| Sysmon | 1, 5, 8, 10, 25 | 1007 Process Activity | `process_creation` rules; LSASS access (10) |
| Sysmon | 3 / 22 | 4001 Network / 4003 DNS | IOC matching, network rules |
| Sysmon | 11, 15, 23, 26 | 1001 File System Activity | Ransom-note and file rules |
| Sysmon | 12–14 (registry) and anything else | 0 Base Event (kept, searchable) | Hunting |
| PowerShell | 4104 | 1007 (script block in `message`) | Hunting |
| Defender Antivirus | 1006, 1116, 1117 | 2004 Detection Finding | Vendor-detection rule |

:::box green Proven in the demo
The demo estate includes a Windows file server without an EDR. Its Security log arrives as NXLog JSON in local time, and its Sysmon log as Winlogbeat JSON. The same run includes a Linux jump host over RFC 3164 syslog. From those logs MERIDIAN raises:

- brute force (30 × 4625);
- an account added to Administrators (4732);
- a certutil download (Sysmon 1);
- the threat-intelligence domain (Sysmon 22);
- the Security log being cleared (1102).

The run rejects nothing.
:::

## 6 Normalisation

### The schema

Every event is OCSF-flat: 42 typed columns shared by all classes (time, class, activity, severity, status, user, source and destination IP and port, device, process, file, URL, DNS, action, cloud account, API operation, resource, message and others). Two columns are special:

- `raw` keeps the original record;
- `event_uid` is a stable hash used for de-duplication.

Columns are an allow-list: rules, queries and MCP tools can reference only these names.

### Mappers

{: .purple }
| `format` | Input | Produces |
| --- | --- | --- |
| `syslog` | RFC 5424/3164 lines, or structured records (journald, Vector, Fluent Bit); routes CEF, LEEF and Windows JSON; built-in patterns (sshd, sudo, useradd, usermod) plus your `patterns` | Typed classes, or 0 Base Event |
| `cef` | ArcSight CEF (alone or inside syslog) | 4001 / 4002 / 4003 / 3002 |
| `leef` | IBM LEEF 1.0 and 2.0 (custom delimiters) | 4001 / 4002 / 4003 / 3002 |
| `windows` | NXLog, Winlogbeat, Fluent Bit (map), rendered XML, XML-to-JSON | Section 5 table |
| `mde` | Defender XDR advanced-hunting stream | 1007, 4001/4002, 1001, 3002, 2004 |
| `entra` | Entra ID sign-in and audit logs | 3002, 3001, 3005, 6003 |
| `cloudtrail` | AWS CloudTrail | 6003, 3002 |
| `ocsf` | Any OCSF producer (Security Lake, CrowdStrike, Okta, Zscaler) | Flattened as-is |
| `json` | Anything else, with `class_uid` (or `class_field` + `class_map`) and a `field_map` of dotted paths | Configured class |

### Rules applied to every event

- **Time.** UTC. Naive timestamps take the source's `timezone`. Fractional seconds and offsets are honoured. RFC 3164 times get the year inferred, so December logs read in January land in the right year.
- **Identity.** Users and hosts in lower case. `DOMAIN\user` is split into `user` and `user_domain`. IPv4-mapped IPv6 (`::ffff:`) is reduced to IPv4. Image paths are reduced to the file name in `process_name`, with the full path in `file_path`.
- **Windows placeholders.** Values such as `-` become null.
- **Enrichment.** Asset criticality and crown-jewel tags from the CMDB, identity attributes, and threat-intelligence indicator hits (`ioc_hits`), all at ingestion.
- **De-duplication.** Within a batch by `event_uid`. Re-delivered batches are skipped by the processed-batch ledger. Replays are idempotent.

### Previewing a source before it goes live

```
meridian map-test --file sample.jsonl --format windows --timezone +04:00
format=windows records=1200 events=1200 rejected=0
  class 3002 Authentication: 840
  class 1007 Process Activity: 310
  class 0 Base Event: 50
  columns populated: time(1200), device(1200), user(1150), src_ip(820), process_name(310), ...
```

`map-test` stores nothing. Run it on a sample from every new source, and keep the output with the onboarding record.

### Adding a mapper

A mapper is one function `(record, settings) -> [events]` registered in `meridian/mappers/__init__.py`. It must be deterministic and side-effect free, build events with `ocsf.event()` (which rejects unknown columns), and come with tests on real samples. Field maps and `patterns` cover most new sources without code.

## 7 Retention and rotation

### Layers

{: .teal }
| Layer | Holds | Kept | Controlled by |
| --- | --- | --- | --- |
| Source | Windows event logs, syslog relay disk queues, shipper buffers | Size-based (the operating system or shipper) | Your build standards: big enough to ride out a WAN or collector outage |
| Landing zone | Raw batches as received | **90 days**, then deleted | Lifecycle rule (both clouds). Cool tier after 7 days on Azure |
| Lake | OCSF Parquet per class, day and hour | **WORM for `lake_retention_days`** (default 365) | S3 Object Lock (GOVERNANCE or COMPLIANCE) / Azure immutability policy |
| Lake tiering | Same | Azure: cool at 30 d, cold at 90 d, archive at 400 d; AWS: Standard-IA at 30 d, Glacier Instant Retrieval at 180 d | Lifecycle rules |
| Lake end of life | Same | `lake_expire_days`, or per class `lake_expire_days_by_class`; 0 = keep | Lifecycle rule per class; never earlier than WORM (validated) |
| Azure Data Explorer (medium and large tiers) | Hot copy for fast hunting | Hot cache 31 days, retention 400 days | Table policies |
| Operational store | Alerts, cases, approvals, agent runs, audit chain | Kept | PostgreSQL with 35-day backups |
| Processed-batch ledger, finished work | Bookkeeping | 120 and 30 days (`store.ledger_days`, `store.work_days`) | Daily housekeeping in the scheduler |
| Platform logs | MERIDIAN's own logs | 30 days | CloudWatch Logs / Log Analytics (with a daily cap) |

### Example policy

```
lake_retention_days       = 400                 # WORM minimum: every log for 13 months
lake_expire_days          = 400                 # default end of life
lake_expire_days_by_class = {
  "3002" = 2555                                 # authentication: 7 years
  "3001" = 2555                                 # account changes: 7 years
  "6003" = 2555                                 # cloud and API audit: 7 years
  "4001" = 400                                  # network flows: 13 months
}
```

This example meets, for instance, PCI DSS v4.0 requirement 10.5.1: at least 12 months of audit log history, with the latest three months immediately available. MERIDIAN keeps all of it queryable. Set the figures from your own regulatory and legal register; MERIDIAN only enforces them.

:::box red Decisions that are hard to undo
- **COMPLIANCE-mode Object Lock** (AWS) and a **locked immutability policy** (Azure) cannot be shortened by anyone for the retention period. Take legal advice first. GOVERNANCE mode and unlocked policies are the defaults.
- **Shortening the end of life** deletes data at the next lifecycle run. Treat a change to `lake_expire_days*` as a change to a records-retention policy, with approval.
:::

### Rotation of everything else

- **Keys.** The KMS key (AWS) and Key Vault keys rotate automatically.
- **Secrets.** Ingest secrets, source tokens and pull credentials are rotated by writing a new value and restarting the receiving role. A token is bound to one source, so rotating one sender does not affect the others.
- **Syslog certificates.** Issue from your internal CA with a lifetime you can renew automatically. With mutual TLS, revoke a collector by removing its certificate from the trusted CA bundle.
- **Batches.** Landing and lake objects are written once and never modified, so there is nothing to rotate in place.

## 8 Sizing

{: .teal }
| Measure | Value | How it was obtained |
| --- | --- | --- |
| Mapper throughput (one core) | Windows/Sysmon about 40,000 events/s; syslog with patterns about 43,000; CEF about 14,000 | Measured in the build sandbox, mapper only |
| Worker throughput, end to end (one process) | About 9,600 events/s: map, enrich, de-duplicate, write Parquet, evaluate 30 streaming rules | Measured on 100,000 Sysmon events in the build sandbox |
| 200 GB/day at about 500 bytes per event | About 4,600 events/s on average | Arithmetic |
| Worker replicas | AWS: 2 to 20 on queue depth; Azure: 1 to 10 (KEDA rule on the landing queue) | Terraform defaults |
| Syslog receiver | 2 tasks (AWS) or 2–4 replicas (Azure); one receiver per source key | Terraform defaults |

The sandbox figures are a floor, not a promise: measure your own mix during the shadow run (AZ-00 / AWS-00 stage S6). Raise `max_events_per_batch` only if producers cannot split batches.

## 9 Operations

!fig images/flow-log-pull-light.svg 9.1 The API collector: the cursor advances only after the data is in the landing zone.

### Signals

{: .teal }
| Metric | Alert when | Meaning |
| --- | --- | --- |
| `meridian_source_last_batch_age_seconds{source}` | Greater than the source's normal interval × 3, or −1 | Silent source (PCI DSS 10.7: failure of a critical control) |
| `meridian_ingest_rejected_24h` / `meridian_ingest_events_24h` | Reject ratio above 1%, or rising | Format change at the sender, or a wrong `format` / `timezone` |
| `meridian_pull_last_run_ok{source}` | 0 for two intervals | API credentials expired, throttling, API change |
| Dead-letter queue / poison queue depth | Greater than 0 | A batch that cannot be processed |
| `meridian_work_items{kind="triage",status="queued"}` | Growing for 30 minutes | Detection backlog, not ingestion |
| `meridian_heartbeat_age_seconds{role="collector"}` | Greater than 300 | Collector stopped |

### Troubleshooting

{: .amber }
| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Events land hours in the future or past | Naive local time without `timezone`, or a device clock problem | Set `timezone` on the source; fix NTP at the sender |
| Everything from a syslog source is class 0 | The device's message format has no pattern | Add `patterns` (regex with named groups that are column names), then `meridian replay --prefix <source>/` |
| Windows events from Fluent Bit are class 0 or missing fields | `Event_Data_As_Map` not set | Set it; replay |
| TLS handshake fails | Client certificate not from the configured CA, or SAN mismatch on the server certificate | Check `--tls-client-ca` and the certificate chain |
| HTTPS push returns 401 | Wrong token for that source, or HMAC clock skew over 5 minutes | Each token is bound to one source; fix NTP |
| HTTPS push returns 413 | Over 10 MB per request or over 64 MB decompressed | Reduce the shipper's batch size |
| API pull stuck | 429 or 5xx from the API, or a cursor in the past beyond the API's limit | Check the logs; `meridian pull --source <key> --reset` re-reads from `start_minutes` |
| Duplicates after an API retry | Inclusive `since` at the boundary | Same `event_uid`; de-duplicated at query time |

## 10 Onboarding a source

{: .teal }
| Step | Action | Done when |
| --- | --- | --- |
| O1 | Choose the path (section 3) and the source key. Record the owner and the expected daily volume | Entry in the source register |
| O2 | Take a sample, run `meridian map-test`, add `patterns` / `field_map` / `timezone` until the important columns are populated | Output filed; rejects 0 |
| O3 | Add the source to the configuration (`sources:`); create its token, writer policy or pull secret | Deployed |
| O4 | Turn on the sender; confirm `meridian_source_last_batch_age_seconds` is fresh and rejects stay below 1% | 24 hours clean |
| O5 | Check that the rules relying on it fire on a test event (for example a failed logon or `certutil -urlcache` in a lab) | Alert seen |
| O6 | Add the source to silent-source alerting and to the LODESTAR coverage list | Done |

## 11 Security of the ingestion tier

{: .red }
| Threat | Control |
| --- | --- |
| Spoofed or injected log data | Private network paths only; TLS with client certificates for syslog; HMAC or a source-bound token for push; IAM limited to one prefix for object storage. Telemetry is labelled untrusted for agents |
| One sender writing as another source | Tokens, writer policies and HMAC secrets are each scoped to a single source |
| Oversized or malicious bodies | Request and decompression caps (zip bombs → 413); 64 KB per syslog line; Windows XML with DTDs or entities is refused; one bad record never blocks a batch |
| Credential exposure | Secrets only in Key Vault / Secrets Manager; configuration refuses literal secrets; syslog keys held in memory |
| Tampering with stored logs | Landing immutable by convention and expiry only; lake under WORM; lake writer is the ingestion identity only, and the agents' identity has read access |
| Loss during outages | Source buffers, relay disk queues, receiver retry buffer, queue redelivery with a dead-letter queue, 90-day replayable landing |

## 12 Limits and open items

{: .amber }
| Item | Position |
| --- | --- |
| UDP on Azure | Container Apps has no UDP ingress. Use a site relay or a VM-based receiver |
| Kafka | No native consumer. Bridge with Vector, Fluent Bit or Cribl to object storage or push |
| Dedicated mappers | Nine formats at release. Other products use `json` field maps, `ocsf` or `patterns`; dedicated mappers for high-volume sources are Phase 2 of the adoption plan |
| Fluent Bit positional inserts | Not mapped; `Event_Data_As_Map` is required |
| HEC acknowledgement | Not offered |
| Cross-batch duplicates | Kept, with the same `event_uid`; removed at query time |
| Lake compaction | Small files from low-volume sources raise query cost; compaction is Phase 1 work (EXECUTIVE_REVIEW §5) |

### Sources for the external claims in this document

{: .sources }
| Source | What it establishes | Reference |
| --- | --- | --- |
| Azure Monitor Agent: send data to Event Hubs and Storage | Preview; no new rules from February 2026; stops after 31 July 2026; Azure VMs only | learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-send-data-to-event-hubs-and-storage |
| NSG flow logs overview | NSG flow logs retire 30 September 2027; no new ones; migrate to VNet flow logs | learn.microsoft.com/azure/network-watcher/nsg-flow-logs-overview |
| Azure Container Apps ingress | HTTP and TCP ingress; no inbound UDP | learn.microsoft.com/azure/container-apps/ingress-how-to |
| Office 365 Management Activity API | Subscription start; content listing with NextPageUri; 24-hour windows within 7 days; content types | learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-reference |
| Fluent Bit winevtlog input | `event_data_as_map`, `string_inserts`, `render_event_as_xml` | docs.fluentbit.io/manual/data-pipeline/inputs/windows-event-log-winevtlog |
| NXLog Community Edition reference | `im_msvistalog`, `om_ssl`, `om_tcp`, `xm_json`, `xm_syslog` in CE; no `om_http` | docs.nxlog.co/ce/current |
| NXLog Agent om_http | HTTP(S) output with `AddHeader`, gzip, `ndjson` / `jsonarray` batching | docs.nxlog.co/agent/current/om/http.html |
| Winlogbeat outputs | Elasticsearch, Logstash, Kafka, Redis, file, console | elastic.co/docs/reference/beats/winlogbeat |
| PCI DSS v4.0 | 10.5.1: 12 months of audit history, 3 months immediately available | pcisecuritystandards.org |
| MERIDIAN repository | Every MERIDIAN behaviour stated here, with tests | meridian/ingest, meridian/mappers, tests/test_ingestion.py (v{{VERSION}}) |
