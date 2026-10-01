# Onboard data sources

Every source follows the same pattern:

1. **Deliver** batches to the landing zone under `<prefix>/`.
2. **Declare** the source in `sources:` with the right `format`.
3. **Verify** that events arrive and map.

The full ingestion design (six paths, Windows and Sysmon, normalisation, retention and rotation, sizing, troubleshooting) is [LOG-00](../pdf/MERIDIAN-LOG-00-Log-Ingestion-Normalisation-Retention.pdf) (source: [../ingestion/MERIDIAN-LOG-00.md](../ingestion/MERIDIAN-LOG-00.md)). Before any source goes live, preview its normalisation on a sample:

```bash
meridian map-test --file sample.jsonl --source <key>        # or --format windows|syslog|cef|leef|... --timezone +04:00
```

Use this query to check that a source's events are in the lake:

```bash
meridian query '{"classes":[<class>],"last_minutes":60,"where":[{"field":"source","op":"eq","value":"<key>"}],"limit":5}'
```

In the cloud, run it with `az containerapp exec` (Azure) or a one-off ECS task (AWS). `/metrics` also shows `meridian_source_last_batch_age_seconds{source="<prefix>"}`, which should stay below your alert threshold (default 300 s).

## Source matrix

| Source | Azure path | AWS path | Format | OCSF classes |
| --- | --- | --- | --- | --- |
| Microsoft Defender XDR | Streaming API to Event Hub `mde` | Event Hub, then relay function to `/api/ingest/mde` | `mde` | 1007, 4001, 1001, 3002, 2004 |
| Entra ID sign-in / audit | Diagnostic settings to Event Hub `entra` | Same, through a relay function | `entra` | 3002, 3001, 3005 |
| Azure Activity log | Subscription diagnostic settings to Event Hub `azure-activity` | n/a | `json` (field map) | 6003 |
| AWS CloudTrail | n/a (or push) | Organisation trail to the landing bucket `AWSLogs/` | `cloudtrail` | 6003, 3002 |
| Amazon Security Lake | n/a | Subscriber copy to `securitylake/` | `ocsf` | as produced |
| Firewalls (Palo Alto, Fortinet, Check Point) | Syslog CEF to a `meridian syslog` listener | Syslog CEF to an NLB in front of the `syslog` service | `cef` | 4001 |
| Web proxy (Zscaler NSS, Netskope) | Syslog CEF | Syslog CEF | `cef` | 4002 |
| DNS (Infoblox, Route 53 resolver) | OCSF producer or push | Security Lake / push | `ocsf` / `json` | 4003 |
| Windows servers and DCs, Sysmon | Event Forwarding to a collector; NXLog CE to the TLS syslog receiver, or Fluent Bit push | Same (syslog through the NLB) | `windows` (via `syslog`) | 3002, 3001, 3005, 1007, 4001, 4003, 1001, 6003 |
| Linux (rsyslog, syslog-ng, journald) | TLS syslog (6514) | Syslog via NLB, or Vector / Fluent Bit to S3 | `syslog` | 3002, 1007, 3001, 0 |
| Network, OT and appliances (CEF, LEEF, plain syslog) | Site relay, then TLS syslog | Syslog via NLB | `syslog` (+ `patterns`) | 4001, 0 |
| Microsoft 365 audit, Okta, GitHub, other SaaS APIs | API collector (`pull:` block) | Same | `json` (field map) | as mapped |
| Existing Splunk HEC senders | `/services/collector` with a source token | Same | per source | as mapped |
| Any SaaS with JSON logs | `/api/ingest/<key>` (HMAC or source token) | Same | `json` | as mapped |

## 1. Microsoft Defender XDR (Azure)

1. In the Microsoft Defender portal, go to Settings > Microsoft Defender XDR > Streaming API > Add.
2. Choose **Forward events to Event Hub**:
   * Event Hub resource ID: `az eventhubs namespace show -g rg-$PREFIX -n $(terraform output -raw eventhub_namespace) --query id -o tsv`;
   * event hub name: `mde`.
3. Select the event types: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `AlertInfo`, `AlertEvidence`. Other tables are ignored by the current mapper.
4. Event Hubs Capture writes Avro to `landing/mde/...` every minute.

**Verify:** after about 5 minutes, `query` for class 1007 with `source = mde` returns rows.

## 2. Entra ID (Azure)

1. In the Entra admin center, go to Monitoring & health > Diagnostic settings > Add diagnostic setting.
2. Select the logs `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `AuditLogs` and `RiskyUsers`.
3. Choose **Stream to an event hub**: the MERIDIAN namespace, event hub `entra`, and policy `RootManageSharedAccessKey` (or a send-only policy you create).

**Verify:** `query` for class 3002 with `source = entra` returns sign-ins within about 10 minutes.

## 3. Azure Activity log (Azure)

```bash
az monitor diagnostic-settings subscription create --name meridian --location $LOCATION \
  --event-hub-auth-rule "$(az eventhubs namespace authorization-rule show -g rg-$PREFIX \
     --namespace-name $(terraform output -raw eventhub_namespace) -n RootManageSharedAccessKey --query id -o tsv)" \
  --event-hub-name azure-activity \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true}]'
```

Repeat for each subscription you monitor. The source entry in `config/examples/azure.yaml` maps these records to API Activity (6003).

## 4. AWS CloudTrail (AWS)

**New organisation trail.** Run from the management account (or the delegated administrator):

```bash
aws cloudtrail create-trail --name meridian-org --s3-bucket-name $(terraform output -raw landing_bucket) \
  --is-organization-trail --is-multi-region-trail --kms-key-id $(terraform output -raw kms_key_arn)
aws cloudtrail start-logging --name meridian-org
```

Set `cloudtrail_account_ids` to the management account ID in `terraform.tfvars` before applying, so that the bucket and key policies allow delivery.

**Existing trail in a log-archive bucket.** Add an S3 replication rule from that bucket to the landing bucket, keeping the `AWSLogs/` prefix. Do not create a second trail.

**Verify:** within about 15 minutes, `query` for class 6003 with `source = cloudtrail` returns API calls, and the DLQ stays empty.

## 5. Firewalls and proxies (CEF over syslog)

**Endpoint.**

* **AWS:** the NLB in front of the `syslog` ECS service (TCP and UDP 5514). Allow the source IPs in `syslog_cidrs`.
* **Azure:** run `meridian syslog --source firewall --port 5514` on a small VM or Container Instance in the VNet. One listener per source key, or separate ports.
* **Pilot:** the `syslog` service in Docker Compose.

Prefer TCP: it is reliable and supports RFC 6587 octet counting.

| Vendor | Configuration |
| --- | --- |
| Fortinet FortiGate | `config log syslogd setting` / `set status enable` / `set server <ip>` / `set port 5514` / `set mode reliable` / `set format cef` / `end` |
| Check Point | `cp_log_export add name meridian target-server <ip> target-port 5514 protocol tcp format cef`, then `cp_log_export restart name meridian` |
| Palo Alto Networks | Device > Server Profiles > Syslog (TCP 5514, IETF), with a custom log format using Palo Alto's published CEF format strings for Traffic and Threat logs; attach it to a Log Forwarding profile |
| Zscaler NSS (proxy) | Add an NSS feed: SIEM type Other, TCP to the listener, feed output type CEF |

**Verify:**

* `query` for class 4001 (firewall) or 4002 (proxy) returns events;
* the network rules fire on known test traffic, for example inbound RDP from a public test IP in a lab.

## 6. Any JSON source (signed push)

1. Declare the source with a field map:

   ```yaml
   - key: saas_audit
     format: json
     settings: {class_uid: 6003, field_map: {time: ts, user: actor.email, api_operation: action, src_ip: ip, resource: target.id}}
   ```

2. Give the sender a per-source secret, `MERIDIAN_INGEST_SECRET_SAAS_AUDIT`, stored as a Key Vault / Secrets Manager secret mapped to that environment variable.
3. Push signed requests. `scripts/push_events.py` is the reference client. Log shippers that cannot sign (Fluent Bit, Vector, NXLog Agent, Logstash, Cribl) use a source token instead: add `<key>:<token of 32+ characters>` to the `ingest-tokens` secret and send `Authorization: Bearer <token>` (LOG-00 §4.4). SaaS webhooks that sign with their own scheme still need a small relay (Azure Function or Lambda) that verifies the vendor's signature.

**Verify:** `python scripts/push_events.py --url https://<public-url> --source saas_audit --file sample.json` returns `202`, and the events can be queried.

## 7. Context: CMDB, identities and threat intel

| File | Refresh | Notes |
| --- | --- | --- |
| `assets.csv` | Daily (pipeline export from the CMDB) | Criticality 5 or the `crown_jewel` tag marks crown jewels; these always reach a human |
| `identities.csv` | Daily (HR / IdP export) | `privileged = true` drives the `privileged_user` tag |
| `intel/*.csv`, `*.json` (STIX 2.1), `*.txt` | As feeds update | Indicators of type ip, domain (parent domains match), url, sha256 and md5 |

Context is loaded at start-up. After a refresh, restart the worker and agents roles. Live reload is planned.

**Verify:** `meridian doctor` reports the asset, identity and indicator counts.

## 8. Windows, Linux, network devices and SaaS APIs

These paths are designed in [LOG-00](../ingestion/MERIDIAN-LOG-00.md); this section is the checklist.

* **Windows (domain):** Group Policy for the advanced audit policy and command-line process auditing (LOG-00 §5); a Windows Event Forwarding subscription to two collectors; NXLog CE on each collector (`im_msvistalog` on `ForwardedEvents`, `to_json()`, `om_ssl` to the syslog receiver on 6514 with a client certificate). Declare `{key: syslog, format: syslog, settings: {timezone: <collector time zone>}}`. **Verify:** a test failed logon appears as class 3002 with `status = Failure` within a minute.
* **Sysmon:** deploy with a maintained configuration and include its channel in the subscription. **Verify:** `certutil -urlcache` on a lab host raises `mer-ep-lolbin-download`.
* **Linux:** rsyslog or syslog-ng with TLS and a disk queue (LOG-00 §4.3). **Verify:** a failed SSH login appears as class 3002.
* **Network and OT devices:** UDP to a site relay; relay to MERIDIAN over TLS. Add `patterns` for the messages you want typed, replay, and confirm with `map-test`.
* **TLS syslog receiver:** AWS: an NLB TLS listener with an ACM certificate in front of TCP 5514, or `--tls-port 6514`. Azure: `syslog_receiver = true` after putting the PEM certificate and key into Key Vault (`syslog-tls-cert`, `syslog-tls-key`).
* **SaaS APIs:** add a `pull:` block to the source, create the credential with `extra_secrets` in Terraform, and run `meridian pull --source <key>` once to test. **Verify:** `meridian_pull_last_run_ok{source="<key>"} 1`.
