# Troubleshooting

Start with three commands. They answer most questions:

```bash
meridian doctor                  # configuration, store, lake, queue, model, context
curl -s https://<host>/readyz    # readiness, rules, heartbeats, placeholder secrets
curl -s -H "Authorization: Bearer $METRICS_TOKEN" https://<host>/metrics | grep -E "heartbeat|source_last|work_items|approvals"
```

## Platform

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `/readyz` returns 503 with `placeholder_secrets` | A vault secret still holds `set-me` / `change-me` | Set it (DEPLOY-* step 5/6) and restart the roles |
| `/readyz` returns 503 with `store` | Database unreachable or wrong URL | Check the private DNS zone / security group, `MERIDIAN_DATABASE_URL` (Azure) or `MERIDIAN_DB_HOST` + the Aurora secret (AWS) |
| ECS tasks stop at once with `ResourceInitializationError` | A referenced secret has no value, or the execution role cannot read it | Put the secret value; check the `<prefix>-ecs-exec` role and the KMS key policy |
| Container App revision fails to provision | Key Vault reference denied or ACR pull denied | Check the identity's Key Vault Secrets User and AcrPull role assignments; wait for RBAC propagation (up to 10 minutes) |
| `ConfigError: Literal secret at ...` | A secret value typed into YAML | Replace it with `${ENV_VAR}` and put the value in the vault |
| Two schedulers both logging cycles | Old version without the leader lock, or the clocks differ greatly | Upgrade; check NTP; inspect the `lock:scheduler` cursor in the `cursors` table |
| Heartbeat age keeps growing for one role | Role crashed or is blocked | Check that role's logs; restart; for agents, check model endpoint latency |

## Ingestion

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Landing files arrive but no events | No source matches the prefix (`no source configured`), or the mapper rejects records | Check `processed_batches` (errors = 1); add or fix the source `prefix` / `format`; then `meridian replay --prefix ...` |
| Messages in the DLQ / poison queue | A batch fails repeatedly (bad format, permissions) | Look up the key in the worker logs; fix; replay the prefix; delete the parked message |
| Event Hubs Capture produces no blobs | Diagnostic setting or streaming API not sending; Capture disabled | Check incoming messages in the namespace metrics; confirm the hub names `mde` / `entra` / `azure-activity` |
| CloudTrail objects missing | Bucket or KMS policy does not allow the trail's account | Set `cloudtrail_account_ids` and re-apply; check `aws cloudtrail get-trail-status` |
| Syslog events missing | Firewall cannot reach the port; UDP dropped; wrong source key | Test with `logger -n <ip> -P 5514 -T "CEF:0|test|test|1|1|test|5|src=203.0.113.9"`; prefer TCP; check `syslog_cidrs` / the NSG |
| `401 invalid signature or stale timestamp` on push | Wrong secret, clock skew > 300 s, or body changed after signing | Sync the clock; sign the exact bytes sent; check that the per-source secret name matches the key |
| Events in the wrong hour or day | Fixed in 1.0 (all timestamps normalised to UTC) | Replay the affected prefixes after upgrading |

## Detection and agents

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Rule never fires | Field not populated by the mapper, logsource maps to another class, or the rule is disabled | `meridian query` for the class and field; check `detections.disabled`; add a unit test |
| Correlations late after an outage | Expected: catch-up evaluates missed windows (up to 24 h) | Watch the next cycles; beyond 24 h, replay or run a hunt |
| All runs show `(degraded)` | Daily budget reached, or model errors | `/api/runs` errors; Foundry / Bedrock quota and access; `model.pricing` set correctly; raise the budget only with approval |
| `AccessDeniedException` from Bedrock | Model access not granted, ARN missing from `bedrock_model_arns` (include inference-profile destinations), or wrong region | Bedrock console Model access; fix the ARNs and re-apply |
| Foundry `401/403` | Identity lacks Azure AI User on the Foundry account, or the wrong resource name | Check the role assignment and `FOUNDRY_RESOURCE`; local auth is disabled by design |
| Alerts never auto-close | By design for severity > 2, crown jewels, confidence < 0.8 or degraded runs | Review the `agents.policy` settings |
| Slow hunts / high Athena cost | Wide time windows, no class filter, many small files | Narrow the queries; schedule compaction (Phase 1); consider ADX on Azure |

## Response

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `403 the requester cannot approve` | Four-eyes: the same person requested and approved | Another responder approves |
| `409 approval is expired` | TTL passed (default 24 h) | Ask the agent or an analyst to request again; consider a shorter on-call response time |
| Action `failed` with 403 from Defender or Graph | Missing application permission (Machine.Isolate, User.RevokeSessions.All, User.EnableDisableAccount.All) or no admin consent | Grant the permission and consent; retest in dry run, then live |
| AWS action `AccessDenied` | Target not tagged `meridian-containable=true`, or a cross-account role is missing | Tag the resource; configure `role_arn` |
| Firewall does not block an EDL entry | Firewall not pulling, or the token is wrong | Fetch `/edl/ip.txt` with the token from the firewall's network; check the firewall's EDL refresh interval |
