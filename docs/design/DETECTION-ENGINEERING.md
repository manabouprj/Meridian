# Detection engineering guide

Detections are YAML files in `config/rules/` (any folder listed in `detections.paths`). They use Sigma syntax, plus a small `meridian:` extension block.

## 1. Rule lifecycle

1. **Write** the rule in a branch: one `---`-separated document per rule, with a unique `id` (`mer-<area>-<name>`).
2. **Validate** with `meridian rules --check`, which fails on any parse error or unsupported construct.
3. **Test.** Add sample events to a unit test (see `tests/test_detection.py`) covering at least one true positive and one near-miss. Run `pytest -q`.
4. **Replay** against recent data in non-production: `meridian replay --prefix <source>/<yyyy>/<mm>/<dd>`, then review the alert volume.
5. **Promote** through a pull request (reviewed by a second detection engineer), then deploy. The workers load rules at start-up, so restart the worker and scheduler roles.
6. **Tune** with `meridian tune --rule <id>`. The tune agent proposes a filter and an expected noise reduction; a human applies it in a pull request.

## 2. Streaming rule anatomy

```yaml
title: Encoded PowerShell command line
id: mer-ep-encoded-powershell
status: stable                       # experimental | test | stable
level: high                          # informational=1 low=2 medium=3 high=4 critical=5 (alert severity)
description: PowerShell launched with an encoded command.
tags: [attack.execution, attack.t1059.001]   # MITRE ATT&CK tags become the alert's mitre list
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    Image|endswith: ['\powershell.exe', '\pwsh.exe']
  selection_cli:
    CommandLine|contains: [' -enc ', ' -encodedcommand ']
  condition: selection_img and selection_cli
falsepositives: [Software deployment tools]
meridian: {entity: device, suppress_minutes: 60}   # alert grouping field and de-duplication window
```

**Severity matters.** Auto-close is only possible for rules at `low` or `informational` level (severity <= 2 by default). Set the level by impact, not by expected volume.

## 3. Correlation rule anatomy

```yaml
title: Password spray from one source
id: mer-cor-password-spray
level: high
logsource: {category: authentication}
correlation:
  type: value_count                  # event_count | value_count
  group-by: [src_ip]
  timespan: 30m
  condition: {gte: 15, field: user}  # value_count needs `field`
meridian:
  entity: src_ip
  suppress_minutes: 60
  query: {classes: [3002], where: [{field: status, op: eq, value: Failure}]}   # base events (QuerySpec)
```

Correlations run on the lake every `correlation_interval_minutes`. Keep `query.classes` and `where` as narrow as possible, because they drive query cost (Athena bills per TB scanned).

## 4. Support matrix

### Log sources (`logsource.category`) to OCSF classes

| Category | OCSF classes |
| --- | --- |
| process_creation | 1007 |
| file_event, file_delete, file_rename | 1001 |
| network_connection | 4001, 4002 |
| firewall | 4001 |
| proxy, webserver | 4002 |
| dns, dns_query | 4003 |
| authentication, signinlogs | 3002 |
| auditlogs | 3001, 3005, 6003 |
| cloudtrail | 6003, 3002 |
| detection | 2004 |
| email | 4009 (no mapper yet) |
| any | all |

### Sigma field names to MERIDIAN columns

| Sigma field | Column |
| --- | --- |
| Image, OriginalFileName | process_name |
| CommandLine | process_cmdline |
| ParentImage | parent_process_name |
| TargetFilename | file_path |
| Hashes, sha256 | file_sha256 |
| DestinationIp / DestinationPort / DestinationHostname | dst_ip / dst_port / dst_domain |
| SourceIp, IpAddress / SourcePort | src_ip / src_port |
| QueryName | dns_query |
| User, TargetUserName, UserPrincipalName | user |
| Computer, ComputerName | device |
| c-uri / cs-host / cs-method | url / dst_domain / http_method |
| eventName, OperationName, operationName | api_operation |
| eventSource, AppDisplayName | app_name |
| awsRegion | cloud_region |
| Action | action |

You can also use any MERIDIAN column name directly (see [DATA-MODEL.md](DATA-MODEL.md)).

### Modifiers and conditions

* **Modifiers:** `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `gt`, `gte`, `lt`, `lte`, `exists`.
* **Wildcards:** `*` and `?`.
* **Conditions:** `and`, `or`, `not`, `1 of <pattern>`, `all of <pattern>`, and parentheses.
* **Rejected with an error** (never silently ignored): `windash`, `base64`, `base64offset`, and any unmapped field.

## 5. Importing community rules (SigmaHQ)

1. Copy candidate rules into a staging folder and run `meridian rules --check` with that folder added to `detections.paths`.
2. Rules that fail on unmapped fields need either a field-map addition (when the data exists in the schema) or a new column (a schema change: see COMPONENT-DESIGN §2).
3. Measure the import yield, and prioritise by ATT&CK coverage gaps and by last year's SIEM true positives (the executive review, Phase 2).

## 6. Quality bar for promotion

| Check | Target |
| --- | --- |
| Parses and loads | 100% (`rules --check`) |
| Unit test with a true positive and a near-miss | Required |
| Alert volume on 7 days of replayed data | Agreed with the SOC lead; at most about 5% of rules produce 80% of alerts |
| ATT&CK tag | Required |
| Documented false positives | Required |
| Owner | A named detection engineer (in the pull request) |
