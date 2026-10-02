# MERIDIAN roadmap

The phases come from the executive review (section 4); each item is a GitHub issue in the matching milestone.
`docs/roadmap/issues.json` is the source; `scripts/create_roadmap_issues.ps1` creates the labels, milestones and
issues with the GitHub CLI and skips any issue that already exists, so it is safe to run again.

```powershell
winget install --id GitHub.cli        # once
gh auth login                         # once, as the repository owner
.\scripts\create_roadmap_issues.ps1 -Repo manabouprj/Meridian
```

| Phase | Item | Area | Done when | Reference |
| --- | --- | --- | --- | --- |
| 0 | First live deployment on Azure (non-production) | infra | `scripts/verify_deployment.py azure` reports no FAIL; output filed | AZ-00 §7-8 |
| 0 | First live deployment on AWS (non-production) | infra | `scripts/verify_deployment.py aws` reports no FAIL; output filed | AWS-00 §7-8 |
| 0 | Residency decision for AI inference signed by the DPO | compliance | Signed decision recorded; Terraform model settings match it | AZ-00 / AWS-00 §6 |
| 0 | Pin the base image digest and turn on Dependabot alerts and security updates | security | Dockerfile pinned by digest; first Dependabot PRs reviewed | CHANGELOG 1.0.1 |
| 0 | Alarms as code | infra | Alarms deployed by Terraform; each fired once in a test | OPERATIONS §4; LOG-00 §9 |
| 0 | Drilled disaster-recovery exercise | infra | Restore and replay timed and documented | UPGRADE-ROLLBACK |
| 0 | Choose and add a licence | repo | LICENSE file committed | Repository review, October 2026 |
| 1 | Onboard Windows and Active Directory through Event Forwarding and NXLog | ingestion | `map-test` evidence filed; rejects < 1%; failed-logon and certutil tests raise alerts | LOG-00 §5, §10 |
| 1 | Onboard Linux, network and OT syslog through site relays | ingestion | Sources fresh for 2 weeks; patterns cover the agreed messages | LOG-00 §4.3 |
| 1 | Onboard Microsoft 365 audit and Okta through the API collector | ingestion | Field maps reviewed; `meridian_pull_last_run_ok` = 1 for 2 weeks | LOG-00 §4.5 |
| 1 | E-mail security mapper | ingestion | Mapper with tests on real samples; phishing rules use it | EXECUTIVE_REVIEW §3.1 |
| 1 | Lake compaction and narrower agent query windows | infra | As-built query cost within the cost model (EXECUTIVE_REVIEW §5) | EXECUTIVE_REVIEW §3.3, §5 |
| 1 | Schema migrations for the operational store | infra | Upgrade and rollback tested on PostgreSQL | EXECUTIVE_REVIEW §3.1 |
| 2 | Port the top SIEM rules by true-positive value | detection | >= 95% of last year's SIEM true positives reproduced | EXECUTIVE_REVIEW §4 |
| 2 | Lateral-movement detections | detection | Rules with tests; fired in the attack-simulation harness | EXECUTIVE_REVIEW §3.1 |
| 2 | Attack-simulation test harness | detection | Harness in CI or a scheduled lab run with a coverage report | EXECUTIVE_REVIEW §4 |
| 2 | Report ATT&CK coverage to LODESTAR | integration | KPI shown as measured in LODESTAR | INT-00 §10 |
| 3 | Golden set of 500+ labelled alerts and weekly evaluation | ai | >= 90% analyst agreement for 4 weeks | EXECUTIVE_REVIEW §3.1 |
| 3 | Drift monitoring and sampled review of auto-closures | ai | No missed incident in sampled auto-closures over a quarter | EXECUTIVE_REVIEW §4 |
| 4 | Analyst search and dashboards | ux | Analysts complete a month of hunts without the SIEM | EXECUTIVE_REVIEW §3.1 |
| 4 | ServiceNow / Jira integration and case SLAs | integration | Two-way sync tested; SLA report | EXECUTIVE_REVIEW §4 |
| 4 | LODESTAR context back into MERIDIAN and dual-secret rotation | integration | Agents cite LODESTAR priority; rotation without rejected pushes | INT-00 §10 |
| 5 | Compliance coverage reporting and auditor walkthrough | compliance | Pre-audit passed | EXECUTIVE_REVIEW §3.1, §4 |
| 5 | Historical SIEM export and decommission runbook | ingestion | History queryable in MERIDIAN; SIEM retired at renewal | EXECUTIVE_REVIEW §4 |
