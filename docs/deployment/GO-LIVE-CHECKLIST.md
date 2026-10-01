# Go-live checklist

Use this as the gate before analysts rely on MERIDIAN in production, with the SIEM still running. Every item needs evidence: a screenshot, command output or ticket. The SIEM decommission gate is separate and stricter (see EXECUTIVE_REVIEW.md, Phase 5).

## A. Platform

| # | Check | Evidence |
| --- | --- | --- |
| A1 | `/readyz` returns ready, with no `placeholder_secrets` | Command output |
| A2 | `meridian doctor` has no FAIL lines | Output |
| A3 | All roles running at the desired count; heartbeat ages < 120 s | `/metrics` |
| A4 | Exactly one active scheduler (leader lock held) | Scheduler logs; the `lock:scheduler` cursor |
| A5 | Database HA enabled; PITR 35 days; restore tested into a scratch server | Change ticket |
| A6 | Lake WORM policy active with the agreed retention and mode | Portal / `aws s3api get-object-lock-configuration` |
| A7 | Landing lifecycle (90 days) and lake tiering active | Portal / CLI |
| A8 | Alerts configured: dead-letter or poison queue, queue age, readiness, heartbeat, silent source, degraded runs, spend | Monitoring screenshots |
| A9 | Terraform state remote, locked and access-controlled; `deployer_cidrs` cleared (Azure) | Backend configuration |

## B. Security

| # | Check | Evidence |
| --- | --- | --- |
| B1 | Console reachable only from approved networks; TLS certificate valid | Test from an outside network fails |
| B2 | SSO works; unmapped users refused; roles match groups | Test accounts |
| B3 | Four-eyes enforced: the requester cannot approve (console, API and MCP paths) | Test |
| B4 | Interactive API docs disabled (`/docs` returns 404) | curl |
| B5 | API keys and tokens stored in the vault and the PAM tool; rotation date set | Ticket |
| B6 | Model inference residency approved by the DPO; model invocation logging decision recorded | Sign-off |
| B7 | `verify-audit` valid; daily verification scheduled | Output |
| B8 | Penetration test or security review of the console and ingest endpoints completed | Report |

## C. Data and detection

| # | Check | Evidence |
| --- | --- | --- |
| C1 | Every in-scope source delivering; `source_last_batch_age` < 300 s | `/metrics` |
| C2 | Mapping spot-check: 20 random events per source reviewed against the raw record | Worksheet |
| C3 | `rules --check` clean; rule volume over 7 days reviewed with the SOC lead | Output and report |
| C4 | Test detections fired for each source (lab or attack simulation) | Alert ids |
| C5 | CMDB and identity context loaded; crown jewels identified | `doctor` counts |

## D. AI and response

| # | Check | Evidence |
| --- | --- | --- |
| D1 | `meridian eval` >= 0.8 on the shipped set **and** on at least 50 of your own labelled alerts | Output |
| D2 | Auto-close policy set: confidence >= 0.8, max severity 2, crown jewels excluded (or auto-close disabled for the first weeks) | Config review |
| D3 | Daily and per-run budgets set from the cost model; spend alert at 80% | Config |
| D4 | Degraded mode tested (budget set to 0 in staging): triage continues and nothing auto-closes | Test |
| D5 | Every enabled response action tested in dry run; live actions enabled one at a time after a tabletop exercise | Tickets |
| D6 | Teams / Slack approval notifications received by the on-call responder | Screenshot |

## E. People and process

| # | Check | Evidence |
| --- | --- | --- |
| E1 | Named platform owner and detection-engineering owner | RACI |
| E2 | SOC trained on the console, case workflow and approvals | Attendance |
| E3 | Runbooks (OPERATIONS.md) linked from the on-call tool | Link |
| E4 | Weekly sampling of 50 auto-closed alerts assigned | Calendar or ticket |
| E5 | Change process for rules, prompts and models agreed (pull request + CI + `eval`) | Process document |

**Sign-off:** Platform owner, SOC lead, CISO delegate. Date.
