# MERIDIAN deployment documentation

These are step-by-step runbooks for deploying, onboarding, validating, operating and upgrading MERIDIAN. Every step ends with a **Verify** check. Do not move on until the check passes.

## Choose your path

| Situation | Runbook | Time |
| --- | --- | --- |
| Evaluate on a laptop with fictional data | [DEPLOY-LOCAL.md](DEPLOY-LOCAL.md), section 1 | 10 minutes |
| Single-host pilot on your own data (Docker) | [DEPLOY-LOCAL.md](DEPLOY-LOCAL.md), section 2 | Half a day |
| Production on Microsoft Azure + Microsoft Foundry | [DEPLOY-AZURE.md](DEPLOY-AZURE.md) | 2-3 days, plus approvals |
| Production on AWS + Amazon Bedrock | [DEPLOY-AWS.md](DEPLOY-AWS.md) | 2-3 days, plus approvals |

## Then, in order

1. [PREREQUISITES.md](PREREQUISITES.md): accounts, permissions, tools, identity and network decisions. Read this first.
2. The cloud runbook for your platform.
3. [ONBOARD-SOURCES.md](ONBOARD-SOURCES.md): connect Defender, Entra, CloudTrail, firewalls, proxies and SaaS sources.
4. [GO-LIVE-CHECKLIST.md](GO-LIVE-CHECKLIST.md): the gate before analysts rely on MERIDIAN.
5. [UPGRADE-ROLLBACK.md](UPGRADE-ROLLBACK.md): releases, rollback and disaster recovery.
6. [TROUBLESHOOTING.md](TROUBLESHOOTING.md): symptoms, causes and fixes.
7. Onboard sources by path and preview their normalisation with [LOG-00](../pdf/MERIDIAN-LOG-00-Log-Ingestion-Normalisation-Retention.pdf) (source [../ingestion](../ingestion/MERIDIAN-LOG-00.md)).
8. Optional: connect LODESTAR with [INT-00](../pdf/MERIDIAN-LODESTAR-INT-00-Integration-Design-and-Deployment.pdf) (steps I0-I6; source [../integration](../integration/MERIDIAN-LODESTAR-INT-00.md)).

The build documents [AZ-00](../pdf/MERIDIAN-AZ-00-Foundry-Design-and-Deployment.pdf) and [AWS-00](../pdf/MERIDIAN-AWS-00-Bedrock-Design-and-Deployment.pdf) give the same procedure as stages S0-S7, with the residency position, the go-live gate and the agent constitutions in one place.

Day-2 operations (alerts, runbooks, capacity) are in [../OPERATIONS.md](../OPERATIONS.md). The phased adoption plan and business case are in [../EXECUTIVE_REVIEW.md](../EXECUTIVE_REVIEW.md).

## Conventions in these runbooks

* **Commands are written for bash** (Linux, macOS, WSL, Azure Cloud Shell, AWS CloudShell).
* **On Windows PowerShell,** use the same commands with these changes:
  * replace `\` line continuations with a backtick (`` ` ``), or join the lines;
  * set variables as `$env:NAME = "value"` instead of `export NAME=value`;
  * read Terraform outputs with `terraform output -raw <name>` in both shells.
* **Placeholders** look like `<prefix>`, `<acr>` and `<account-id>`. Replace them; do not type the angle brackets.
* **Secrets are never pasted into files in the repository.** They go into Key Vault or Secrets Manager, or a git-ignored `.env` for local use.
