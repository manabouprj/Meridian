# Upgrade, rollback and disaster recovery

## 1. Release process

1. **Read the release notes,** in particular any line that says "schema" or "config".
2. **Run CI** on the release tag:
   * tests on SQLite and PostgreSQL, ruff, rules check;
   * Terraform `validate` / `test`;
   * the image build and its vulnerability scan.
3. **Stage it.** Deploy to non-production, then run:
   * `doctor`;
   * `eval` (the shipped set and your own labelled alerts);
   * `replay` of one day of data;
   * a dry-run approval.
4. **Roll out in production** in this order. Ingestion is idempotent, so workers of different versions can overlap safely.

| Step | Role | Azure | AWS |
| --- | --- | --- | --- |
| 1 | Scheduler (pause) | `az containerapp update ... --min-replicas 0 --max-replicas 0` | `aws ecs update-service --desired-count 0` |
| 2 | Worker | New image | New image |
| 3 | Agents | New image | New image |
| 4 | API | New image (2 replicas: rolling) | New image (rolling, ALB health on `/readyz`) |
| 5 | Scheduler (resume) | New image, replicas 1 | New image, desired count 1 |

   * **Azure:** `az containerapp update -g rg-<prefix> -n ca-<prefix>-<role> --image <acr>.azurecr.io/meridian:<new>`, or change `image` in tfvars and `terraform apply`.
   * **AWS:** change `image` in tfvars and run `terraform apply`. This creates new task definition revisions and the services roll.

5. **Verify** after the rollout:
   * `/readyz` is ready and heartbeats are fresh;
   * no new entries in the dead-letter or poison queue;
   * the next correlation cycle completes;
   * `verify-audit` is valid.

## 2. Schema changes

1.0 creates tables at start-up when they are missing. New releases follow these rules:

* **Additive changes** (new tables or nullable columns) apply automatically.
* **Destructive or type changes** ship with a migration script and must be run before step 2 above. A migration tool (Alembic) is planned before the first such change.
* **Always back up first:**
  * Azure: on-demand backup (PITR covers 35 days);
  * AWS: `aws rds create-db-cluster-snapshot --db-cluster-identifier <prefix>-db --db-cluster-snapshot-identifier pre-upgrade-<date>`.

## 3. Rollback

| Situation | Action |
| --- | --- |
| New version unhealthy (no schema change) | Redeploy the previous image tag with the same commands. Batches that failed under the new version are retried from the queue |
| Bad rule or mapper produced wrong alerts | Revert the change, redeploy, then `meridian replay --prefix <affected prefix>`; close the false alerts in bulk through the API |
| Model or prompt regression | Revert `model.*` or the prompt release; `eval` must pass before re-enabling auto-close |
| Schema migration failed | Restore the pre-upgrade snapshot (PITR) to a new server, repoint the database URL, redeploy the previous image |

## 4. Disaster recovery

* **Targets:** RPO 0 for the lake (immutable, replicated storage), RPO < 5 minutes for the store, RTO about 4 hours for a full region loss.
* **Annual drill:** restore the store to a new server, deploy the stack into a second resource group or account with Terraform, and run `doctor` and `verify-audit`. Record the timings.

| Failure | Azure | AWS |
| --- | --- | --- |
| Single zone | Automatic: ZRS storage, zone-redundant PostgreSQL HA and Container Apps | Automatic: S3, multi-AZ Aurora, ECS across 3 AZs |
| Database corruption / logical error | PITR to a point before the error; repoint | PITR or snapshot restore; repoint |
| Region loss | Restore the geo-redundant backup in the paired region; `terraform apply` with the new `location` and a replicated or new storage account; repoint exports (diagnostic settings, Defender streaming) | Restore the snapshot copy (or Aurora Global Database); `terraform apply` in the DR region; enable Cross-Region Replication of the lake ahead of time; repoint CloudTrail |
| Accidental resource deletion | Key Vault soft delete + purge protection; storage soft delete; Terraform re-apply | Aurora deletion protection; S3 versioning + Object Lock; Terraform re-apply |
| Lost secrets | Key Vault soft delete (90 days) | Secrets Manager recovery window |
