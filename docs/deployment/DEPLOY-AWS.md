# Deploy on AWS + Amazon Bedrock

Target architecture: [../LLD-aws.md](../LLD-aws.md). Complete [PREREQUISITES.md](PREREQUISITES.md) first.

**Elapsed time:** about 1 day of hands-on work, plus approvals and the export configuration. Each step ends with a **Verify** check.

## Step 0: set variables

```bash
export AWS_REGION=me-central-1              # data residency region (lake, database, compute)
export BEDROCK_REGION=me-central-1          # region where your Claude models / inference profiles are enabled
export PREFIX=meridian
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR=$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
```

**Verify:** `aws sts get-caller-identity` shows the security-tooling account.

## Step 1: Bedrock model access

1. In the Bedrock console (Model access), enable the chosen Claude models in `$BEDROCK_REGION`.
2. List the model IDs and inference profiles:

   ```bash
   aws bedrock list-foundation-models --region $BEDROCK_REGION --by-provider anthropic --query "modelSummaries[].modelId"
   aws bedrock list-inference-profiles --region $BEDROCK_REGION --query "inferenceProfileSummaries[].inferenceProfileId"
   ```

3. Record the model IDs or inference-profile IDs for `model.fast` / `model.deep`, and their ARNs for the Terraform variable `bedrock_model_arns`. Include the foundation-model ARNs in every destination region the profile can route to.

**Verify:** both lists contain the Claude models you plan to use.

## Step 2: build and push the image (ARM64 / Graviton)

```bash
aws ecr create-repository --repository-name meridian --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=KMS
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR
docker buildx build --platform linux/arm64 -t $ECR/meridian:1.0.0 --push .
```

**Verify:** `aws ecr describe-images --repository-name meridian --query "imageDetails[].imageTags"` lists `1.0.0`, and the scan shows no critical findings.

## Step 3: configure Terraform

```bash
cd infra/aws
cp terraform.tfvars.example terraform.tfvars
```

Set these values in `terraform.tfvars`:

* `prefix`, `region`, `bedrock_region`, `bedrock_model_arns`, `image` (`$ECR/meridian:1.0.0`);
* `certificate_arn` (ACM certificate for the console hostname);
* `public_url`, `oidc_issuer`, `oidc_client_id`;
* `object_lock_mode` (`GOVERNANCE` unless legal approved `COMPLIANCE`);
* `nat_gateway` (`true` if MERIDIAN must call vendor SaaS APIs such as Defender, Graph or intel feeds);
* `client_cidrs` (corporate ranges that may open the console);
* `syslog_cidrs` (firewall and proxy sources);
* `cloudtrail_account_ids` (the organisation management account, if it owns the trail).

Also enable the `backend "s3" {}` block (PREREQUISITES section 4).

**Verify:** `terraform init` succeeds and `terraform validate` prints `Success!`. Optionally run `terraform test`, an offline plan with mocked providers.

## Step 4: plan and apply

```bash
terraform plan -out tf.plan      # review the resource list before applying
terraform apply tf.plan
terraform output
```

Apply usually takes 15-25 minutes; Aurora is the slowest part. ECS tasks will fail to start until step 5 is done. This is expected, because the secrets have no values yet.

**Verify:** `terraform output api_internal_dns` and `terraform output landing_queue_url` return values.

## Step 5: set the secrets and start the services

```bash
gen() { python -c "import secrets; print(secrets.token_urlsafe(32))"; }
put() { aws secretsmanager put-secret-value --secret-id "$PREFIX/$1" --secret-string "$2" >/dev/null && echo "set $1"; }
put api-keys "admin:$(gen),responder:$(gen),analyst:$(gen)"
put session-secret "$(gen)$(gen)"
put ingest-secret "$(gen)"
put ingest-tokens "none"                           # or "source:<32+ char token>,..." for shippers (LOG-00 §4.4)
put edl-token "$(gen)"
put metrics-token "$(gen)"
put agent-tokens "none:$(gen):lake:read"          # replace when AgentCore / remote agents are used
put oidc-client-secret "<client secret from your IdP>"
put lodestar-webhook-secret "<from LODESTAR, or $(gen)>"   # same value as LODESTAR_WEBHOOK_SECRET_<ORG>; set lodestar_url / lodestar_org in tfvars (INT-00 §7)
for s in api worker agents scheduler syslog collector; do
  aws ecs update-service --cluster $PREFIX --service $s --force-new-deployment >/dev/null && echo "redeploy $s"; done
```

Keep a copy of the API keys in your privileged-access vault. The database credentials are managed by Aurora; there is nothing to set.

**Verify:** after about 3 minutes, `aws ecs describe-services --cluster $PREFIX --services api worker agents scheduler syslog --query "services[].[serviceName,runningCount,desiredCount]" --output table` shows `runningCount = desiredCount` for every service, and the ALB target group is healthy (its health check is `/readyz`).

## Step 6: application configuration

The image ships `config/examples/aws.yaml`. For your organisation, edit a copy:

* `org`;
* `security.oidc.role_map`;
* `security.mcp_scope_map`;
* `response` (including `aws_quarantine_instance.quarantine_security_group`);
* `notify`.

Rebuild the image with it as `/app/config/examples/aws.yaml`, and include the context files (`assets.csv`, `identities.csv`, `intel/`), or deliver them through your image pipeline. Then roll out the new tag:

```bash
terraform apply -var image=$ECR/meridian:1.0.0-<build>
```

**Verify:** the next step's `doctor` shows your organisation name and source count.

## Step 7: containment prerequisites

```bash
# Quarantine security group (no inbound, no outbound) in each VPC where instances may be contained
SG=$(aws ec2 create-security-group --group-name meridian-quarantine --description "MERIDIAN quarantine" \
     --vpc-id <workload-vpc> --query GroupId --output text)
aws ec2 revoke-security-group-egress --group-id $SG --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
# Opt in the resources MERIDIAN may contain
aws ec2 create-tags --resources <instance-id> --tags Key=meridian-containable,Value=true
aws iam tag-user --user-name <user> --tags Key=meridian-containable,Value=true
```

**Verify:** a dry-run `aws_quarantine_instance` approval on a tagged instance shows the intended `ModifyInstanceAttribute` request.

## Step 8: health check and model evaluation (one-off tasks)

```bash
NET="awsvpcConfiguration={subnets=[$(terraform output -json private_subnet_ids | python -c 'import json,sys;print(",".join(json.load(sys.stdin)))')],securityGroups=[$(terraform output -raw app_security_group_id)],assignPublicIp=DISABLED}"
aws ecs run-task --cluster $PREFIX --launch-type FARGATE --task-definition $PREFIX-api \
  --network-configuration "$NET" --overrides '{"containerOverrides":[{"name":"api","command":["doctor"]}]}'
aws ecs run-task --cluster $PREFIX --launch-type FARGATE --task-definition $PREFIX-agents \
  --network-configuration "$NET" --overrides '{"containerOverrides":[{"name":"agents","command":["eval"]}]}'
aws logs tail /meridian/$PREFIX --since 10m --format short | grep -E "PASS|WARN|FAIL|accuracy"
```

The evaluation uses the agents task definition because only the agents role may call Bedrock.

**Verify:**

* `doctor` shows no FAIL lines. A WARN for `context` is expected until the CMDB is loaded.
* `eval` reports `accuracy >= 80%` with provider `anthropic_bedrock`.

## Step 9: console access and SSO

1. Create a DNS record for the `public_url` hostname, pointing to `terraform output -raw api_internal_dns`. Use a private hosted zone associated with the VPCs your users route through, or your corporate DNS.
2. Route user traffic to the internal ALB through Transit Gateway, VPN or Direct Connect, or publish it through your edge (CloudFront + WAF with VPC origins).
3. Register the redirect URI `https://<public-url>/auth/callback` in your IdP application.

**Verify:** members of the responder group sign in and `/api/me` shows the responder role. Unmapped users are refused.

## Step 10: onboard sources

Follow [ONBOARD-SOURCES.md](ONBOARD-SOURCES.md). Start with the organisation CloudTrail, then syslog through your Network Load Balancer, then push sources.

**Verify:**

* `aws sqs get-queue-attributes --queue-url $(terraform output -raw landing_queue_url) --attribute-names ApproximateNumberOfMessages` stays near 0;
* the DLQ is empty;
* `/metrics` shows fresh `meridian_source_last_batch_age_seconds` values.

## Step 11: end-to-end test

1. Trigger a CloudTrail detection in a sandbox account, for example create an access key for a test IAM user. This should raise `mer-aws-access-key-created`.
2. Within about 10 minutes (trail delivery plus processing), the alert appears and is triaged.
3. Request `aws_deactivate_access_key` from the case and approve it as a second responder. It runs as a dry run unless enabled.

**Verify:** the case timeline shows triage, the approval and the execution, and `verify-audit` (as a one-off task) prints `valid`.

## Step 12: tighten after go-live

* Create the CloudWatch alarms from [../OPERATIONS.md](../OPERATIONS.md) section 4. At minimum:
  * DLQ depth > 0;
  * oldest message age > 900 s;
  * ALB 5xx;
  * running task count < desired;
  * Aurora CPU.
* Scrape `/metrics` with Amazon Managed Service for Prometheus (ADOT collector).
* Enable Bedrock model invocation logging to the KMS-encrypted log group if your AI governance policy requires it.
* Review the Object Lock mode with legal before moving to `COMPLIANCE`.

## Optional: Bedrock AgentCore

Follow LLD-aws §7:

1. register the MCP servers as AgentCore Gateway targets;
2. attach `infra/aws/agentcore-policy.cedar`;
3. configure outbound OAuth to MERIDIAN.

Approvals stay in MERIDIAN.
