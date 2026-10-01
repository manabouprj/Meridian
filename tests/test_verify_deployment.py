"""verify_deployment.py logic against recorded CLI output (compliant and misconfigured environments)."""
import copy
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import verify_deployment as vd  # noqa: E402

AZ = {
    ("storage", "account", "list"): [{"name": "stmeridian", "isHnsEnabled": True, "publicNetworkAccess": "Disabled",
                                      "allowSharedKeyAccess": False, "minimumTlsVersion": "TLS1_2"}],
    ("storage", "container", "immutability-policy"): {"immutabilityPeriodSinceCreationInDays": 365, "state": "Locked"},
    ("keyvault", "list"): [{"name": "kv-m", "properties": {"enablePurgeProtection": True, "enableRbacAuthorization": True,
                                                         "publicNetworkAccess": "Disabled"}}],
    ("cognitiveservices", "account", "list"): [{"name": "aif-m", "kind": "AIServices",
                                                "properties": {"disableLocalAuth": True, "publicNetworkAccess": "Disabled"}}],
    ("cognitiveservices", "account", "deployment"): [
        {"name": "meridian-fast", "sku": {"name": "DataZoneStandard"}, "properties": {"model": {"version": "2"}}},
        {"name": "meridian-deep", "sku": {"name": "DataZoneStandard"}, "properties": {"model": {"version": "2"}}}],
    ("postgres", "flexible-server", "list"): [{"name": "psql-m", "network": {"publicNetworkAccess": "Disabled"},
                                               "highAvailability": {"mode": "ZoneRedundant"},
                                               "backup": {"backupRetentionDays": 35, "geoRedundantBackup": "Enabled"}}],
    ("containerapp", "env", "list"): [{"properties": {"vnetConfiguration": {"internal": True}}}],
    ("containerapp", "list"): [{"name": "ca-m-api", "properties": {"configuration": {
        "ingress": {"external": False}, "secrets": [{"name": "api-keys", "keyVaultUrl": "https://kv/secrets/x"}]}}}],
    ("network", "private-endpoint", "list"): [{"privateLinkServiceConnections": [
        {"privateLinkServiceConnectionState": {"status": "Approved"}}]}] * 5,
    ("monitor", "log-analytics", "workspace", "list"): [{"workspaceCapping": {"dailyQuotaGb": 2}}],
    ("eventgrid", "system-topic", "list"): [{"name": "egt-m"}],
    ("eventgrid", "system-topic", "event-subscription"): [{"destination": {"endpointType": "StorageQueue"},
                                                           "filter": {"includedEventTypes": ["Microsoft.Storage.BlobCreated"]}}],
}

AWS = {
    ("s3api", "get-object-lock-configuration"): {"ObjectLockConfiguration": {
        "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}}}},
    ("s3api", "get-public-access-block"): {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
    ("s3api", "get-bucket-encryption"): {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "arn:aws:kms:x"}}]}},
    ("s3api", "get-bucket-policy"): {"Policy": json.dumps({"Statement": [{"Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})},
    ("sqs", "get-queue-attributes"): {"Attributes": {"RedrivePolicy": "{...}", "KmsMasterKeyId": "arn:aws:kms:x"}},
    ("rds", "describe-db-clusters"): {"DBClusters": [{"DeletionProtection": True, "StorageEncrypted": True,
                                                      "BackupRetentionPeriod": 35}]},
    ("rds", "describe-db-instances"): {"DBInstances": [{"PubliclyAccessible": False}, {"PubliclyAccessible": False}]},
    ("ecs", "describe-task-definition"): {"taskDefinition": {"containerDefinitions": [
        {"readonlyRootFilesystem": True, "user": "meridian", "environment": [{"name": "MERIDIAN_CLOUD", "value": "aws"}]}]}},
    ("elbv2", "describe-load-balancers"): {"LoadBalancers": [{"Scheme": "internal", "LoadBalancerArn": "arn:lb"}]},
    ("elbv2", "describe-listeners"): {"Listeners": [{"Port": 443, "Protocol": "HTTPS",
                                                     "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06"}]},
    ("ec2", "describe-security-groups"): {"SecurityGroups": [
        {"GroupName": n, "IpPermissions": [{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "10.70.0.0/16"}]}]}
        for n in ("meridian-alb", "meridian-app", "meridian-db", "meridian-vpce")]},
    ("iam", "get-role-policy"): {"PolicyDocument": {"Statement": [
        {"Action": ["bedrock:InvokeModel"], "Resource": ["arn:aws:bedrock:*::foundation-model/anthropic.claude-x*"]}]}},
    ("ec2", "describe-vpc-endpoints"): {"VpcEndpoints": [{"PrivateDnsEnabled": True, "State": "available"}]},
    ("secretsmanager", "list-secret-version-ids"): {"Versions": [{"VersionStages": ["AWSCURRENT"]}]},
    ("logs", "describe-log-groups"): {"logGroups": [{"kmsKeyId": "arn:aws:kms:x", "retentionInDays": 30}]},
}
OUTPUTS = {"lake_bucket": {"value": "m-lake"}, "landing_bucket": {"value": "m-landing"},
           "landing_queue_url": {"value": "https://sqs/q"}}


def runner(table):
    def run(cmd):
        args = cmd[1:]
        for key in sorted(table, key=len, reverse=True):
            if tuple(args[:len(key)]) == key:
                return copy.deepcopy(table[key])
        raise RuntimeError(f"unexpected command {cmd}")
    return run


def ready_opener(body):
    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    return lambda url, timeout=15: R(json.dumps(body).encode())


def statuses(results):
    return {r.check: r.status for r in results}


def test_azure_compliant_environment_passes():
    ok = {"ready": True, "heartbeats": {"worker": 10, "agents": 12, "scheduler": 30}}
    res = vd.azure_checks("rg-m", run=runner(AZ), url="https://m.example", opener=ready_opener(ok))
    assert all(r.status == "PASS" for r in res), vd.render(res)
    assert len(res) == 12


def test_azure_misconfigurations_are_caught():
    bad = copy.deepcopy(AZ)
    bad[("cognitiveservices", "account", "deployment")][0]["properties"]["model"]["version"] = "1"   # Anthropic-hosted
    bad[("cognitiveservices", "account", "list")][0]["properties"]["disableLocalAuth"] = False
    bad[("storage", "container", "immutability-policy")] = {"immutabilityPeriodSinceCreationInDays": 30, "state": "Unlocked"}
    bad[("containerapp", "list")][0]["properties"]["configuration"]["secrets"][0].pop("keyVaultUrl")
    s = statuses(vd.azure_checks("rg-m", run=runner(bad)))
    assert s["Foundry inference residency (Azure-hosted, Data Zone)"] == "FAIL"
    assert s["Foundry: no API keys, no public access"] == "FAIL"
    assert s["Lake WORM retention"] == "FAIL"
    assert s["Apps: no external ingress, secrets only from Key Vault"] == "FAIL"
    assert s["Readiness (/readyz)"] == "SKIP"


def test_azure_global_standard_is_a_warning():
    g = copy.deepcopy(AZ)
    for d in g[("cognitiveservices", "account", "deployment")]:
        d["sku"]["name"] = "GlobalStandard"
    assert statuses(vd.azure_checks("rg-m", run=runner(g)))["Foundry inference residency (Azure-hosted, Data Zone)"] == "WARN"


def test_aws_compliant_environment_passes():
    res = vd.aws_checks("meridian", "me-central-1", OUTPUTS, run=runner(AWS))
    assert [r.status for r in res if r.status != "SKIP"] == ["PASS"] * 11, vd.render(res)
    assert len(res) == 12


def test_aws_misconfigurations_are_caught():
    bad = copy.deepcopy(AWS)
    bad[("ec2", "describe-security-groups")]["SecurityGroups"][1]["IpPermissions"].append(
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    bad[("iam", "get-role-policy")]["PolicyDocument"]["Statement"][0]["Resource"] = ["*"]
    bad[("ecs", "describe-task-definition")]["taskDefinition"]["containerDefinitions"][0]["environment"].append(
        {"name": "MERIDIAN_INGEST_SECRET", "value": "oops"})
    bad[("secretsmanager", "list-secret-version-ids")] = {"Versions": []}
    bad[("ec2", "describe-vpc-endpoints")] = {"VpcEndpoints": []}
    s = statuses(vd.aws_checks("meridian", "me-central-1", OUTPUTS, run=runner(bad)))
    for check in ("Security groups: no open or all-protocol ingress",
                  "Agents role: model access limited to approved ARNs, no wildcards",
                  "Tasks: non-root, read-only root FS, secrets only from Secrets Manager",
                  "Application secrets have values",
                  "Model traffic stays in the VPC (bedrock-runtime endpoint, private DNS)"):
        assert s[check] == "FAIL", check


def test_a_check_that_cannot_run_fails_rather_than_passes():
    def broken(cmd):
        raise RuntimeError("AuthorizationFailed")
    res = vd.azure_checks("rg-m", run=broken)
    assert all(r.status in ("FAIL", "SKIP") for r in res)
