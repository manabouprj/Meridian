"""Verify a deployed MERIDIAN environment against its security design (12 checks per cloud).

A deployment guide that ends at "apply succeeded" describes an intention, not a control. This script checks the
properties the design depends on, from outside the application, using the cloud CLIs you are already logged in to.
It only reads; it changes nothing.

    # Azure (az login; subscription selected)
    python scripts/verify_deployment.py azure --resource-group rg-meridian [--url https://meridian.example]

    # AWS (credentials for the security-tooling account)
    terraform -chdir=infra/aws output -json > outputs.json
    python scripts/verify_deployment.py aws --prefix meridian --region me-central-1 --outputs outputs.json [--url ...]

Exit code 0 when no check FAILs (WARN is allowed and printed). Use the output as go-live evidence.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Runner = Callable[[list[str]], Any]


@dataclass
class Result:
    status: str          # PASS | WARN | FAIL | SKIP
    check: str
    detail: str


def cli(cmd: list[str]) -> Any:
    """Run a cloud CLI command and return parsed JSON (None on empty output). Raises on non-zero exit."""
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:400] or f"exit {out.returncode}")
    return json.loads(out.stdout) if out.stdout.strip() else None


def _safe(name: str, fn: Callable[[], list[Result] | Result]) -> list[Result]:
    try:
        r = fn()
        return r if isinstance(r, list) else [r]
    except Exception as exc:                    # a check that cannot run is reported, never silently passed
        return [Result("FAIL", name, f"could not evaluate: {exc}")]


def _readyz(url: str | None, opener=urllib.request.urlopen) -> Result:
    if not url:
        return Result("SKIP", "Readiness (/readyz)", "no --url given (run from a host that can reach the console)")
    with opener(url.rstrip("/") + "/readyz", timeout=15) as r:
        body = json.loads(r.read().decode())
    if body.get("ready") and not body.get("placeholder_secrets"):
        stale = [k for k, v in (body.get("heartbeats") or {}).items() if v is None or v > 300]
        return Result("WARN" if stale else "PASS", "Readiness (/readyz)",
                      f"ready; stale or missing heartbeats: {stale}" if stale else "ready, no placeholder secrets, heartbeats fresh")
    return Result("FAIL", "Readiness (/readyz)", json.dumps(body)[:300])


# ----------------------------------------------------------------------------------------------- Azure
def azure_checks(rg: str, run: Runner = cli, retention_days: int = 365, url: str | None = None,
                 opener=urllib.request.urlopen) -> list[Result]:
    az = lambda *a: run(["az", *a, "-o", "json"])  # noqa: E731
    res: list[Result] = []

    def storage():
        accts = [a for a in az("storage", "account", "list", "-g", rg) if a.get("isHnsEnabled")]
        if not accts:
            return Result("FAIL", "Lake storage account", "no HNS (ADLS Gen2) account in the resource group")
        a = accts[0]
        bad = []
        if a.get("publicNetworkAccess") != "Disabled":
            bad.append("public network access enabled")
        if a.get("allowSharedKeyAccess") is not False:
            bad.append("shared keys allowed")
        if a.get("minimumTlsVersion") != "TLS1_2":
            bad.append(f"min TLS {a.get('minimumTlsVersion')}")
        return Result("FAIL" if bad else "PASS", "Lake storage account is private and keyless",
                      "; ".join(bad) or f"{a['name']}: private, no shared keys, TLS 1.2")

    def worm():
        acct = [a for a in az("storage", "account", "list", "-g", rg) if a.get("isHnsEnabled")][0]["name"]
        p = az("storage", "container", "immutability-policy", "show", "--account-name", acct, "--container-name", "lake",
               "--auth-mode", "login") or {}
        days = int(p.get("immutabilityPeriodSinceCreationInDays") or 0)
        state = p.get("state", "absent")
        if days < retention_days:
            return Result("FAIL", "Lake WORM retention", f"{days} days (< {retention_days}), state {state}")
        return Result("PASS" if state == "Locked" else "WARN", "Lake WORM retention",
                      f"{days} days, state {state}" + ("" if state == "Locked" else " - lock it once legal approves"))

    def keyvault():
        kv = az("keyvault", "list", "-g", rg)[0]
        p = kv.get("properties", {})
        bad = []
        if not p.get("enablePurgeProtection"):
            bad.append("purge protection off")
        if not p.get("enableRbacAuthorization"):
            bad.append("access policies instead of RBAC")
        public = p.get("publicNetworkAccess") != "Disabled"
        if bad:
            return Result("FAIL", "Key Vault hardening", "; ".join(bad))
        return Result("WARN" if public else "PASS", "Key Vault hardening",
                      "public access enabled (deployer_cidrs) - clear it after go-live" if public
                      else f"{kv['name']}: RBAC, purge protection, private")

    def foundry():
        accts = [a for a in az("cognitiveservices", "account", "list", "-g", rg) if a.get("kind") == "AIServices"]
        if not accts:
            return [Result("FAIL", "Foundry account", "no AIServices account found")]
        a, p = accts[0], accts[0].get("properties", {})
        out = [Result("PASS" if p.get("disableLocalAuth") and p.get("publicNetworkAccess") == "Disabled" else "FAIL",
                      "Foundry: no API keys, no public access",
                      f"disableLocalAuth={p.get('disableLocalAuth')}, publicNetworkAccess={p.get('publicNetworkAccess')}")]
        deps = az("cognitiveservices", "account", "deployment", "list", "-g", rg, "-n", a["name"]) or []
        if not deps:
            out.append(Result("FAIL", "Foundry model deployments", "none"))
            return out
        msgs, worst = [], "PASS"
        for d in deps:
            sku, ver = (d.get("sku") or {}).get("name"), ((d.get("properties") or {}).get("model") or {}).get("version")
            msgs.append(f"{d['name']}={sku}/v{ver}")
            if ver == "1":
                worst = "FAIL"                      # Anthropic-hosted: processing may leave Azure
            elif sku != "DataZoneStandard" and worst != "FAIL":
                worst = "WARN"                      # Global Standard: any Azure region
        out.append(Result(worst, "Foundry inference residency (Azure-hosted, Data Zone)", ", ".join(msgs)))
        return out

    def postgres():
        s = az("postgres", "flexible-server", "list", "-g", rg)[0]
        bad = []
        if (s.get("network") or {}).get("publicNetworkAccess") != "Disabled":
            bad.append("public access")
        if (s.get("highAvailability") or {}).get("mode") != "ZoneRedundant":
            bad.append("no zone-redundant HA")
        b = s.get("backup") or {}
        if int(b.get("backupRetentionDays") or 0) < 35:
            bad.append(f"backup {b.get('backupRetentionDays')} days")
        if b.get("geoRedundantBackup") != "Enabled":
            bad.append("no geo-redundant backup")
        return Result("FAIL" if bad else "PASS", "PostgreSQL: private, HA, 35-day PITR, geo backup",
                      "; ".join(bad) or s["name"])

    def apps():
        env = az("containerapp", "env", "list", "-g", rg)[0]
        internal = ((env.get("properties") or {}).get("vnetConfiguration") or {}).get("internal")
        out = [Result("PASS" if internal else "FAIL", "Container Apps environment is internal", f"internal={internal}")]
        bad = []
        for a in az("containerapp", "list", "-g", rg):
            cfg = (a.get("properties") or {}).get("configuration") or {}
            if (cfg.get("ingress") or {}).get("external"):
                bad.append(f"{a['name']}: external ingress")
            for sec in cfg.get("secrets") or []:
                if not sec.get("keyVaultUrl"):
                    bad.append(f"{a['name']}: secret '{sec.get('name')}' not a Key Vault reference")
        out.append(Result("FAIL" if bad else "PASS", "Apps: no external ingress, secrets only from Key Vault",
                          "; ".join(bad) or "all apps internal; all secrets are Key Vault references"))
        return out

    def endpoints():
        pes = az("network", "private-endpoint", "list", "-g", rg)
        status = [c.get("privateLinkServiceConnectionState", {}).get("status")
                  for pe in pes for c in (pe.get("privateLinkServiceConnections") or [])]
        ok = len(pes) >= 5 and all(s == "Approved" for s in status)
        return Result("PASS" if ok else "FAIL", "Private endpoints approved (blob, dfs, queue, vault, Foundry)",
                      f"{len(pes)} endpoints, states {sorted(set(status))}")

    def law():
        ws = az("monitor", "log-analytics", "workspace", "list", "-g", rg)[0]
        cap = (ws.get("workspaceCapping") or {}).get("dailyQuotaGb")
        return Result("PASS" if cap and float(cap) > 0 else "WARN", "Platform log workspace has a daily cap",
                      f"dailyQuotaGb={cap} (security telemetry belongs in the lake, not here)")

    def eventgrid():
        topics = az("eventgrid", "system-topic", "list", "-g", rg)
        subs = az("eventgrid", "system-topic", "event-subscription", "list", "-g", rg, "--system-topic-name", topics[0]["name"])
        ok = [x for x in subs if (x.get("destination") or {}).get("endpointType") == "StorageQueue"
              and "Microsoft.Storage.BlobCreated" in ((x.get("filter") or {}).get("includedEventTypes") or [])]
        return Result("PASS" if ok else "FAIL", "Landing notifications: BlobCreated -> Storage Queue",
                      f"{len(ok)} subscription(s)" if ok else "no BlobCreated subscription to a storage queue")

    for name, fn in (("storage", storage), ("worm", worm), ("keyvault", keyvault), ("foundry", foundry),
                     ("postgres", postgres), ("apps", apps), ("endpoints", endpoints), ("eventgrid", eventgrid),
                     ("law", law)):
        res += _safe(name, fn)
    res += _safe("readyz", lambda: _readyz(url, opener))
    return res


# ----------------------------------------------------------------------------------------------- AWS
def aws_checks(prefix: str, region: str, outputs: dict, run: Runner = cli, retention_days: int = 365,
               url: str | None = None, opener=urllib.request.urlopen) -> list[Result]:
    aws = lambda *a: run(["aws", *a, "--region", region, "--output", "json"])  # noqa: E731
    o = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in outputs.items()}
    lake, landing = o.get("lake_bucket"), o.get("landing_bucket")
    res: list[Result] = []

    def object_lock():
        c = (aws("s3api", "get-object-lock-configuration", "--bucket", lake) or {}).get("ObjectLockConfiguration", {})
        r = ((c.get("Rule") or {}).get("DefaultRetention") or {})
        days, mode = int(r.get("Days") or 0), r.get("Mode")
        if c.get("ObjectLockEnabled") != "Enabled" or days < retention_days:
            return Result("FAIL", "Lake Object Lock (WORM)", f"enabled={c.get('ObjectLockEnabled')} days={days}")
        return Result("PASS" if mode == "COMPLIANCE" else "WARN", "Lake Object Lock (WORM)",
                      f"{days} days, mode {mode}" + ("" if mode == "COMPLIANCE" else " - GOVERNANCE can be bypassed by privileged admins"))

    def buckets():
        bad = []
        for b in (lake, landing):
            pab = (aws("s3api", "get-public-access-block", "--bucket", b) or {}).get("PublicAccessBlockConfiguration", {})
            if not all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                bad.append(f"{b}: public access block incomplete")
            enc = aws("s3api", "get-bucket-encryption", "--bucket", b) or {}
            rules = (enc.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or [{}]
            sse = (rules[0].get("ApplyServerSideEncryptionByDefault") or {})
            if sse.get("SSEAlgorithm") != "aws:kms" or not sse.get("KMSMasterKeyID"):
                bad.append(f"{b}: not SSE-KMS with a customer key")
            pol = (aws("s3api", "get-bucket-policy", "--bucket", b) or {}).get("Policy", "")
            if "aws:SecureTransport" not in pol:
                bad.append(f"{b}: no TLS-only policy")
        return Result("FAIL" if bad else "PASS", "Buckets: no public access, SSE-KMS (CMK), TLS only",
                      "; ".join(bad) or f"{lake}, {landing}")

    def queue():
        a = (aws("sqs", "get-queue-attributes", "--queue-url", o.get("landing_queue_url"), "--attribute-names", "All")
             or {}).get("Attributes", {})
        ok = bool(a.get("RedrivePolicy")) and bool(a.get("KmsMasterKeyId"))
        return Result("PASS" if ok else "FAIL", "Landing queue: dead-letter queue and KMS",
                      f"redrive={'yes' if a.get('RedrivePolicy') else 'no'}, kms={'yes' if a.get('KmsMasterKeyId') else 'no'}")

    def aurora():
        c = (aws("rds", "describe-db-clusters", "--db-cluster-identifier", f"{prefix}-db") or {}).get("DBClusters", [{}])[0]
        insts = (aws("rds", "describe-db-instances", "--filters", f"Name=db-cluster-id,Values={prefix}-db") or {}).get("DBInstances", [])
        bad = []
        if not c.get("DeletionProtection"):
            bad.append("deletion protection off")
        if not c.get("StorageEncrypted"):
            bad.append("storage not encrypted")
        if int(c.get("BackupRetentionPeriod") or 0) < 35:
            bad.append(f"backups {c.get('BackupRetentionPeriod')} days")
        if len(insts) < 2:
            bad.append(f"{len(insts)} instance(s): no failover")
        if any(i.get("PubliclyAccessible") for i in insts):
            bad.append("an instance is publicly accessible")
        return Result("FAIL" if bad else "PASS", "Aurora: private, encrypted, 2 instances, 35-day backups, protected",
                      "; ".join(bad) or f"{prefix}-db")

    def tasks():
        bad = []
        secretish = ("SECRET", "TOKEN", "PASSWORD", "API_KEYS", "CREDENTIALS")
        for role in ("api", "worker", "agents", "scheduler", "syslog", "collector"):
            td = (aws("ecs", "describe-task-definition", "--task-definition", f"{prefix}-{role}") or {}).get("taskDefinition", {})
            for c in td.get("containerDefinitions", []):
                if not c.get("readonlyRootFilesystem"):
                    bad.append(f"{role}: writable root filesystem")
                if not c.get("user") or c.get("user") in ("root", "0"):
                    bad.append(f"{role}: runs as root")
                for e in c.get("environment", []):
                    if any(s in e.get("name", "") for s in secretish) and e.get("value"):
                        bad.append(f"{role}: secret-like variable {e['name']} in plain environment")
        return Result("FAIL" if bad else "PASS", "Tasks: non-root, read-only root FS, secrets only from Secrets Manager",
                      "; ".join(bad) or "5 task definitions compliant")

    def alb():
        lb = (aws("elbv2", "describe-load-balancers", "--names", f"{prefix}-api") or {}).get("LoadBalancers", [{}])[0]
        ls = (aws("elbv2", "describe-listeners", "--load-balancer-arn", lb.get("LoadBalancerArn", "")) or {}).get("Listeners", [])
        bad = []
        if lb.get("Scheme") != "internal":
            bad.append(f"scheme {lb.get('Scheme')}")
        for li in ls:
            if li.get("Protocol") != "HTTPS":
                bad.append(f"listener {li.get('Port')} is {li.get('Protocol')}")
            elif "TLS13" not in (li.get("SslPolicy") or ""):
                bad.append(f"listener {li.get('Port')} policy {li.get('SslPolicy')}")
        return Result("FAIL" if bad else "PASS", "Load balancer: internal, HTTPS only, TLS 1.3 policy", "; ".join(bad) or "ok")

    def sgs():
        groups = (aws("ec2", "describe-security-groups", "--filters",
                      f"Name=group-name,Values={prefix}-alb,{prefix}-app,{prefix}-db,{prefix}-vpce") or {}).get("SecurityGroups", [])
        bad = []
        for g in groups:
            for p in g.get("IpPermissions", []):
                if p.get("IpProtocol") == "-1":
                    bad.append(f"{g['GroupName']}: all-protocol ingress")
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])):
                    bad.append(f"{g['GroupName']}: ingress from 0.0.0.0/0")
        if len(groups) < 4:
            bad.append(f"expected 4 security groups, found {len(groups)}")
        return Result("FAIL" if bad else "PASS", "Security groups: no open or all-protocol ingress", "; ".join(bad) or "4 groups")

    def iam():
        doc = (aws("iam", "get-role-policy", "--role-name", f"{prefix}-agents", "--policy-name", "agents") or {}).get("PolicyDocument", {})
        if isinstance(doc, str):
            doc = json.loads(doc)
        bad = []
        for st in doc.get("Statement", []):
            acts = st.get("Action") if isinstance(st.get("Action"), list) else [st.get("Action")]
            res_ = st.get("Resource") if isinstance(st.get("Resource"), list) else [st.get("Resource")]
            if any(str(a).startswith("bedrock:") for a in acts) and "*" in res_:
                bad.append("bedrock actions on Resource *")
            if any(a in ("*", "bedrock:*", "s3:*", "iam:*") for a in acts):
                bad.append(f"wildcard action {acts}")
        return Result("FAIL" if bad else "PASS", "Agents role: model access limited to approved ARNs, no wildcards",
                      "; ".join(bad) or f"{prefix}-agents")

    def bedrock_endpoint():
        eps = (aws("ec2", "describe-vpc-endpoints", "--filters",
                   f"Name=service-name,Values=com.amazonaws.{region}.bedrock-runtime") or {}).get("VpcEndpoints", [])
        ok = any(e.get("PrivateDnsEnabled") and e.get("State", "").lower() == "available" for e in eps)
        return Result("PASS" if ok else "FAIL", "Model traffic stays in the VPC (bedrock-runtime endpoint, private DNS)",
                      f"{len(eps)} endpoint(s)")

    def secrets():
        missing = []
        for n in ("api-keys", "session-secret", "ingest-secret", "ingest-tokens", "edl-token", "metrics-token", "agent-tokens",
                  "oidc-client-secret", "lodestar-webhook-secret"):
            v = (aws("secretsmanager", "list-secret-version-ids", "--secret-id", f"{prefix}/{n}") or {}).get("Versions", [])
            if not any("AWSCURRENT" in (x.get("VersionStages") or []) for x in v):
                missing.append(n)
        return Result("FAIL" if missing else "PASS", "Application secrets have values",
                      f"missing: {missing}" if missing else "9/9 set (values not read)")

    def logs():
        groups = (aws("logs", "describe-log-groups", "--log-group-name-prefix", f"/meridian/{prefix}") or {}).get("logGroups", [])
        ok = groups and all(g.get("kmsKeyId") for g in groups) and all(g.get("retentionInDays") for g in groups)
        return Result("PASS" if ok else "FAIL", "Platform logs: KMS-encrypted with a retention period",
                      f"{len(groups)} log group(s)")

    for name, fn in (("object_lock", object_lock), ("buckets", buckets), ("queue", queue), ("aurora", aurora),
                     ("tasks", tasks), ("alb", alb), ("sgs", sgs), ("iam", iam), ("bedrock", bedrock_endpoint),
                     ("secrets", secrets), ("logs", logs)):
        res += _safe(name, fn)
    res += _safe("readyz", lambda: _readyz(url, opener))
    return res


def render(results: list[Result]) -> str:
    lines = [f"{r.status:5s} {r.check}: {r.detail}" for r in results]
    n = {s: sum(r.status == s for r in results) for s in ("PASS", "WARN", "FAIL", "SKIP")}
    lines.append(f"-- {n['PASS']} pass, {n['WARN']} warn, {n['FAIL']} fail, {n['SKIP']} skipped")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify a deployed MERIDIAN environment (read-only)")
    sub = p.add_subparsers(dest="cloud", required=True)
    a = sub.add_parser("azure")
    a.add_argument("--resource-group", required=True)
    w = sub.add_parser("aws")
    w.add_argument("--prefix", default="meridian")
    w.add_argument("--region", required=True)
    w.add_argument("--outputs", required=True, help="terraform output -json file")
    for x in (a, w):
        x.add_argument("--url", help="console base URL for the /readyz check")
        x.add_argument("--retention-days", type=int, default=365)
    args = p.parse_args(argv)
    if args.cloud == "azure":
        results = azure_checks(args.resource_group, retention_days=args.retention_days, url=args.url)
    else:
        with open(args.outputs, encoding="utf-8") as f:
            outputs = json.load(f)
        results = aws_checks(args.prefix, args.region, outputs, retention_days=args.retention_days, url=args.url)
    print(render(results))
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
