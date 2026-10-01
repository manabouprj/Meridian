"""Containment actions. Agents can only REQUEST these; `execute` runs after a human approves.

Each action states the least-privilege permission it needs. `dry_run` (the default) records exactly
what would be sent without calling the API - switch it off per action once the change board agrees.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx


@dataclass
class Action:
    name: str
    description: str
    target_hint: str
    permission: str
    validate_target: Callable[[str], str | None]
    run: Callable[[str, dict[str, Any], dict[str, Any]], dict[str, Any]]


def _uuidish(t: str) -> str | None:
    return None if re.fullmatch(r"[A-Za-z0-9\-]{8,64}", t) else "target must be an object / device id"


def _upn_or_id(t: str) -> str | None:
    return None if re.fullmatch(r"[^\s/]+@[^\s/]+|[0-9a-fA-F\-]{36}", t) else "target must be a UPN or Entra object id"


def _indicator(t: str) -> str | None:
    t = t.strip()
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        net = None
    if net is not None:
        mapped = getattr(net.network_address, "ipv4_mapped", None)
        if mapped is not None:                  # ::ffff:10.0.0.5 is 10.0.0.5 - judge it as IPv4
            net = ipaddress.ip_network(f"{mapped}/{max(0, net.prefixlen - 96)}", strict=False)
        if net.is_unspecified or net.is_reserved:
            return "refusing to block unspecified / reserved addresses"
        internal = any(net.subnet_of(n) for n in _INTERNAL if n.version == net.version)
        too_big = net.prefixlen < (24 if net.version == 4 else 48)
        if internal or net.is_loopback or net.is_link_local or net.is_multicast or too_big:
            return "refusing to block internal / loopback ranges or networks larger than /24 (/48)"
        return None
    if re.fullmatch(r"(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,24}", t.lower()):
        return None
    return "target must be a public IP, CIDR (/24 or smaller) or a domain"


_INTERNAL = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                               "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128",
                                               "fe80::/10")]


def _aws_key(t: str) -> str | None:
    return None if re.fullmatch(r"[\w+=,.@-]{1,64}:AKIA[0-9A-Z]{16}|[\w+=,.@-]{1,64}:ASIA[0-9A-Z]{16}", t) else \
        "target must be '<iam-user>:<access-key-id>'"


def _ec2(t: str) -> str | None:
    return None if re.fullmatch(r"i-[0-9a-f]{8,17}", t) else "target must be an EC2 instance id (i-...)"


def _token(scope: str, cfg: dict[str, Any]) -> str:
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential().get_token(scope).token


def _http(cfg: dict[str, Any]) -> httpx.Client:
    kw = {"transport": cfg["_transport"]} if cfg.get("_transport") else {}
    return httpx.Client(timeout=30, trust_env=True, **kw)


def _isolate(target: str, params: dict, cfg: dict) -> dict:
    url = f"{cfg.get('mde_base', 'https://api.securitycenter.microsoft.com')}/api/machines/{target}/isolate"
    body = {"Comment": params.get("comment", "MERIDIAN approved containment"), "IsolationType": params.get("type", "Full")}
    if cfg.get("dry_run", True):
        return {"dry_run": True, "request": {"method": "POST", "url": url, "body": body}}
    tok = cfg.get("_token") or _token("https://api.securitycenter.microsoft.com/.default", cfg)
    with _http(cfg) as c:
        r = c.post(url, json=body, headers={"Authorization": f"Bearer {tok}"})
    r.raise_for_status()
    return {"status": r.status_code, "machine_action_id": r.json().get("id")}


def _revoke(target: str, params: dict, cfg: dict) -> dict:
    url = f"{cfg.get('graph_base', 'https://graph.microsoft.com/v1.0')}/users/{target}/revokeSignInSessions"
    if cfg.get("dry_run", True):
        return {"dry_run": True, "request": {"method": "POST", "url": url}}
    tok = cfg.get("_token") or _token("https://graph.microsoft.com/.default", cfg)
    with _http(cfg) as c:
        r = c.post(url, headers={"Authorization": f"Bearer {tok}"})
    r.raise_for_status()
    return {"status": r.status_code}


def _disable(target: str, params: dict, cfg: dict) -> dict:
    url = f"{cfg.get('graph_base', 'https://graph.microsoft.com/v1.0')}/users/{target}"
    if cfg.get("dry_run", True):
        return {"dry_run": True, "request": {"method": "PATCH", "url": url, "body": {"accountEnabled": False}}}
    tok = cfg.get("_token") or _token("https://graph.microsoft.com/.default", cfg)
    with _http(cfg) as c:
        r = c.patch(url, json={"accountEnabled": False}, headers={"Authorization": f"Bearer {tok}"})
    r.raise_for_status()
    return {"status": r.status_code}


def _block(target: str, params: dict, cfg: dict) -> dict:
    store = cfg["_store"]
    try:                                        # classify by parsing, not by character set ("bad.cafe" is a domain)
        ipaddress.ip_network(target.strip(), strict=False)
        kind = "ip"
    except ValueError:
        kind = "domain"
    store.add_block(target.strip().lower(), kind, params.get("case_id", ""), params.get("approved_by", ""),
                    int(cfg.get("block_ttl_days", 30)))
    return {"listed": target, "list": f"/edl/{kind}.txt", "note": "firewalls / proxies pull the EDL on their schedule"}


def _aws_client(service: str, cfg: dict):
    """boto3 client with the task role, or - for cross-account response - a role in the member account
    (`role_arn`, which should itself only allow resources tagged meridian-containable=true)."""
    import boto3
    region = cfg.get("region")
    if not cfg.get("role_arn"):
        return boto3.client(service, region_name=region)
    creds = boto3.client("sts").assume_role(RoleArn=cfg["role_arn"], RoleSessionName="meridian-response",
                                            DurationSeconds=900)["Credentials"]
    return boto3.client(service, region_name=region, aws_access_key_id=creds["AccessKeyId"],
                        aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])


def _aws_key_off(target: str, params: dict, cfg: dict) -> dict:
    user, key = target.split(":", 1)
    if cfg.get("dry_run", True):
        return {"dry_run": True, "request": {"api": "iam:UpdateAccessKey", "UserName": user, "AccessKeyId": key, "Status": "Inactive"}}
    iam = cfg.get("_iam") or _aws_client("iam", cfg)
    iam.update_access_key(UserName=user, AccessKeyId=key, Status="Inactive")
    return {"deactivated": key}


def _aws_quarantine(target: str, params: dict, cfg: dict) -> dict:
    sg = cfg.get("quarantine_security_group")
    if not sg:
        raise RuntimeError("response.quarantine_security_group is not configured")
    if cfg.get("dry_run", True):
        return {"dry_run": True, "request": {"api": "ec2:ModifyInstanceAttribute", "InstanceId": target, "Groups": [sg]}}
    ec2 = cfg.get("_ec2") or _aws_client("ec2", cfg)
    ec2.modify_instance_attribute(InstanceId=target, Groups=[sg])
    return {"quarantined": target, "security_group": sg}


def _redact_url(url: str | None) -> str | None:
    """Keep scheme and host only: webhook URLs often embed a SAS signature or token in the path or query."""
    if not url:
        return url
    from urllib.parse import urlsplit
    u = urlsplit(url)
    return f"{u.scheme}://{u.hostname}/..." if u.hostname else "(configured)"


def _soar(target: str, params: dict, cfg: dict) -> dict:
    """Hand over to an existing SOAR / automation platform with a signed webhook."""
    url, secret = cfg.get("soar_webhook_url"), cfg.get("soar_webhook_secret", "")
    body = json.dumps({"action": params.get("soar_action", "contain"), "target": target, "case_id": params.get("case_id"),
                       "approved_by": params.get("approved_by")}).encode()
    if cfg.get("dry_run", True) or not url:
        return {"dry_run": True, "request": {"url": _redact_url(url), "body": json.loads(body)}}
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    with _http(cfg) as c:
        r = c.post(url, content=body, headers={"Content-Type": "application/json", "X-Meridian-Timestamp": ts,
                                                "X-Meridian-Signature": f"sha256={sig}"})
    r.raise_for_status()
    return {"status": r.status_code}


ACTIONS: dict[str, Action] = {a.name: a for a in [
    Action("isolate_device", "Network-isolate a device with Microsoft Defender for Endpoint", "MDE machine id",
           "WindowsDefenderATP Machine.Isolate (application)", _uuidish, _isolate),
    Action("revoke_sessions", "Revoke all refresh tokens / sessions of an Entra ID user", "UPN or object id",
           "Graph User.RevokeSessions.All", _upn_or_id, _revoke),
    Action("disable_user", "Disable an Entra ID user account", "UPN or object id",
           "Graph User.EnableDisableAccount.All", _upn_or_id, _disable),
    Action("block_indicator", "Add an IP / domain to MERIDIAN's external dynamic block list (firewall / proxy pull it)",
           "public IP, CIDR /24 or smaller, or domain", "none (MERIDIAN internal list)", _indicator, _block),
    Action("aws_deactivate_access_key", "Deactivate an IAM user's access key", "<iam-user>:<access-key-id>",
           "iam:UpdateAccessKey on the user", _aws_key, _aws_key_off),
    Action("aws_quarantine_instance", "Replace an EC2 instance's security groups with the quarantine group", "i-...",
           "ec2:ModifyInstanceAttribute", _ec2, _aws_quarantine),
    Action("soar_playbook", "Hand the approved action to your SOAR / automation via signed webhook", "any id the playbook accepts",
           "SOAR webhook secret", lambda t: None if 0 < len(t) <= 300 else "target required", _soar),
]}
