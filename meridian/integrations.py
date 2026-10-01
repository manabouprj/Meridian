"""Outbound integrations: LODESTAR (prioritisation + board reporting) and chat notifications.

LODESTAR: MERIDIAN pushes its cases as SOC findings to LODESTAR's signed webhook
(/api/ingest/soc?org=<key>, HMAC-SHA256 over "<timestamp>.<body>"), plus a health block with the KPIs
LODESTAR's KRIs use (mttd_hours, incidents_open, log sources). LODESTAR then correlates them with
vulnerabilities, identity risk and external intel and puts them on the CISO's Today list.
Chat: approval requests and critical cases go to a Slack incoming webhook / Teams workflow URL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

SEV = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}


def lodestar_payload(store, hours: int = 24 * 7, sources: list[str] | None = None, context=None) -> dict[str, Any]:
    cases = store.list_cases(limit=500)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    findings = []
    for c in cases:
        if c["updated_at"] < since and c["status"] not in ("new", "triaged", "investigating", "awaiting_approval"):
            continue
        ids = entity_fields(store, c, context)
        status = "resolved" if c["status"] == "closed" else ("in_progress" if c["status"] in ("investigating", "awaiting_approval", "contained") else "open")
        if c.get("verdict") == "benign":
            status = "false_positive"
        findings.append({
            "finding_id": f"meridian-{c['case_id']}", "source": "meridian", "finding_type": "incident",
            "title": c["title"][:300], "severity": SEV.get(int(c["severity"] or 3), "medium"), "status": status,
            **ids,
            # a MALICIOUS verdict is confirmed threat activity in this environment: LODESTAR's strongest urgency
            # signal (Today list when the asset is business-critical). Suspicious/inconclusive cases are not.
            "actively_exploited_in_env": c.get("verdict") == "malicious" and status != "resolved",
            "first_seen": c["created_at"].isoformat(), "last_seen": c["updated_at"].isoformat(),
            "description": (c.get("summary") or "")[:2000],
            "evidence": {"case_id": c["case_id"], "verdict": c.get("verdict"), "mitre": c.get("mitre") or [],
                         "entity": c["entity"], "entity_type": ids.pop("_entity_type", None)}})
    opened = [c for c in cases if c["created_at"] >= datetime.now(timezone.utc) - timedelta(days=30)]
    mttd = None
    if opened:
        gaps = []
        for c in opened[:200]:
            full = store.get_case(c["case_id"])
            alerts = full.get("alerts") or []
            if alerts:
                first_evt = min(a["first_seen"] for a in alerts)
                gaps.append((min(a["created_at"] for a in alerts) - first_evt).total_seconds() / 3600)
        mttd = round(sum(gaps) / len(gaps), 2) if gaps else None
    kpis: dict[str, Any] = {"incidents_open": sum(1 for c in cases if c["status"] not in ("closed",))}
    if mttd is not None:
        kpis["mttd_hours"] = mttd
    closed = [c for c in cases if c["status"] in ("closed", "contained") and c["updated_at"] >= datetime.now(timezone.utc) - timedelta(days=30)]
    if closed:                       # mean hours from case opened to contained / closed, last 30 days
        kpis["mttr_hours"] = round(sum((c["updated_at"] - c["created_at"]).total_seconds() for c in closed) / 3600 / len(closed), 2)
    health: dict[str, Any] = {"kpis": kpis}
    if sources:                     # coverage = configured sources that delivered data in the last 24 h (measured)
        seen = store.source_last_seen(sources)
        fresh = [s for s, t in seen.items() if t and datetime.now(timezone.utc) - t < timedelta(hours=24)]
        health["coverage_pct"] = round(100 * len(fresh) / len(sources))
        kpis["log_sources_silent"] = len(sources) - len(fresh)        # LODESTAR SOC KPI name
    return {"findings": findings, "health": health}


ASSET_ENTITY_TYPES = {"device", "cloud_account", "resource"}      # LODESTAR resolves these against the CMDB
IP_ENTITY_TYPES = {"src_ip", "dst_ip", "ip"}


def entity_fields(store, case: dict[str, Any], context=None) -> dict[str, Any]:
    """Map a case's entities onto LODESTAR's Finding identity fields (contract: docs/integration/MERIDIAN-LODESTAR-INT-00.md §4).
    Devices, cloud accounts and resources -> asset_id (CMDB match by name / alias / external id); users -> user_id;
    IP addresses are NOT assets (an attacker IP must not create or match an asset) -> entity_keys only.
    Every other entity of the case goes to entity_keys so LODESTAR can correlate across domains."""
    full = store.get_case(case["case_id"]) or {}
    alerts = full.get("alerts") or []
    etype = next((a.get("entity_type") for a in alerts if a.get("entity") == case["entity"]), None) or (
        "user" if "@" in (case["entity"] or "") else "device")
    out: dict[str, Any] = {"asset_id": None, "user_id": None, "_entity_type": etype}
    if etype == "user" or "@" in (case["entity"] or ""):
        out["user_id"] = case["entity"]
    elif etype in ASSET_ENTITY_TYPES:
        out["asset_id"] = case["entity"]
    keys = {str(e) for e in ((case.get("data") or {}).get("entities") or [])} | {case["entity"]}
    devices: list[str] = []
    for a in alerts:
        if a.get("entity_type") == "device" and a.get("entity"):
            devices.append(str(a["entity"]).lower())
        for ev in ((a.get("data") or {}).get("sample") or [])[:20]:
            if ev.get("user") and not out["user_id"]:
                out["user_id"] = str(ev["user"]).lower()
            if ev.get("device"):
                devices.append(str(ev["device"]).lower())
    if devices and (context is not None or not out["asset_id"]):
        # Report the MOST CRITICAL asset the case reached (same CMDB as LODESTAR), not merely the first one: a
        # phishing chain that started on a workstation and reached a file server is a file-server incident.
        def crit(d: str) -> int:
            a = context.asset_for(d) if context is not None else None
            return a.criticality if a else 0
        best = max(dict.fromkeys(devices), key=crit)
        if out["asset_id"] is None or crit(best) > crit(out["asset_id"]):
            out["asset_id"] = best
    out["entity_keys"] = sorted(k for k in keys if k and k not in (out["asset_id"], out["user_id"]))[:50]
    return out


def push_lodestar(store, cfg: dict[str, Any], transport=None, sources: list[str] | None = None, context=None) -> dict[str, Any]:
    url, secret = cfg.get("url"), cfg.get("webhook_secret")
    if not url or not secret:
        return {"skipped": "lodestar.url / webhook_secret not configured"}
    body = json.dumps(lodestar_payload(store, sources=sources, context=context), default=str).encode()
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    target = f"{url.rstrip('/')}/api/ingest/soc" + (f"?org={cfg['org']}" if cfg.get("org") else "")
    kw = {"transport": transport} if transport else {}
    with httpx.Client(timeout=30, trust_env=True, **kw) as c:
        r = c.post(target, content=body, headers={"Content-Type": "application/json", "X-Lodestar-Timestamp": ts,
                                                   "X-Lodestar-Signature": f"sha256={sig}"})
    return {"status": r.status_code, "accepted": (r.json() if r.headers.get("content-type", "").startswith("application/json") else {}).get("accepted")}


def notify(cfg: dict[str, Any], title: str, lines: list[str], link: str | None = None, transport=None) -> list[dict]:
    """Slack incoming webhook and/or Teams workflow webhook. Never raises - chat outages must not block response."""
    out = []
    text = f"*{title}*\n" + "\n".join(f"- {line}" for line in lines) + (f"\n<{link}|Open in MERIDIAN>" if link else "")
    kw = {"transport": transport} if transport else {}
    for kind, url in (("slack", cfg.get("slack_webhook_url")), ("teams", cfg.get("teams_workflow_url"))):
        if not url:
            continue
        body = {"text": text} if kind == "slack" else {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "content": {
                "type": "AdaptiveCard", "version": "1.4", "body": [{"type": "TextBlock", "weight": "Bolder", "text": title, "wrap": True}]
                + [{"type": "TextBlock", "text": line, "wrap": True} for line in lines],
                "actions": [{"type": "Action.OpenUrl", "title": "Open in MERIDIAN", "url": link}] if link else []}}]}
        try:
            with httpx.Client(timeout=10, trust_env=True, **kw) as c:
                r = c.post(url, json=body)
            out.append({"channel": kind, "status": r.status_code})
        except Exception as exc:
            out.append({"channel": kind, "error": str(exc)[:200]})
    return out
