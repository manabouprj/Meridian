"""Deterministic analyst that speaks the same tool-use protocol as an LLM.

Used for: tests and the offline demo; and DEGRADED MODE in production - when the model budget for the
day is spent or the model endpoint is unavailable, triage continues with these transparent rules
instead of stopping (each run is labelled provider=scripted so humans know).
It deliberately uses the same MCP tools, limits and output schemas as the LLM agents.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from . import LLMResponse

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8")]


def _public_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return not any(ip in n for n in _INTERNAL if n.version == ip.version)


def _task(messages: list[dict]) -> dict[str, Any]:
    txt = messages[0]["content"][0]["text"]
    return json.loads(txt.split("\n", 1)[1])


def _results(messages: list[dict]) -> list[tuple[str, Any]]:
    """(tool name, parsed payload) for every tool result so far, in order."""
    names = {}
    out = []
    for m in messages:
        if m["role"] == "assistant":
            for b in m["content"]:
                if b["type"] == "tool_use":
                    names[b["id"]] = b["name"]
        else:
            for b in m["content"] if isinstance(m["content"], list) else []:
                if b.get("type") == "tool_result":
                    try:
                        payload = json.loads(b["content"]) if isinstance(b["content"], str) else b["content"]
                    except ValueError:
                        payload = b["content"]
                    out.append((names.get(b["tool_use_id"], "?"), payload, bool(b.get("is_error"))))
    return out


def _qids(results) -> list[str]:
    ids = []
    for _, p, err in results:
        if isinstance(p, dict) and p.get("query_id") and not err:
            ids.append(p["query_id"])
    return ids


class ScriptedProvider:
    name = "scripted"
    model = "meridian-rules-v1"

    def __init__(self):
        self._n = 0

    def _use(self, name: str, args: dict) -> dict:
        self._n += 1
        return {"type": "tool_use", "id": f"toolu_s{self._n:05d}", "name": name, "input": args}

    async def complete(self, system: str, messages: list[dict], tools: list[dict], max_tokens: int) -> LLMResponse:
        kind = (re.search(r"AGENT: (\w+)", system) or [None, "triage"])[1]
        step = sum(1 for m in messages if m["role"] == "assistant")
        task = _task(messages)
        res = _results(messages)
        have = {t["name"] for t in tools}
        fn = {"triage": self._triage, "investigate": self._investigate, "hunt": self._hunt, "tune": self._tune}[kind]
        blocks = fn(step, task, res, have)
        return LLMResponse(blocks, "tool_use", input_tokens=0, output_tokens=0, model=self.model)

    # ------------------------------------------------------------------ triage
    def _triage(self, step, task, res, have):
        a = task.get("alert") or {}
        entity, etype = a.get("entity", ""), a.get("entity_type", "device")
        if step == 0:
            calls = [self._use("context__related_alerts", {"entity": entity, "hours": 24})]
            if etype in ("device", "dst_ip", "resource"):
                calls.append(self._use("context__lookup_asset", {"name_or_ip": entity}))
            if etype == "user":
                calls.append(self._use("context__lookup_identity", {"user": entity}))
            return calls
        if step == 1 and etype in ("user", "device", "src_ip") and "lake__entity_timeline" in have:
            t = {"user": "user", "device": "device", "src_ip": "ip"}[etype]
            return [self._use("lake__entity_timeline", {"entity_type": t, "value": entity.split(" / ")[0], "hours": 24, "limit": 50})]
        sev = int(a.get("severity", 3))
        sample = a.get("sample") or []
        ioc = any(s.get("ioc_hits") for s in sample) or "ioc" in " ".join(str(s.get("tags", "")) for s in sample)
        crown = any("crown_jewel" in str(s.get("tags", "")) or "privileged_user" in str(s.get("tags", "")) for s in sample)
        related = 0
        asset_crit = 0
        for name, p, _err in res:
            if name == "context__related_alerts" and isinstance(p, dict):
                related = len({x.get("rule_id") for x in p.get("alerts", [])} - {a.get("rule_id")})
            if name == "context__lookup_asset" and isinstance(p, dict) and p.get("found"):
                asset_crit = int(p.get("criticality") or 0)
                crown = crown or asset_crit >= 5
            if name == "context__lookup_identity" and isinstance(p, dict) and p.get("privileged"):
                crown = True
        reasons = [f"rule severity {sev}"]
        if ioc:
            reasons.append("matched a threat-intel indicator")
        if crown:
            reasons.append("involves a crown-jewel asset or privileged identity")
        if related:
            reasons.append(f"{related} other detection(s) on the same entity in 24h")
        score = sev + (1 if ioc else 0) + (1 if crown else 0) + min(2, related)
        if score >= 6 or (sev >= 5):
            verdict, nxt = "malicious", ("escalate_now" if sev >= 5 or crown else "investigate")
        elif score >= 4:
            verdict, nxt = "suspicious", "investigate"
        elif score <= 2:
            verdict, nxt = "benign", "close"
        else:
            verdict, nxt = "inconclusive", "investigate"
        conf = round(min(0.95, 0.5 + 0.08 * score), 2)
        out = {"verdict": verdict, "confidence": conf, "severity": max(1, min(5, sev + (1 if crown and verdict == "malicious" else 0))),
               "summary": f"{a.get('title')} on {entity}: {verdict} ({'; '.join(reasons)}). Rules-based triage.",
               "reasons": reasons, "evidence": [a.get("alert_id", "")] + _qids(res), "next_step": nxt,
               "mitre": a.get("mitre", [])}
        return [self._use("submit_result", out)]

    # ------------------------------------------------------------------ investigate
    def _investigate(self, step, task, res, have):
        case_id = task.get("case_id")
        if step == 0:
            return [self._use("cases__get_case", {"case_id": case_id})]
        case = next((p.get("case") for n, p, e in res if n == "cases__get_case" and isinstance(p, dict)), {}) or {}
        alerts = case.get("alerts") or []
        samples = [s for al in alerts for s in ((al.get("data") or {}).get("sample") or [])]
        users = sorted({s["user"] for s in samples if s.get("user")})[:5]
        devices = sorted({s["device"] for s in samples if s.get("device")})[:5]
        ips = sorted({s[k] for s in samples for k in ("src_ip", "dst_ip") if s.get(k) and _public_ip(s[k])})[:5]
        iocs = sorted({h.split(" (")[0] for s in samples for h in str(s.get("ioc_hits") or "").split("; ") if h})[:20]
        if step == 1:
            calls = [self._use("lake__entity_timeline", {"entity_type": "user", "value": u, "hours": 48, "limit": 50}) for u in users[:2]]
            calls += [self._use("lake__entity_timeline", {"entity_type": "device", "value": d, "hours": 48, "limit": 50}) for d in devices[:2]]
            if iocs:
                calls.append(self._use("lake__ioc_sweep", {"indicators": iocs, "hours": 168}))
            return calls or [self._use("response__list_actions", {})]
        sev = int(case.get("severity") or task.get("severity") or 3)
        malicious = (case.get("verdict") or task.get("verdict_at_triage")) == "malicious" or sev >= 5
        if step == 2:
            note = (f"Scope: users {users or '-'}, devices {devices or '-'}, public IPs {ips or '-'}. "
                    f"{len(alerts)} alert(s); verdict at triage: {case.get('verdict')}.")
            return [self._use("cases__add_case_note", {"case_id": case_id, "note": note, "evidence": _qids(res)}),
                    self._use("response__list_actions", {})]
        approvals = [p.get("approval_id") for n, p, e in res if n == "response__request_containment" and isinstance(p, dict) and not e]
        if step == 3 and malicious and "response__request_containment" in have:
            calls = []
            dev_ids = sorted({s.get("device_id") for s in samples if s.get("device_id")})
            for d in dev_ids[:1]:
                calls.append(self._use("response__request_containment", {"case_id": case_id, "action": "isolate_device", "target": d,
                                                                          "rationale": f"Malicious activity on {devices}; isolate to stop spread."}))
            for u in users[:1]:
                calls.append(self._use("response__request_containment", {"case_id": case_id, "action": "revoke_sessions", "target": u,
                                                                          "rationale": f"Account {u} involved in malicious activity; revoke sessions."}))
            for ip in ips[:1]:
                calls.append(self._use("response__request_containment", {"case_id": case_id, "action": "block_indicator", "target": ip,
                                                                          "rationale": f"External IP {ip} involved; block at the perimeter."}))
            if calls:
                return calls
        timeline = []
        for n, p, _e in res:
            if n == "lake__entity_timeline" and isinstance(p, dict):
                for r in p.get("rows", [])[:5]:
                    timeline.append({"time": str(r.get("time")), "what": f"{r.get('class_name')}: {r.get('activity_name') or ''} "
                                     f"{r.get('process_cmdline') or r.get('url') or r.get('api_operation') or r.get('message') or ''}"[:300]})
        out = {"verdict": "malicious" if malicious else (case.get("verdict") or "suspicious"),
               "confidence": 0.75 if malicious else 0.6,
               "summary": f"Case {case_id}: {case.get('title')}. Scope users={users}, devices={devices}, ips={ips}.",
               "root_cause": "Determined from correlated detections; confirm with the asset owner.",
               "scope": {"users": users, "devices": devices, "ips": ips, "domains": []},
               "timeline": sorted(timeline, key=lambda x: x["time"])[:20], "approvals_requested": [a for a in approvals if a],
               "recommendations": ["Confirm with the asset owner", "Reset credentials of affected users"] if malicious else
                                  ["Monitor; no containment needed yet"], "evidence": _qids(res)}
        return [self._use("submit_result", out)]

    # ------------------------------------------------------------------ hunt
    def _hunt(self, step, task, res, have):
        iocs = task.get("indicators") or []
        if step == 0:
            calls = []
            if iocs:
                calls.append(self._use("lake__ioc_sweep", {"indicators": iocs[:200], "hours": int(task.get("hours", 168))}))
            calls.append(self._use("lake__aggregate_events", {"group_by": ["process_name", "parent_process_name"], "classes": [1007],
                                                              "last_minutes": 60 * 24, "limit": 20}))
            return calls
        findings = []
        for n, p, _e in res:
            if n == "lake__ioc_sweep" and isinstance(p, dict) and p.get("hits"):
                for col, rows in p.get("by_column", {}).items():
                    for r in rows[:10]:
                        findings.append({"title": f"Indicator {r.get(col)} seen", "severity": 4,
                                         "entity": str(r.get("device") or r.get("user") or r.get(col)),
                                         "description": f"{r.get('event_count')} event(s) between {r.get('first_seen')} and {r.get('last_seen')}",
                                         "evidence": []})
        return [self._use("submit_result", {"summary": f"{len(findings)} finding(s) for the hunt.", "findings": findings[:25],
                                            "proposed_rules": []})]

    # ------------------------------------------------------------------ tune
    def _tune(self, step, task, res, have):
        stats = task.get("stats") or {}
        benign = stats.get("benign", 0)
        total = max(1, stats.get("total", 1))
        rec = "tune" if benign / total >= 0.8 and total >= 20 else "keep"
        return [self._use("submit_result", {"rule_id": task.get("rule_id", ""), "recommendation": rec,
                                            "rationale": f"{benign}/{total} recent alerts were judged benign.",
                                            "proposed_filter_yaml": "", "expected_reduction_pct": round(100 * benign / total, 1) if rec == "tune" else 0})]
