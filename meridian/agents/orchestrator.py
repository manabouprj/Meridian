"""Turns alerts into decisions: triage every new alert, group into cases, investigate, request containment.

Policy (config `agents.policy`) decides what happens with each verdict; the model never decides policy.
Budget guard: when today's model spend reaches `agents.daily_budget_usd`, or the model endpoint fails,
triage continues in degraded mode with the deterministic analyst and every result is labelled.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from ..store import Store
from .definitions import DEFAULT_AGENTS, AgentDef
from .providers import Pricing, Provider
from .providers.scripted import ScriptedProvider
from .runtime import AgentResult, ToolHub, run_agent

log = logging.getLogger("meridian.agents")

DEFAULT_POLICY = {
    "auto_close_benign_min_confidence": 0.8,    # benign verdicts below this stay open for a human
    "auto_close_max_severity": 2,               # only alerts whose RULE severity is at or below this may auto-close
    "auto_close_crown_jewels": False,           # alerts touching crown-jewel assets always go to a human
    "case_min_severity": 3,                     # suspicious/malicious alerts at or above this open / join a case
    "investigate_min_severity": 4,              # investigation agent runs for cases at or above this (or malicious)
    "case_window_hours": 24,                    # alerts on the same entity within this window join the same case
}


class AgentService:
    def __init__(self, store: Store, hub_factory, providers: dict[str, Provider], settings, pricing: Pricing | None = None,
                 agents: dict[str, AgentDef] | None = None):
        self.store, self.hub_factory, self.providers, self.settings = store, hub_factory, providers, settings
        self.pricing = pricing or Pricing()
        self.agents = agents or DEFAULT_AGENTS
        cfg = settings.agents or {}
        self.policy = {**DEFAULT_POLICY, **(cfg.get("policy") or {})}
        self.daily_budget = float(cfg.get("daily_budget_usd", 50))
        self.run_budget = float(cfg.get("run_budget_usd", 2))
        org = settings.section("org")
        self.org_ctx = (settings.org, org.get("industry", "unspecified industry"), ", ".join(org.get("crown_jewels") or []))

    # ------------------------------------------------------------------ helpers
    def halted(self, kind: str) -> bool:
        """Kill switch: `meridian halt --agent <kind|all>` or POST /api/agents/<kind>/halt. A halted agent makes no
        model calls; triage continues with the deterministic analyst (labelled degraded), so detection never stops."""
        return bool(self.store.get_cursor(f"halt:{kind}") or self.store.get_cursor("halt:all"))

    def _provider(self, tier: str) -> tuple[Provider, bool]:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        if self.store.spend_since(today) >= self.daily_budget:
            return ScriptedProvider(), True
        return self.providers.get(tier) or self.providers.get("fast") or ScriptedProvider(), False

    async def _run(self, kind: str, ref: str, task: dict[str, Any]) -> AgentResult:
        defn = self.agents[kind]
        provider, degraded = self._provider(defn.model_tier)
        if self.halted(kind):
            provider, degraded = ScriptedProvider(), True
        system = defn.system(*self.org_ctx)
        started = datetime.now(timezone.utc)
        async with self.hub_factory(kind) as hub:
            try:
                res = await asyncio.wait_for(run_agent(defn, task, provider, hub, system=system, pricing=self.pricing,
                                                       budget_usd=self.run_budget), timeout=defn.timeout_s)
            except TimeoutError:
                res = AgentResult(kind, "limit", error=f"wall-clock limit of {defn.timeout_s}s reached",
                                  model=provider.model, provider=provider.name)
            if res.outcome == "failed" and "model call failed" in res.error and provider.name != "scripted":
                log.warning("%s agent: model unavailable (%s) - degraded mode", kind, res.error[:120])
                degraded = True
                res = await run_agent(defn, task, ScriptedProvider(), hub, system=system, pricing=self.pricing)
        res.degraded = degraded
        self.store.record_run(agent=kind, ref=ref, provider=res.provider + (" (degraded)" if degraded else ""), model=res.model,
                              started_at=started, ended_at=datetime.now(timezone.utc), input_tokens=res.input_tokens,
                              output_tokens=res.output_tokens, cost_usd=res.cost_usd, tool_calls=res.tool_calls,
                              outcome=res.outcome, error=res.error[:2000], transcript=res.transcript[-60:],
                              definition_sha256=defn.fingerprint())
        self.store.audit(f"agent:{kind}", "agent_run", {"ref": ref, "outcome": res.outcome, "provider": res.provider,
                                                        "degraded": degraded, "tool_calls": res.tool_calls, "cost_usd": res.cost_usd,
                                                        "definition_sha256": defn.fingerprint()})
        return res

    # ------------------------------------------------------------------ triage
    async def triage(self, alert_id: str) -> dict[str, Any]:
        a = self.store.get_alert(alert_id)
        if not a:
            return {"alert_id": alert_id, "skipped": "alert not found"}
        if a.get("verdict"):
            return {"alert_id": alert_id, "skipped": "already triaged"}
        data = a.get("data") or {}
        task = {"alert": {k: data.get(k, a.get(k)) for k in ("alert_id", "rule_id", "title", "severity", "mitre", "entity",
                                                               "entity_type", "event_count", "description", "sample")}}
        res = await self._run("triage", alert_id, task)
        if res.outcome != "ok":
            self.store.set_alert(alert_id, status="needs_human")
            return {"alert_id": alert_id, "outcome": res.outcome, "error": res.error}
        out = res.output
        p = self.policy
        status, case_id = "triaged", None
        if out["verdict"] == "benign" and self._may_auto_close(a, out, res.degraded):
            status = "closed"
        elif out["verdict"] in ("suspicious", "malicious", "inconclusive") and out["severity"] >= p["case_min_severity"]:
            ents = alert_entities(a)
            case = self.store.open_case_for(sorted(ents), p["case_window_hours"])
            if case:
                case_id = case["case_id"]
                merged = sorted(set((case.get("data") or {}).get("entities") or []) | ents)[:100]
                upd: dict[str, Any] = {"severity": max(case["severity"], out["severity"]),
                                       "data": {**(case.get("data") or {}), "entities": merged},
                                       "mitre": sorted(set(case.get("mitre") or []) | set(out.get("mitre") or []))}
                if out["verdict"] == "malicious":
                    upd["verdict"] = "malicious"
                self.store.update_case(case_id, **upd)
            else:
                case_id = self.store.create_case(f"{a['title']} - {a['entity']}", out["severity"], a["entity"], out.get("mitre") or [],
                                                 out["summary"], out["verdict"], out["confidence"], data={"entities": sorted(ents)})
            self.store.add_note(case_id, "agent:triage", "agent", out["summary"], out["evidence"])
            status = "in_case"
            if out["next_step"] in ("investigate", "escalate_now") and (
                    out["verdict"] == "malicious" or out["severity"] >= p["investigate_min_severity"]):
                self.store.enqueue("investigate", case_id)
        self.store.set_alert(alert_id, status=status, verdict=out["verdict"], confidence=out["confidence"], case_id=case_id)
        return {"alert_id": alert_id, "verdict": out["verdict"], "status": status, "case_id": case_id,
                "provider": res.provider, "cost_usd": res.cost_usd}

    # ------------------------------------------------------------------ investigate
    async def investigate(self, case_id: str) -> dict[str, Any]:
        case = self.store.get_case(case_id)
        if not case:
            return {"case_id": case_id, "skipped": "case not found"}
        self.store.update_case(case_id, status="investigating")
        res = await self._run("investigate", case_id, {"case_id": case_id, "title": case["title"], "entity": case["entity"],
                                                        "severity": case["severity"], "verdict_at_triage": case["verdict"]})
        if res.outcome != "ok":
            self.store.add_note(case_id, "agent:investigate", "system", f"Investigation agent ended: {res.outcome} {res.error}")
            return {"case_id": case_id, "outcome": res.outcome, "error": res.error}
        out = res.output
        self.store.add_note(case_id, "agent:investigate", "agent", out["summary"] + (f"\nRoot cause: {out['root_cause']}" if out["root_cause"] else ""),
                            {"evidence": out["evidence"], "scope": out["scope"], "timeline": out["timeline"],
                             "recommendations": out["recommendations"]})
        pending = [x for x in self.store.list_approvals("pending") if x["case_id"] == case_id]
        status = "awaiting_approval" if pending else ("investigating" if out["verdict"] != "benign" else "closed")
        self.store.update_case(case_id, verdict=out["verdict"], confidence=out["confidence"], status=status,
                               summary=out["summary"][:3000])
        return {"case_id": case_id, "verdict": out["verdict"], "approvals": [x["approval_id"] for x in pending],
                "provider": res.provider, "cost_usd": res.cost_usd}

    # ------------------------------------------------------------------ hunt / tune
    async def tune(self, rule_id: str, days: int = 14) -> dict[str, Any]:
        """Ask the tune agent for a recommendation on one noisy rule. Proposals are never applied automatically:
        a detection engineer reviews the proposed filter and changes the rule through a pull request."""
        recent = [a for a in self.store.list_alerts(limit=2000) if a["rule_id"] == rule_id][:50]
        if not recent:
            return {"outcome": "skipped", "result": None, "error": f"no recent alerts for rule {rule_id}"}
        task = {"rule_id": rule_id, "days": days, "alerts": [
            {k: a.get(k) for k in ("alert_id", "entity", "severity", "status", "verdict", "confidence", "event_count")}
            for a in recent]}
        res = await self._run("tune", f"tune:{rule_id}", task)
        return {"outcome": res.outcome, "result": res.output, "error": res.error}

    async def hunt(self, hypothesis: str, indicators: list[str] | None = None, hours: int = 168) -> dict[str, Any]:
        res = await self._run("hunt", "hunt", {"hypothesis": hypothesis, "indicators": indicators or [], "hours": hours})
        return {"outcome": res.outcome, "result": res.output, "error": res.error}

    def _may_auto_close(self, a: dict[str, Any], out: dict[str, Any], degraded: bool) -> bool:
        """Deterministic gate: the model's confidence is necessary but never sufficient. Severity comes from the rule
        (the model cannot lower it), crown-jewel assets always reach a human, and degraded runs never auto-close."""
        p = self.policy
        if degraded or out["confidence"] < p["auto_close_benign_min_confidence"]:
            return False
        if int(a.get("severity") or 5) > int(p["auto_close_max_severity"]):
            return False
        sample = ((a.get("data") or {}).get("sample") or [])
        if not p["auto_close_crown_jewels"] and any("crown_jewel" in str(ev.get("tags") or "") for ev in sample):
            return False
        return True

    # Lease longer than the longest run (deep agents: 1800 s wall clock) so no other replica picks the item up.
    LEASE_S = 3600

    def request_hunt(self, hypothesis: str, indicators: list[str], hours: int, requested_by: str) -> str:
        """Hunts run in the agents service (which holds the model permissions), not in the API process."""
        from ..store.db import new_id
        hunt_id = new_id("HUNT")
        self.store.set_cursor(f"hunt:{hunt_id}", json.dumps({
            "hunt_id": hunt_id, "status": "queued", "hypothesis": hypothesis, "indicators": indicators, "hours": hours,
            "requested_by": requested_by, "requested_at": datetime.now(timezone.utc).isoformat()}))
        self.store.enqueue("hunt", hunt_id)
        return hunt_id

    def get_hunt(self, hunt_id: str) -> dict[str, Any] | None:
        raw = self.store.get_cursor(f"hunt:{hunt_id}")
        return json.loads(raw) if raw else None

    async def _run_hunt(self, hunt_id: str) -> dict[str, Any]:
        h = self.get_hunt(hunt_id)
        if not h:
            return {"hunt_id": hunt_id, "skipped": "hunt not found"}
        out = await self.hunt(h["hypothesis"], h.get("indicators") or [], int(h.get("hours", 168)))
        h.update(status="done" if out["outcome"] == "ok" else "failed", finished_at=datetime.now(timezone.utc).isoformat(),
                 **out)
        self.store.set_cursor(f"hunt:{hunt_id}", json.dumps(h, default=str))
        return {"hunt_id": hunt_id, "outcome": out["outcome"]}

    async def work_once(self, worker: str = "agents") -> dict[str, Any] | None:
        item = self.store.lease(["triage", "investigate", "hunt"], worker, lease_s=self.LEASE_S)
        if not item:
            return None
        try:
            if item["kind"] == "hunt":
                out = await self._run_hunt(item["ref"])
            else:
                out = await (self.triage(item["ref"]) if item["kind"] == "triage" else self.investigate(item["ref"]))
            self.store.complete(item["id"], ok=True)
            return {"kind": item["kind"], **out}
        except Exception as exc:
            log.exception("agent work item %s failed", item["id"])
            self.store.complete(item["id"], ok=False, error=f"{type(exc).__name__}: {exc}")
            return {"kind": item["kind"], "ref": item["ref"], "error": str(exc)[:300]}


GENERIC_ENTITIES = {"", "unknown", "system", "local service", "network service", "nt authority\\system", "administrator"}


def alert_entities(a: dict[str, Any]) -> set[str]:
    """Entities an alert touches: its own entity plus users, hosts and public IPs in its sample events."""
    ents = {str(a.get("entity", "")).lower()}
    for ev in ((a.get("data") or {}).get("sample") or [])[:20]:
        for k in ("user", "device"):
            if ev.get(k):
                ents.add(str(ev[k]).lower())
    return {e for e in ents if e not in GENERIC_ENTITIES and " / " not in e} | (
        {str(a.get("entity", "")).lower()} if " / " in str(a.get("entity", "")) else set())


def default_hub_factory(toolbox, servers: dict[str, Any], scopes_by_kind: dict[str, set[str]] | None = None):
    """In-process MCP: the agent talks MCP to the servers inside this process, with the caller scoped to its role."""
    from contextlib import asynccontextmanager

    from ..mcp_servers import CALLER, Caller

    scopes = scopes_by_kind or {
        "triage": {"lake:read", "context:read"},
        "investigate": {"lake:read", "context:read", "cases:read", "cases:write", "response:request"},
        "hunt": {"lake:read", "context:read"}, "tune": {"lake:read", "context:read"},
    }
    names = {"triage": ["lake", "context"], "investigate": ["lake", "context", "cases", "response"],
             "hunt": ["lake", "context"], "tune": ["lake", "context"]}

    @asynccontextmanager
    async def factory(kind: str):
        token = CALLER.set(Caller(f"agent:{kind}", scopes[kind]))
        try:
            async with ToolHub({n: servers[n] for n in names[kind]}) as hub:
                yield hub
        finally:
            CALLER.reset(token)
    return factory
