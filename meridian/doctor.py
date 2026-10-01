"""`meridian doctor`: readiness report - each problem with its fix."""
from __future__ import annotations

import os
import sys


class Report:
    def __init__(self):
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, level, area, msg, fix=""):
        self.rows.append((level, area, msg, fix))

    @property
    def failed(self) -> bool:
        return any(r[0] == "FAIL" for r in self.rows)

    def render(self) -> str:
        out = []
        for level, area, msg, fix in self.rows:
            out.append(f"[{level}] {area:<10} {msg}")
            if fix:
                out.append(f"       {'':<10} -> {fix}")
        n = {k: sum(1 for r in self.rows if r[0] == k) for k in ("PASS", "WARN", "FAIL")}
        out.append(f"\n{n['PASS']} passed, {n['WARN']} warnings, {n['FAIL']} failures")
        return "\n".join(out)


def doctor(config: str | None = None) -> Report:
    from .config import ConfigError
    from .runtime import Runtime
    r = Report()
    r.add("PASS" if sys.version_info >= (3, 11) else "FAIL", "runtime", f"Python {sys.version.split()[0]}", "" if sys.version_info >= (3, 11) else "use Python 3.12")
    try:
        rt = Runtime.load(config)
    except ConfigError as exc:
        r.add("FAIL", "config", str(exc), "fix config/meridian.yaml")
        return r
    s = rt.settings
    r.add("PASS", "config", f"org='{s.org}' cloud={s.cloud} engine={s.query_engine} sources={len(s.sources)}")
    try:
        rt.store.ping()
        r.add("PASS", "store", s.database_url.split("@")[-1])
    except Exception as exc:
        r.add("FAIL", "store", f"cannot open the database: {exc}", "check store.url / MERIDIAN_DATABASE_URL and network access")
    if s.cloud != "local" and s.database_url.startswith("sqlite"):
        r.add("WARN", "store", "SQLite in a cloud deployment", "use Azure Database for PostgreSQL / Aurora PostgreSQL")
    rules = rt.rules
    errs = getattr(rt, "rule_errors", [])
    r.add("FAIL" if errs else "PASS", "rules", f"{len(rules)} rules loaded" + (f", {len(errs)} error(s): {errs[:3]}" if errs else ""),
          "run `meridian rules --check`" if errs else "")
    for path in (s.lake_root, s.landing_root):
        try:
            store = rt.lake if path == s.lake_root else rt.landing
            next(iter(store.list("")), None)
            r.add("PASS", "storage", f"{path} reachable")
        except Exception as exc:
            r.add("FAIL", "storage", f"{path}: {type(exc).__name__}: {str(exc)[:120]}", "grant the workload identity read/write on the lake and landing")
    ctx = rt.context
    if not ctx.assets:
        r.add("WARN", "context", "no CMDB assets loaded - alerts cannot be tied to crown jewels", "export your CMDB to config/assets.csv (LODESTAR format)")
    else:
        r.add("PASS", "context", f"{len(ctx.assets)} assets, {len(ctx.identities)} identities, {len(ctx.iocs)} indicators")
    prov = (s.model or {}).get("provider", "scripted")
    if prov == "scripted":
        r.add("WARN", "model", "provider is 'scripted' (rules-based triage, no LLM)", "set model.provider to anthropic_foundry or anthropic_bedrock")
    else:
        r.add("PASS", "model", f"provider {prov}")
        if not (s.model or {}).get("pricing"):
            r.add("WARN", "model", "no model.pricing - spend tracking and budgets read $0", "add your price sheet under model.pricing")
    if s.security.get("require_auth", True):
        if not os.environ.get("MERIDIAN_API_KEYS") and not (s.security.get("oidc") or {}).get("issuer"):
            r.add("FAIL", "auth", "no API keys and no SSO configured", "set MERIDIAN_API_KEYS or security.oidc")
        if len(os.environ.get("MERIDIAN_SESSION_SECRET", "")) < 32:
            r.add("WARN", "auth", "MERIDIAN_SESSION_SECRET missing or short", "set 32+ random characters")
    if not os.environ.get("MERIDIAN_AGENT_TOKENS") and not s.security.get("mcp_scope_map"):
        r.add("WARN", "mcp", "no remote MCP callers configured (agents run in-process only)",
              "set MERIDIAN_AGENT_TOKENS or security.mcp_scope_map to use Foundry Agent Service / AgentCore")
    if s.response.get("dry_run", True):
        r.add("WARN", "response", "containment is dry-run (approvals are recorded, nothing is executed)",
              "set response.actions.<action>.dry_run: false after change-board approval")
    if not os.environ.get("MERIDIAN_METRICS_TOKEN"):
        r.add("WARN", "ops", "MERIDIAN_METRICS_TOKEN not set - /metrics disabled", "set it and scrape /metrics")
    return r
