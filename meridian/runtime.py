"""Builds the running system from configuration (shared by API, workers, scheduler and CLI)."""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

from .config import Settings, load_settings


@dataclass
class Runtime:
    settings: Settings

    @classmethod
    def load(cls, path: str | None = None, **overrides: Any) -> "Runtime":
        return cls(load_settings(path, overrides or None))

    @cached_property
    def store(self):
        from .store import Store
        return Store(self.settings.database_url)

    @cached_property
    def landing(self):
        from .lake import open_store
        return open_store(self.settings.landing_root)

    @cached_property
    def lake(self):
        from .lake import open_store
        return open_store(self.settings.lake_root)

    @cached_property
    def engine(self):
        from .lake.engines import open_engine
        return open_engine(self.settings)

    @cached_property
    def context(self):
        from .context import Context
        c = self.settings.section("context")
        p = lambda k, d: self.settings.path(c.get(k, d)) if c.get(k, d) else None  # noqa: E731
        return Context.load(p("assets", "config/assets.csv"), p("identities", "config/identities.csv"),
                            p("intel_dir", "config/intel"))

    @cached_property
    def rules(self):
        from .detect import load_rules
        dirs = [self.settings.path(d) for d in (self.settings.section("detections").get("paths") or ["config/rules"])]
        rules, errors = load_rules(dirs)
        disabled = set(self.settings.section("detections").get("disabled") or [])
        self.rule_errors = errors
        return [r for r in rules if r.id not in disabled]

    @cached_property
    def pipeline(self):
        from .detect import StreamDetector
        from .ingest import Pipeline
        return Pipeline(self.settings.sources, self.landing, self.lake, self.store, self.context, StreamDetector(self.rules))

    @cached_property
    def toolbox(self):
        from .mcp_servers import Toolbox
        return Toolbox(self.store, self.engine, self.context, {
            **(self.settings.agents.get("limits") or {}),
            "allowed_actions": self.settings.response.get("allowed_actions"),
            "approval_ttl_hours": self.settings.response.get("approval_ttl_hours", 24)})

    @cached_property
    def mcp_servers(self):
        from .mcp_servers import build_servers
        return build_servers(self.toolbox)

    @cached_property
    def providers(self) -> dict[str, Any]:
        from .agents.providers import make_provider
        m = self.settings.model or {}
        base = {k: v for k, v in m.items() if k not in ("fast", "deep", "pricing")}
        out = {}
        for tier in ("fast", "deep"):
            cfg = {**base, **(m.get(tier) or {})}
            out[tier] = make_provider(cfg)
        return out

    @cached_property
    def agent_service(self):
        from .agents import AgentService, default_hub_factory
        from .agents.providers import Pricing
        pricing = Pricing({k: tuple(v) for k, v in ((self.settings.model or {}).get("pricing") or {}).items()})
        return AgentService(self.store, default_hub_factory(self.toolbox, self.mcp_servers), self.providers,
                            self.settings, pricing)

    def queue(self):
        from .ingest import open_queue
        return open_queue(self.settings, self.landing, self.store)

    def path(self, p: str) -> Path:
        return self.settings.path(p)
