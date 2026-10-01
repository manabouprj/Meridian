"""The ingestion worker: landing batch -> OCSF-flat -> enrich -> lake (Parquet) -> streaming detections -> alerts.

Runs as a horizontally scaled worker (Azure Container Apps job scaled by the storage queue, or an
ECS Fargate service scaled by SQS depth). No LLM is involved here: ingestion and first-line
detection are deterministic, cheap and auditable. Agents only see alerts and targeted query results.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from ..context import Context
from ..detect import StreamDetector
from ..lake import ObjectStore, write_events
from ..mappers import get_mapper
from ..store import Store
from .landing import read_batch

log = logging.getLogger("meridian.ingest")


@dataclass
class BatchResult:
    key: str
    source: str | None
    records: int = 0
    events: int = 0
    rejected: int = 0
    alerts: int = 0
    new_alerts: list[str] = field(default_factory=list)
    lake_files: list[str] = field(default_factory=list)
    skipped: str | None = None


class Pipeline:
    def __init__(self, sources: list[dict[str, Any]], landing: ObjectStore, lake: ObjectStore, store: Store,
                 context: Context, detector: StreamDetector, max_events_per_batch: int = 500_000):
        self.sources = sorted([s for s in sources if s.get("enabled", True)],
                              key=lambda s: -len(s.get("prefix") or s["key"]))
        self.landing, self.lake, self.store, self.ctx, self.detector = landing, lake, store, context, detector
        self.max_events = max_events_per_batch

    def source_for(self, key: str) -> dict[str, Any] | None:
        for s in self.sources:
            prefix = (s.get("prefix") or s["key"]).strip("/") + "/"
            if key.startswith(prefix):
                return s
        return None

    def process(self, key: str, force: bool = False) -> BatchResult:
        src = self.source_for(key)
        res = BatchResult(key=key, source=src["key"] if src else None)
        if src is None:
            res.skipped = "no source configured for this prefix"
            self.store.mark_batch(key, 0, 0, errors=1)
            return res
        if not force and self.store.batch_done(key):
            res.skipped = "already processed"
            return res
        mapper = get_mapper(src.get("format", "json"))
        # mapper options live under `settings:`; top-level class_uid / field_map ... are accepted too (common slip)
        top = {k: v for k, v in src.items() if k in ("class_uid", "class_field", "class_map", "field_map")}
        settings = {**top, **(src.get("settings") or {}), "key": src["key"]}
        events: list[dict[str, Any]] = []
        for rec in read_batch(key, self.landing.get(key)):
            res.records += 1
            try:
                mapped = mapper(rec, settings)
            except Exception as exc:          # one malformed record never blocks the batch
                res.rejected += 1
                if res.rejected <= 3:
                    log.warning("mapper %s rejected a record in %s: %s", src.get("format"), key, exc)
                continue
            if not mapped:
                res.rejected += 1
            for ev in mapped:
                events.append(self.ctx.enrich(ev))
            if len(events) > self.max_events:
                raise RuntimeError(f"batch {key} exceeds {self.max_events} events - split the producer's batches")
        # de-duplicate inside the batch (vendors re-send)
        seen, unique = set(), []
        for ev in events:
            if ev["event_uid"] not in seen:
                seen.add(ev["event_uid"])
                unique.append(ev)
        res.events = len(unique)
        batch_id = hashlib.sha256(key.encode()).hexdigest()[:24]
        if unique:
            res.lake_files = write_events(self.lake, unique, batch_id)
        for a in self.detector.evaluate(unique):
            res.alerts += 1
            if self.store.upsert_alert(a):
                res.new_alerts.append(a.alert_id)
                self.store.enqueue("triage", a.alert_id)
        self.store.mark_batch(key, res.events, res.alerts, errors=res.rejected)
        return res
