"""Run detections: per-event rules on each ingested batch, correlation rules on the lake on a schedule.

Alert identity = rule + entity + time bucket (the rule's suppress window), so repeated matches
inside the window update one alert instead of flooding analysts and agents.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from ..lake.query import QuerySpec
from ..models import Alert, sample_event
from .sigma import Rule, RuleError, selection_to_where


def _bucket(t: datetime, minutes: int) -> str:
    epoch = int(t.timestamp()) // (max(1, minutes) * 60)
    return str(epoch)


class StreamDetector:
    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if r.kind == "stream"]

    def evaluate(self, events: list[dict[str, Any]]) -> list[Alert]:
        hits: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        by_rule = {r.id: r for r in self.rules}
        for ev in events:
            for r in self.rules:
                if r.classes and ev.get("class_uid") not in r.classes:
                    continue
                try:
                    ok = r.match(ev)
                except Exception:          # a broken rule must never stop the pipeline
                    ok = False
                if ok:
                    entity = str(ev.get(r.entity) or ev.get("device") or ev.get("user") or ev.get("src_ip") or "unknown")
                    hits[(r.id, entity, _bucket(ev["time"], r.suppress_minutes))].append(ev)
        alerts = []
        for (rid, entity, bucket), evs in hits.items():
            r = by_rule[rid]
            evs.sort(key=lambda e: e["time"])
            alerts.append(Alert(
                alert_id=Alert.make_id(rid, entity, bucket), rule_id=rid, title=r.title,
                severity=max(r.severity, max(int(e.get("severity_id") or 0) for e in evs) if rid == "vendor-detection" else r.severity),
                mitre=r.mitre, source="vendor" if rid == "vendor-detection" else "stream", entity_type=r.entity,
                entity=entity, first_seen=evs[0]["time"], last_seen=evs[-1]["time"], event_count=len(evs),
                sample=[sample_event(e) for e in evs[:20]], description=r.description, tags=r.tags))
        return alerts


def correlation_spec(rule: Rule, rules_by_id: dict[str, Rule], now: datetime) -> QuerySpec:
    c = rule.correlation
    base = dict(rule.query or {})
    if not base and c.get("rules"):
        ref = rules_by_id.get(c["rules"][0])
        if ref is None or ref.kind != "stream":
            raise RuleError(f"{rule.id}: correlation references unknown stream rule {c['rules'][0]}")
        sels = [v for k, v in ref.detection.items() if k != "condition"]
        if len(sels) != 1 or not isinstance(sels[0], dict):
            raise RuleError(f"{rule.id}: referenced rule must have exactly one map selection to run on the lake")
        base = {"classes": ref.classes, "where": selection_to_where(sels[0])}
    cond = c["condition"]
    threshold = cond.get("gte") or (cond.get("gt", 0) + 1 if "gt" in cond else None)
    spec = QuerySpec(classes=base.get("classes") or rule.classes, where=base.get("where") or [],
                     since=now - timedelta(minutes=c["minutes"]), until=now, group_by=c["group_by"],
                     count_distinct=cond.get("field") if c["type"] == "value_count" else None,
                     having_min_count=threshold if c["type"] == "event_count" else None,
                     order_by="distinct_count" if c["type"] == "value_count" else "event_count", limit=500)
    return spec


def _passes(rule: Rule, row: dict[str, Any]) -> bool:
    c = rule.correlation
    cond = c["condition"]
    n = float(row.get("distinct_count") if c["type"] == "value_count" else row.get("event_count") or 0)
    if "gte" in cond and n < cond["gte"]:
        return False
    if "gt" in cond and n <= cond["gt"]:
        return False
    if "lte" in cond and n > cond["lte"]:
        return False
    if "lt" in cond and n >= cond["lt"]:
        return False
    return True


def run_correlations(rules: list[Rule], engine, now: datetime | None = None, catchup_minutes: int = 0,
                     step_minutes: int = 5) -> tuple[list[Alert], list[str]]:
    """Evaluate correlation rules for the window ending now. With catchup_minutes, also evaluate windows ending
    every step_minutes over that period (after downtime, or on first start) - alert ids de-duplicate overlaps."""
    now = now or datetime.now(timezone.utc)
    ends = [now - timedelta(minutes=m) for m in range(0, max(0, catchup_minutes) + 1, max(1, step_minutes))]
    alerts: dict[str, Alert] = {}
    errors: list[str] = []
    for end in sorted(ends):
        a, e = _correlate_at(rules, engine, end)
        for x in a:
            alerts.setdefault(x.alert_id, x)
        errors += [m for m in e if m not in errors]
    return list(alerts.values()), errors


def _correlate_at(rules: list[Rule], engine, now: datetime) -> tuple[list[Alert], list[str]]:
    by_id = {r.id: r for r in rules}
    alerts, errors = [], []
    for r in rules:
        if r.kind != "correlation":
            continue
        try:
            rows = engine.run(correlation_spec(r, by_id, now), now=now)
        except Exception as exc:
            errors.append(f"{r.id}: {exc}")
            continue
        for row in rows:
            if not _passes(r, row):
                continue
            entity = " / ".join(str(row.get(g)) for g in r.correlation["group_by"])
            metric = row.get("distinct_count") if r.correlation["type"] == "value_count" else row.get("event_count")
            alerts.append(Alert(
                alert_id=Alert.make_id(r.id, entity, _bucket(now, max(r.suppress_minutes, r.correlation["minutes"]))),
                rule_id=r.id, title=r.title, severity=r.severity, mitre=r.mitre, source="correlation",
                entity_type=r.correlation["group_by"][0], entity=entity,
                first_seen=_dt(row.get("first_seen")) or now, last_seen=_dt(row.get("last_seen")) or now,
                event_count=int(row.get("event_count") or 0),
                sample=[{k: v for k, v in row.items()}], tags=r.tags,
                description=f"{r.description} ({r.correlation['type']} = {metric} in {r.correlation['minutes']} min)"))
    return alerts, errors


def _dt(v: Any) -> datetime | None:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str) and v:
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" UTC", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None
