"""Operational store: alerts, cases, approvals, agent runs, audit, work queue, cursors.

SQLAlchemy Core, so the same code runs on SQLite (single node, development) and PostgreSQL
(Azure Database for PostgreSQL / Amazon Aurora PostgreSQL in production).
The audit table is a hash chain: every row stores the hash of the previous row, so deleting or
editing a past entry is detectable (`verify_audit`).
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    create_engine,
    func,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.types import TypeDecorator

from ..models import Alert


class TStr(TypeDecorator):
    """VARCHAR(n) that truncates instead of failing: PostgreSQL enforces lengths (SQLite does not), and values such
    as entities and titles come from attacker-controlled telemetry. Comparisons are truncated the same way."""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        n = self.impl.length
        return value[:n] if isinstance(value, str) and n and len(value) > n else value


md = MetaData()

processed = Table("processed_batches", md,
                  Column("key", String(512), primary_key=True), Column("processed_at", DateTime(timezone=True)),
                  Column("events", Integer), Column("alerts", Integer), Column("errors", Integer, default=0))
alerts = Table("alerts", md,
               Column("alert_id", String(40), primary_key=True), Column("rule_id", TStr(120), index=True),
               Column("title", TStr(300)), Column("severity", Integer), Column("source", TStr(20)),
               Column("entity_type", TStr(40)), Column("entity", TStr(300), index=True),
               Column("first_seen", DateTime(timezone=True)), Column("last_seen", DateTime(timezone=True), index=True),
               Column("event_count", Integer), Column("mitre", JSON), Column("data", JSON),
               Column("status", TStr(20), default="new", index=True), Column("verdict", TStr(20)),
               Column("confidence", Float), Column("case_id", TStr(40), index=True),
               Column("created_at", DateTime(timezone=True)), Column("updated_at", DateTime(timezone=True)))
cases = Table("cases", md,
              Column("case_id", String(40), primary_key=True), Column("title", TStr(300)),
              Column("severity", Integer), Column("status", TStr(30), index=True), Column("verdict", TStr(20)),
              Column("confidence", Float), Column("entity", TStr(300), index=True), Column("summary", Text),
              Column("assignee", TStr(200)), Column("mitre", JSON), Column("data", JSON),
              Column("created_at", DateTime(timezone=True)), Column("updated_at", DateTime(timezone=True), index=True))
notes = Table("case_notes", md,
              Column("id", Integer, primary_key=True, autoincrement=True), Column("case_id", TStr(40), index=True),
              Column("author", TStr(200)), Column("kind", TStr(20)), Column("body", Text), Column("evidence", JSON),
              Column("created_at", DateTime(timezone=True)))
approvals = Table("approvals", md,
                  Column("approval_id", String(40), primary_key=True), Column("case_id", TStr(40), index=True),
                  Column("action", TStr(80)), Column("target", TStr(300)), Column("params", JSON),
                  Column("rationale", Text), Column("requested_by", TStr(200)), Column("status", TStr(20), index=True),
                  Column("decided_by", TStr(200)), Column("decided_at", DateTime(timezone=True)),
                  Column("result", JSON), Column("created_at", DateTime(timezone=True)),
                  Column("expires_at", DateTime(timezone=True)))
runs = Table("agent_runs", md,
             Column("run_id", String(40), primary_key=True), Column("agent", TStr(60), index=True),
             Column("ref", TStr(60), index=True), Column("provider", TStr(40)), Column("model", TStr(120)),
             Column("started_at", DateTime(timezone=True), index=True), Column("ended_at", DateTime(timezone=True)),
             Column("input_tokens", Integer, default=0), Column("output_tokens", Integer, default=0),
             Column("cost_usd", Float, default=0.0), Column("tool_calls", Integer, default=0),
             Column("outcome", TStr(40)), Column("error", Text), Column("transcript", JSON),
             Column("definition_sha256", TStr(64), index=True))   # agent constitution in force for this run
audit = Table("audit", md,
              Column("id", Integer, primary_key=True, autoincrement=True), Column("ts", DateTime(timezone=True), index=True),
              Column("actor", TStr(200)), Column("event", TStr(80)), Column("details", JSON),
              Column("prev_hash", TStr(64)), Column("hash", TStr(64)))
work = Table("work", md,
             Column("id", Integer, primary_key=True, autoincrement=True), Column("kind", TStr(30), index=True),
             Column("ref", TStr(60)), Column("status", TStr(20), index=True), Column("attempts", Integer, default=0),
             Column("not_before", DateTime(timezone=True)), Column("locked_by", TStr(80)),
             Column("locked_until", DateTime(timezone=True)), Column("error", Text),
             Column("created_at", DateTime(timezone=True)))
blocklist = Table("blocklist", md,
                  Column("value", String(300), primary_key=True), Column("kind", TStr(10), index=True),
                  Column("case_id", TStr(40)), Column("added_by", TStr(200)),
                  Column("added_at", DateTime(timezone=True)), Column("expires_at", DateTime(timezone=True)))
cursors = Table("cursors", md, Column("key", String(200), primary_key=True), Column("value", Text),
                Column("updated_at", DateTime(timezone=True)))

ACTIVE_CASE = ("new", "triaged", "investigating", "awaiting_approval", "contained")


def now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(d: datetime | None) -> datetime | None:
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _row(r) -> dict[str, Any]:
    d = dict(r._mapping)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = _utc(v)
    return d


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Store:
    def __init__(self, url: str, engine: Engine | None = None):
        kw: dict[str, Any] = {"future": True}
        if url.startswith("sqlite"):
            kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            kw.update(pool_pre_ping=True, pool_size=10, max_overflow=10)
        self.engine = engine or create_engine(url, **kw)
        self._audit_lock = threading.Lock()
        if url.startswith("sqlite"):
            with self.engine.begin() as c:
                c.exec_driver_sql("PRAGMA journal_mode=WAL")
        md.create_all(self.engine)

    # ------------------------------------------------------------------ batches
    def batch_done(self, key: str) -> bool:
        with self.engine.connect() as c:
            return c.execute(select(processed.c.key).where(processed.c.key == key)).first() is not None

    def mark_batch(self, key: str, events: int, alerts_n: int, errors: int = 0) -> None:
        with self.engine.begin() as c:
            if c.execute(select(processed.c.key).where(processed.c.key == key)).first():
                c.execute(update(processed).where(processed.c.key == key).values(
                    processed_at=now(), events=events, alerts=alerts_n, errors=errors))
            else:
                c.execute(insert(processed).values(key=key, processed_at=now(), events=events, alerts=alerts_n, errors=errors))

    def source_last_seen(self, prefixes: list[str]) -> dict[str, datetime | None]:
        """Most recent processed batch per source prefix - silent sources are a detection failure (PCI DSS 10.7)."""
        out: dict[str, datetime | None] = {}
        with self.engine.connect() as c:
            for p in prefixes:
                v = c.execute(select(func.max(processed.c.processed_at)).where(
                    processed.c.key.like(p.strip("/") + "/%"))).scalar()
                out[p] = _utc(v)
        return out

    def try_lock(self, name: str, holder: str, ttl_s: int) -> bool:
        """Lease-based leader lock on the cursors table (one active scheduler even with several replicas)."""
        key, t = f"lock:{name}", now()
        mine = json.dumps({"holder": holder, "until": (t + timedelta(seconds=ttl_s)).isoformat()})
        with self.engine.begin() as c:
            cur = c.execute(select(cursors.c.value).where(cursors.c.key == key)).scalar()
            if cur is None:
                try:
                    with c.begin_nested():
                        c.execute(insert(cursors).values(key=key, value=mine, updated_at=t))
                    return True
                except Exception:          # another replica inserted first
                    return False
            d = json.loads(cur)
            if d.get("holder") != holder and datetime.fromisoformat(d["until"]) > t:
                return False
            res = c.execute(update(cursors).where(and_(cursors.c.key == key, cursors.c.value == cur))
                            .values(value=mine, updated_at=t))
            return res.rowcount == 1

    # ------------------------------------------------------------------ alerts
    def upsert_alert(self, a: Alert) -> bool:
        """Insert or merge an alert. Returns True when it is new (and therefore needs triage)."""
        data = json.loads(a.model_dump_json())
        with self.engine.begin() as c:
            cur = c.execute(select(alerts).where(alerts.c.alert_id == a.alert_id)).first()
            if cur:
                cur = _row(cur)
                sample = (cur["data"] or {}).get("sample", [])
                seen = {s.get("event_uid") for s in sample}
                sample += [s for s in data["sample"] if s.get("event_uid") not in seen]
                merged = {**data, "sample": sample[:20]}
                c.execute(update(alerts).where(alerts.c.alert_id == a.alert_id).values(
                    last_seen=max(_utc(cur["last_seen"]), a.last_seen),
                    event_count=(cur["event_count"] or 0) + (a.event_count if a.source != "correlation" else 0),
                    data=merged, updated_at=now(), severity=max(cur["severity"], a.severity)))
                return False
            c.execute(insert(alerts).values(
                alert_id=a.alert_id, rule_id=a.rule_id, title=a.title, severity=a.severity, source=a.source,
                entity_type=a.entity_type, entity=a.entity, first_seen=a.first_seen, last_seen=a.last_seen,
                event_count=a.event_count, mitre=a.mitre, data=data, status="new", created_at=now(), updated_at=now()))
            return True

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as c:
            r = c.execute(select(alerts).where(alerts.c.alert_id == alert_id)).first()
        return _row(r) if r else None

    def list_alerts(self, status: str | None = None, limit: int = 200, since: datetime | None = None) -> list[dict]:
        q = select(alerts).order_by(alerts.c.last_seen.desc()).limit(limit)
        if status:
            q = q.where(alerts.c.status == status)
        if since:
            q = q.where(alerts.c.last_seen >= since)
        with self.engine.connect() as c:
            return [_row(r) for r in c.execute(q)]

    def set_alert(self, alert_id: str, **values: Any) -> None:
        with self.engine.begin() as c:
            c.execute(update(alerts).where(alerts.c.alert_id == alert_id).values(updated_at=now(), **values))

    def related_alerts(self, entity: str, hours: int = 24, exclude: str | None = None) -> list[dict]:
        since = now() - timedelta(hours=hours)
        q = select(alerts).where(and_(alerts.c.entity == entity, alerts.c.last_seen >= since)).order_by(alerts.c.last_seen)
        with self.engine.connect() as c:
            return [_row(r) for r in c.execute(q) if r.alert_id != exclude]

    # ------------------------------------------------------------------ cases
    def open_case_for(self, entities: str | list[str], hours: int = 24) -> dict[str, Any] | None:
        """Most recently updated active case that shares any entity (host, user, IP, account) with the alert."""
        wanted = {e.lower() for e in ([entities] if isinstance(entities, str) else entities) if e}
        since = now() - timedelta(hours=hours)
        q = select(cases).where(and_(cases.c.status.in_(ACTIVE_CASE), cases.c.updated_at >= since)).order_by(
            cases.c.updated_at.desc()).limit(500)
        with self.engine.connect() as c:
            for r in c.execute(q):
                row = _row(r)
                have = {str(x).lower() for x in ((row.get("data") or {}).get("entities") or [])} | {str(row["entity"]).lower()}
                if have & wanted:
                    return row
        return None

    def create_case(self, title: str, severity: int, entity: str, mitre: list[str], summary: str = "",
                    verdict: str | None = None, confidence: float | None = None, data: dict | None = None) -> str:
        cid = new_id("CASE")
        with self.engine.begin() as c:
            c.execute(insert(cases).values(case_id=cid, title=title[:300], severity=severity, status="new", verdict=verdict,
                                           confidence=confidence, entity=entity, summary=summary, mitre=mitre,
                                           data=data or {}, created_at=now(), updated_at=now()))
        self.audit("system", "case_created", {"case_id": cid, "severity": severity, "verdict": verdict, "entity": entity[:200]})
        return cid

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as c:
            r = c.execute(select(cases).where(cases.c.case_id == case_id)).first()
            if not r:
                return None
            out = _row(r)
            out["alerts"] = [_row(x) for x in c.execute(select(alerts).where(alerts.c.case_id == case_id).order_by(alerts.c.first_seen))]
            out["notes"] = [_row(x) for x in c.execute(select(notes).where(notes.c.case_id == case_id).order_by(notes.c.id))]
            out["approvals"] = [_row(x) for x in c.execute(select(approvals).where(approvals.c.case_id == case_id).order_by(approvals.c.created_at))]
        return out

    def list_cases(self, status: str | None = None, limit: int = 200, active_only: bool = False) -> list[dict]:
        q = select(cases).order_by(cases.c.severity.desc(), cases.c.updated_at.desc()).limit(limit)
        if status:
            q = q.where(cases.c.status == status)
        elif active_only:
            q = q.where(cases.c.status.in_(ACTIVE_CASE))
        with self.engine.connect() as c:
            return [_row(r) for r in c.execute(q)]

    def update_case(self, case_id: str, **values: Any) -> None:
        with self.engine.begin() as c:
            c.execute(update(cases).where(cases.c.case_id == case_id).values(updated_at=now(), **values))
        # audit what changed (status, verdict, severity, assignee ...), not bulky data blobs
        self.audit("system", "case_updated", {"case_id": case_id, **{k: v for k, v in values.items()
                                                                      if k in ("status", "verdict", "severity",
                                                                               "assignee", "confidence")}})

    def add_note(self, case_id: str, author: str, kind: str, body: str, evidence: list | dict | None = None) -> None:
        with self.engine.begin() as c:
            c.execute(insert(notes).values(case_id=case_id, author=author[:200], kind=kind, body=body[:20000],
                                           evidence=evidence or [], created_at=now()))
            c.execute(update(cases).where(cases.c.case_id == case_id).values(updated_at=now()))

    # ------------------------------------------------------------------ approvals
    def request_approval(self, case_id: str, action: str, target: str, params: dict, rationale: str,
                         requested_by: str, ttl_hours: int = 24) -> str:
        with self.engine.begin() as c:
            dup = c.execute(select(approvals.c.approval_id).where(and_(
                approvals.c.case_id == case_id, approvals.c.action == action, approvals.c.target == target,
                approvals.c.status.in_(("pending", "approved", "executed"))))).first()
            if dup:
                return dup[0]
            aid = new_id("APR")
            c.execute(insert(approvals).values(approval_id=aid, case_id=case_id, action=action, target=target[:300],
                                               params=params, rationale=rationale[:4000], requested_by=requested_by,
                                               status="pending", created_at=now(), expires_at=now() + timedelta(hours=ttl_hours)))
            c.execute(update(cases).where(cases.c.case_id == case_id).values(status="awaiting_approval", updated_at=now()))
        return aid

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as c:
            r = c.execute(select(approvals).where(approvals.c.approval_id == approval_id)).first()
        return _row(r) if r else None

    def list_approvals(self, status: str | None = "pending") -> list[dict]:
        q = select(approvals).order_by(approvals.c.created_at.desc()).limit(500)
        if status:
            q = q.where(approvals.c.status == status)
        with self.engine.connect() as c:
            return [_row(r) for r in c.execute(q)]

    def decide_approval(self, approval_id: str, status: str, decided_by: str) -> bool:
        """Atomically move a pending, unexpired approval to approved / rejected. False if it was not pending."""
        with self.engine.begin() as c:
            res = c.execute(update(approvals).where(and_(
                approvals.c.approval_id == approval_id, approvals.c.status == "pending",
                or_(approvals.c.expires_at.is_(None), approvals.c.expires_at > now()))).values(
                status=status, decided_by=decided_by, decided_at=now()))
            return res.rowcount == 1

    def finish_approval(self, approval_id: str, status: str, result: dict) -> None:
        with self.engine.begin() as c:
            c.execute(update(approvals).where(approvals.c.approval_id == approval_id).values(status=status, result=result))

    def expire_approvals(self) -> int:
        with self.engine.begin() as c:
            return c.execute(update(approvals).where(and_(approvals.c.status == "pending", approvals.c.expires_at <= now()))
                             .values(status="expired")).rowcount

    # ------------------------------------------------------------------ agent runs
    def record_run(self, **values: Any) -> str:
        rid = values.pop("run_id", None) or new_id("RUN")
        with self.engine.begin() as c:
            c.execute(insert(runs).values(run_id=rid, **values))
        return rid

    def spend_since(self, since: datetime, agent: str | None = None) -> float:
        q = select(func.coalesce(func.sum(runs.c.cost_usd), 0.0)).where(runs.c.started_at >= since)
        if agent:
            q = q.where(runs.c.agent == agent)
        with self.engine.connect() as c:
            return float(c.execute(q).scalar() or 0.0)

    def list_runs(self, limit: int = 100, ref: str | None = None) -> list[dict]:
        q = select(runs).order_by(runs.c.started_at.desc()).limit(limit)
        if ref:
            q = q.where(runs.c.ref == ref)
        with self.engine.connect() as c:
            return [_row(r) for r in c.execute(q)]

    # ------------------------------------------------------------------ audit (hash chain)
    def audit(self, actor: str, event: str, details: dict | None = None) -> None:
        details = json.loads(json.dumps(details or {}, default=str))
        # The chain needs one writer at a time: a process lock (threads) plus, on PostgreSQL, a transaction-scoped
        # advisory lock (api, worker, agents and scheduler are separate processes writing to the same chain).
        with self._audit_lock, self.engine.begin() as c:
            if self.engine.dialect.name == "postgresql":
                c.exec_driver_sql("SELECT pg_advisory_xact_lock(7316290041)")
            prev = c.execute(select(audit.c.hash).order_by(audit.c.id.desc()).limit(1)).scalar() or "0" * 64
            ts = now()
            h = hashlib.sha256(f"{prev}|{ts.isoformat()}|{actor}|{event}|{json.dumps(details, sort_keys=True)}".encode()).hexdigest()
            c.execute(insert(audit).values(ts=ts, actor=actor[:200], event=event[:80], details=details, prev_hash=prev, hash=h))

    def verify_audit(self) -> tuple[bool, int]:
        prev = "0" * 64
        n = 0
        with self.engine.connect() as c:
            for r in c.execute(select(audit).order_by(audit.c.id)):
                ts = _utc(r.ts)
                h = hashlib.sha256(f"{prev}|{ts.isoformat()}|{r.actor}|{r.event}|{json.dumps(r.details, sort_keys=True)}".encode()).hexdigest()
                if r.prev_hash != prev or r.hash != h:
                    return False, n
                prev, n = r.hash, n + 1
        return True, n

    def recent_audit(self, limit: int = 200) -> list[dict]:
        with self.engine.connect() as c:
            return [_row(r) for r in c.execute(select(audit).order_by(audit.c.id.desc()).limit(limit))]

    # ------------------------------------------------------------------ work queue (lease-based)
    def enqueue(self, kind: str, ref: str, delay_s: int = 0) -> None:
        with self.engine.begin() as c:
            if c.execute(select(work.c.id).where(and_(work.c.kind == kind, work.c.ref == ref,
                                                      work.c.status.in_(("queued", "running"))))).first():
                return
            c.execute(insert(work).values(kind=kind, ref=ref, status="queued", attempts=0,
                                          not_before=now() + timedelta(seconds=delay_s), created_at=now()))

    def lease(self, kinds: list[str], worker: str, lease_s: int = 600) -> dict[str, Any] | None:
        t = now()
        with self.engine.begin() as c:
            cand = c.execute(select(work).where(and_(work.c.kind.in_(kinds), or_(
                and_(work.c.status == "queued", work.c.not_before <= t),
                and_(work.c.status == "running", work.c.locked_until < t)))).order_by(work.c.id).limit(1)).first()
            if not cand:
                return None
            res = c.execute(update(work).where(and_(work.c.id == cand.id, work.c.status == cand.status,
                                                    or_(work.c.locked_until.is_(None), work.c.locked_until == cand.locked_until)))
                            .values(status="running", locked_by=worker, locked_until=t + timedelta(seconds=lease_s),
                                    attempts=work.c.attempts + 1))
            if res.rowcount != 1:
                return None
            return _row(cand) | {"attempts": (cand.attempts or 0) + 1}

    def complete(self, work_id: int, ok: bool, error: str = "", retry_s: int = 300, max_attempts: int = 3) -> None:
        with self.engine.begin() as c:
            r = c.execute(select(work).where(work.c.id == work_id)).first()
            if ok:
                c.execute(update(work).where(work.c.id == work_id).values(status="done", locked_until=None, error=None))
            elif r and (r.attempts or 0) >= max_attempts:
                c.execute(update(work).where(work.c.id == work_id).values(status="failed", error=error[:2000], locked_until=None))
            else:
                c.execute(update(work).where(work.c.id == work_id).values(
                    status="queued", error=error[:2000], locked_until=None, not_before=now() + timedelta(seconds=retry_s)))

    def queue_depth(self) -> dict[str, int]:
        with self.engine.connect() as c:
            rows = c.execute(select(work.c.kind, work.c.status, func.count()).group_by(work.c.kind, work.c.status))
            return {f"{k}:{s}": n for k, s, n in rows}

    # ------------------------------------------------------------------ block list (served as EDL)
    def add_block(self, value: str, kind: str, case_id: str, added_by: str, ttl_days: int = 30) -> None:
        with self.engine.begin() as c:
            c.execute(blocklist.delete().where(blocklist.c.value == value))
            c.execute(insert(blocklist).values(value=value, kind=kind, case_id=case_id, added_by=added_by, added_at=now(),
                                               expires_at=now() + timedelta(days=ttl_days)))

    def list_blocks(self, kind: str) -> list[str]:
        with self.engine.connect() as c:
            return [r[0] for r in c.execute(select(blocklist.c.value).where(and_(
                blocklist.c.kind == kind, blocklist.c.expires_at > now())).order_by(blocklist.c.value))]

    # ------------------------------------------------------------------ cursors
    def get_cursor(self, key: str) -> str | None:
        with self.engine.connect() as c:
            return c.execute(select(cursors.c.value).where(cursors.c.key == key)).scalar()

    def set_cursor(self, key: str, value: str) -> None:
        with self.engine.begin() as c:
            if c.execute(select(cursors.c.key).where(cursors.c.key == key)).first():
                c.execute(update(cursors).where(cursors.c.key == key).values(value=value, updated_at=now()))
            else:
                c.execute(insert(cursors).values(key=key, value=value, updated_at=now()))

    def delete_cursor(self, key: str) -> None:
        with self.engine.begin() as c:
            c.execute(cursors.delete().where(cursors.c.key == key))

    # ------------------------------------------------------------------ housekeeping
    def housekeeping(self, ledger_days: int = 120, work_days: int = 30) -> dict[str, int]:
        """Delete bookkeeping that has outlived its purpose. Never touches alerts, cases, approvals, runs or the audit
        chain. processed_batches only protects landing batches from double processing, and landing expires after 90
        days, so the ledger is kept a little longer (ledger_days) and then removed."""
        out = {}
        with self.engine.begin() as c:
            out["processed_batches"] = c.execute(processed.delete().where(
                processed.c.processed_at < now() - timedelta(days=ledger_days))).rowcount
            out["work"] = c.execute(work.delete().where(and_(work.c.status == "done",
                                                             work.c.created_at < now() - timedelta(days=work_days)))).rowcount
        return out

    def ingest_quality(self, hours: int = 24) -> dict[str, dict[str, int]]:
        """Per source prefix: events stored and records rejected by the mapper in the last `hours`."""
        out: dict[str, dict[str, int]] = {}
        with self.engine.connect() as c:
            for key, ev, err in c.execute(select(processed.c.key, processed.c.events, processed.c.errors).where(
                    processed.c.processed_at >= now() - timedelta(hours=hours))):
                d = out.setdefault(key.split("/", 1)[0], {"events": 0, "rejected": 0, "batches": 0})
                d["events"] += ev or 0
                d["rejected"] += err or 0
                d["batches"] += 1
        return out

    def ping(self) -> bool:
        with self.engine.connect() as c:
            return c.exec_driver_sql("SELECT 1").scalar() == 1
