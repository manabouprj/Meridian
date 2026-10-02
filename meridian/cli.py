"""MERIDIAN command line.

  meridian demo [--serve]             fictional estate end to end: ingest -> detect -> agents -> cases (offline)
  meridian worker [--once]            ingestion worker: landing batches -> lake + streaming detections
  meridian agents [--once]            agent worker: triage / investigate queue
  meridian scheduler [--once]         correlations, approval expiry, LODESTAR push, notifications
  meridian serve [--port 8090]        API, console and MCP endpoints
  meridian syslog --source firewall   syslog / CEF receiver -> landing
  meridian query '<QuerySpec JSON>'   run a lake query (same engine and limits as the agents)
  meridian rules [--check]            list / validate detection rules
  meridian hunt --hypothesis ... [--indicator x ...]
  meridian eval [--file tests/fixtures/eval_alerts.jsonl]   score the triage agent against labelled alerts
  meridian doctor                     readiness checks with the fix for each problem
  meridian verify-audit               verify the audit hash chain
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import ROOT, ConfigError
from .ingest.queues import LocalQueue


def _rt(args, **over):
    from .runtime import Runtime
    return Runtime.load(getattr(args, "config", None), **over)


def drain_landing(rt, max_batches: int = 10_000) -> dict:
    q = rt.queue()
    totals = {"batches": 0, "events": 0, "alerts": 0, "new_alerts": 0}
    while totals["batches"] < max_batches:
        msgs = q.receive(10)
        if not msgs:
            break
        for m in msgs:
            k = None
            try:
                for k in m.keys:
                    r = rt.pipeline.process(k)
                    totals["batches"] += 1
                    totals["events"] += r.events
                    totals["alerts"] += r.alerts
                    totals["new_alerts"] += len(r.new_alerts)
            except Exception:
                logging.getLogger("meridian").exception("batch %s failed", k)
                totals["failed"] = totals.get("failed", 0) + 1
                if isinstance(q, LocalQueue) and k:  # local mode: record the failure so it is not retried forever
                    rt.store.mark_batch(k, 0, 0, errors=1)
                continue                             # cloud: not acked -> redelivered, then DLQ / poison queue
            q.ack(m)
    return totals


HEARTBEAT_ROLES = ("worker", "agents", "scheduler", "collector")


def beat(rt, role: str, _last: dict = {}) -> None:  # noqa: B006 - per-process throttle state
    """Record that a background role is alive (shown by /readyz and /metrics); at most every 30 s."""
    if time.monotonic() - _last.get(role, -1e9) < 30:
        return
    _last[role] = time.monotonic()
    try:
        rt.store.set_cursor(f"heartbeat:{role}", datetime.now(timezone.utc).isoformat())
    except Exception:                               # a heartbeat must never stop the work
        logging.getLogger("meridian").warning("heartbeat for %s failed", role)


def run_correlations(rt, catchup_minutes: int = 10, now: datetime | None = None) -> dict:
    from .detect import run_correlations as rc
    alerts, errors = rc(rt.rules, rt.engine, now=now, catchup_minutes=catchup_minutes)
    new = 0
    for a in alerts:
        try:                                         # one bad alert must not stop the others
            if rt.store.upsert_alert(a):
                rt.store.enqueue("triage", a.alert_id)
                new += 1
        except Exception as exc:
            logging.getLogger("meridian").exception("could not store correlation alert %s", a.alert_id)
            errors.append(f"{a.rule_id}: {type(exc).__name__}")
    return {"correlation_alerts": len(alerts), "new": new, "errors": errors}


async def drain_agents(rt, limit: int = 1000) -> list[dict]:
    out = []
    for _ in range(limit):
        r = await rt.agent_service.work_once()
        if r is None:
            break
        out.append(r)
    return out


def cmd_demo(args) -> int:
    import shutil

    from .demo import generate, write_context
    demo = ROOT / "data" / "demo"
    if demo.exists() and not args.keep:
        shutil.rmtree(demo)
    write_context(demo / "context")
    over = {"lake": {"root": str(demo / "lake"), "landing": str(demo / "landing"), "query_engine": "duckdb"},
            "store": {"url": f"sqlite:///{demo / 'meridian.db'}"}, "cloud": "local", "queue": {"type": "local"},
            "org": {"name": "Kestrel Logistics (Demo)", "industry": "logistics and ports",
                    "crown_jewels": ["Finance ledger", "Customer portal"]},
            "context": {"assets": str(demo / "context" / "assets.csv"), "identities": str(demo / "context" / "identities.csv"),
                        "intel_dir": str(demo / "context" / "intel")},
            "model": {"provider": "scripted"}}
    rt = _rt(args, **over)
    t = time.monotonic()
    counts = generate(rt.landing)
    print(f"generated raw records: {counts}")
    ing = drain_landing(rt)
    print(f"ingested: {ing['batches']} batches, {ing['events']} events -> lake; streaming alerts {ing['alerts']}")
    cor = run_correlations(rt, catchup_minutes=180)
    print(f"correlations: {cor['correlation_alerts']} alert(s) {('errors: ' + str(cor['errors'])) if cor['errors'] else ''}")
    results = asyncio.run(drain_agents(rt))
    tri = [r for r in results if r.get("kind") == "triage"]
    print(f"agents: {len(tri)} alerts triaged, {sum(1 for r in results if r.get('kind') == 'investigate')} case(s) investigated")
    for c in rt.store.list_cases(active_only=True):
        print(f"  [{c['severity']}] {c['case_id']} {c['status']:18s} {c['verdict'] or '-':10s} {c['title'][:80]}")
    for a in rt.store.list_approvals("pending"):
        print(f"  approval {a['approval_id']}: {a['action']} -> {a['target']}  ({a['case_id']})")
    ok, n = rt.store.verify_audit()
    print(f"audit chain {'valid' if ok else 'BROKEN'} ({n} entries) - {time.monotonic() - t:.1f}s")
    if args.serve:
        os.environ["MERIDIAN_CONFIG"] = str(_write_demo_config(over))
        if not os.environ.get("MERIDIAN_API_KEYS"):          # ephemeral demo keys, printed once, never written to disk
            import secrets
            keys = {r: secrets.token_urlsafe(24) for r in ("admin", "responder", "analyst")}
            os.environ["MERIDIAN_API_KEYS"] = ",".join(f"{r}:{k}" for r, k in keys.items())
            os.environ.setdefault("MERIDIAN_SESSION_SECRET", secrets.token_urlsafe(48))
            print("demo sign-in keys (this run only):")
            for r, k in keys.items():
                print(f"  {r:9s} {k}")
        print(f"console: http://{args.host}:{args.port}")
        return cmd_serve(args)
    return 0


def _write_demo_config(over: dict) -> Path:
    import yaml
    base = yaml.safe_load((ROOT / "config" / "meridian.yaml").read_text())
    base.update(over)
    base["security"] = {**base.get("security", {}), "secure_cookies": False}
    p = ROOT / "data" / "demo" / "meridian-demo.yaml"
    p.write_text(yaml.safe_dump(base))
    return p


def cmd_worker(args) -> int:
    rt = _rt(args)
    while True:
        beat(rt, "worker")
        try:
            tot = drain_landing(rt)
        except Exception:                           # queue / network hiccup: log, back off, keep the role alive
            logging.getLogger("meridian").exception("worker cycle failed")
            if args.once:
                raise
            time.sleep(5)
            continue
        if tot["batches"]:
            logging.getLogger("meridian").info("worker: %s", tot)
        if args.once:
            print(json.dumps(tot))
            return 0
        if not tot["batches"]:
            time.sleep(2)


def cmd_agents(args) -> int:
    rt = _rt(args)

    async def loop():
        while True:
            beat(rt, "agents")
            try:
                r = await rt.agent_service.work_once()
            except Exception:
                logging.getLogger("meridian").exception("agent cycle failed")
                if args.once:
                    raise
                await asyncio.sleep(5)
                continue
            if r is not None:
                logging.getLogger("meridian").info("agent: %s", json.dumps(r, default=str)[:400])
                continue
            if args.once:
                return
            await asyncio.sleep(2)
    asyncio.run(loop())
    return 0


def cmd_scheduler(args) -> int:
    import socket
    rt = _rt(args)
    every = int(rt.settings.section("detections").get("correlation_interval_minutes", 5)) * 60
    me = f"{socket.gethostname()}:{os.getpid()}"
    while True:
        if not rt.store.try_lock("scheduler", me, ttl_s=every * 3):   # another replica is the active scheduler
            if args.once:
                print("another scheduler holds the lock")
                return 0
            time.sleep(30)
            continue
        beat(rt, "scheduler")
        out = scheduler_cycle(rt)
        print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {json.dumps(out, default=str)}", flush=True)
        if args.once:
            return 0
        time.sleep(every)


MAX_CATCHUP_MINUTES = 24 * 60


def source_prefixes(rt) -> list[str]:
    return [(s.get("prefix") or s["key"]).strip("/") for s in rt.settings.sources]


def scheduler_cycle(rt, now: datetime | None = None) -> dict:
    """One scheduler pass. Each step is isolated: a failing step is logged and reported, the others still run.
    Correlations resume from the last evaluated time (persisted), capped at 24 h of catch-up."""
    from .integrations import notify, push_lodestar
    log = logging.getLogger("meridian")
    now = now or datetime.now(timezone.utc)
    st, out = rt.store, {}

    def step(name, fn):
        try:
            out[name] = fn()
        except Exception as exc:
            log.exception("scheduler step %s failed", name)
            out[name] = {"error": f"{type(exc).__name__}: {exc}"[:300]}

    def correlations():
        last = st.get_cursor("scheduler:correlations_until")
        gap = (now - datetime.fromisoformat(last)).total_seconds() / 60 if last else 10
        res = run_correlations(rt, catchup_minutes=int(min(max(gap, 10), MAX_CATCHUP_MINUTES)), now=now)
        if not res.get("errors"):
            st.set_cursor("scheduler:correlations_until", now.isoformat())
        return res

    def approvals():
        expired = st.expire_approvals()
        pending = st.list_approvals("pending")
        seen = set(json.loads(st.get_cursor("scheduler:notified_approvals") or "[]"))
        fresh = [a for a in pending if a["approval_id"] not in seen]
        if fresh:
            n = rt.settings.section("notify")
            notify(n, f"{len(fresh)} containment request(s) waiting for approval",
                   [f"{a['action']} -> {a['target']} ({a['case_id']}): {a['rationale'][:200]}" for a in fresh[:10]],
                   n.get("console_url"))
        # remember only approvals that are still pending, so the list never grows without bound
        st.set_cursor("scheduler:notified_approvals", json.dumps(sorted({a["approval_id"] for a in pending})))
        return {"expired": expired, "notified": len(fresh)}

    def lodestar():
        last = st.get_cursor("scheduler:lodestar_push")
        if last and (now - datetime.fromisoformat(last)).total_seconds() < 3600:
            return "not due"
        res = push_lodestar(st, rt.settings.lodestar, sources=source_prefixes(rt), context=rt.context)
        if "skipped" not in res:
            st.set_cursor("lodestar:last_status", str(res.get("status")))   # exported as a metric for alerting
        if "skipped" in res or 200 <= int(res.get("status") or 0) < 300:
            st.set_cursor("scheduler:lodestar_push", now.isoformat())   # only advance after success
        else:
            log.error("LODESTAR rejected the push (%s); retrying next cycle", res.get("status"))
        return res

    step("correlations", correlations)
    step("approvals", approvals)
    def housekeeping():
        last = st.get_cursor("scheduler:housekeeping")
        if last and (now - datetime.fromisoformat(last)).total_seconds() < 86400:
            return "not due"
        cfg = rt.settings.raw.get("store") or {}
        res = st.housekeeping(int(cfg.get("ledger_days", 120)), int(cfg.get("work_days", 30)))
        st.set_cursor("scheduler:housekeeping", now.isoformat())
        return res

    step("lodestar", lodestar)
    step("housekeeping", housekeeping)
    return out


def cmd_serve(args) -> int:
    import uvicorn
    if getattr(args, "config", None):
        os.environ["MERIDIAN_CONFIG"] = args.config
    uvicorn.run("meridian.api.app:app", host=getattr(args, "host", "127.0.0.1"), port=getattr(args, "port", 8090),
                log_level="info", proxy_headers=True)
    return 0


def cmd_syslog(args) -> int:
    from .ingest.syslog import serve
    rt = _rt(args)
    from .ingest.syslog import tls_context
    tls = tls_context(args.tls_cert, args.tls_key, args.tls_client_ca) if args.tls_port else None
    asyncio.run(serve(rt.landing, args.source, args.host, args.port, args.port, args.flush, args.tls_port, tls))
    return 0


def cmd_replay(args) -> int:
    """Re-process landing batches under a prefix (after fixing a mapper or a rule). Idempotent: lake files are
    deterministic per batch and alerts are de-duplicated, so replaying twice changes nothing."""
    rt = _rt(args)
    tot = {"batches": 0, "events": 0, "new_alerts": 0}
    for i, k in enumerate(rt.landing.list(args.prefix)):
        if i >= args.limit:
            break
        r = rt.pipeline.process(k, force=True)
        tot["batches"] += 1
        tot["events"] += r.events
        tot["new_alerts"] += len(r.new_alerts)
    print(json.dumps(tot))
    return 0


def cmd_query(args) -> int:
    from .lake import QuerySpec
    rt = _rt(args)
    spec = QuerySpec.model_validate(json.loads(args.spec))
    for row in rt.engine.run(spec):
        print(json.dumps(row, default=str))
    return 0


def cmd_collect(args) -> int:
    """API pull collectors (sources with a `pull:` block): one active replica (lease lock), each source on its own
    interval. Runs with the ingestion identity, because it writes to the landing zone."""
    import socket

    from .ingest.pull import run_due
    rt = _rt(args)
    me = f"{socket.gethostname()}:{os.getpid()}"
    while True:
        beat(rt, "collector")
        if rt.store.try_lock("collector", me, ttl_s=300):
            for r in run_due(rt):
                logging.getLogger("meridian").info("pull: %s", json.dumps(r, default=str)[:400])
        if args.once:
            return 0
        time.sleep(60)


def cmd_pull(args) -> int:
    """Run one API collector now (ignores its interval): onboarding tests and back-fills."""
    from .ingest.pull import Collector
    rt = _rt(args)
    src = next((s for s in rt.settings.sources if s["key"] == args.source and isinstance(s.get("pull"), dict)), None)
    if src is None:
        print(f"no source '{args.source}' with a pull: block")
        return 2
    if args.reset:
        rt.store.delete_cursor(f"pull:{args.source}:cursor")
    print(json.dumps(Collector(src, rt.landing, rt.store).run(), default=str))
    return 0


def cmd_map_test(args) -> int:
    """Show how a sample file normalises before a source goes live: events per OCSF class, populated columns,
    rejected records, and the first events. Nothing is written anywhere."""
    from collections import Counter

    from .ingest.landing import read_batch
    from .mappers import get_mapper
    rt = _rt(args)
    src = next((s for s in rt.settings.sources if s["key"] == args.source), None) if args.source else None
    fmt = args.format or (src or {}).get("format") or "json"
    top = {k: v for k, v in (src or {}).items() if k in ("class_uid", "class_field", "class_map", "field_map")}
    settings = {**top, **((src or {}).get("settings") or {}), "key": args.source or fmt}
    if args.timezone:
        from .mappers.common import UnknownTimeZone, zone
        try:
            zone(args.timezone)
        except UnknownTimeZone as exc:
            print(exc)
            return 2
        settings["timezone"] = args.timezone
    mapper = get_mapper(fmt)
    data = Path(args.file).read_bytes()
    n = rejected = 0
    events, classes, filled = [], Counter(), Counter()
    for rec in read_batch(args.file, data):
        n += 1
        try:
            out = mapper(rec, settings)
        except Exception as exc:
            rejected += 1
            print(f"record {n}: {type(exc).__name__}: {exc}")
            continue
        if not out:
            rejected += 1
        for ev in out:
            classes[f"{ev['class_uid']} {ev['class_name']}"] += 1
            filled.update(k for k, v in ev.items() if v not in (None, "") and k not in ("raw", "event_uid"))
            events.append(ev)
    print(f"format={fmt} records={n} events={len(events)} rejected={rejected}")
    for c, k in classes.most_common():
        print(f"  class {c}: {k}")
    print("  columns populated: " + ", ".join(f"{k}({v})" for k, v in filled.most_common()))
    for ev in events[:args.show]:
        print(json.dumps({k: v for k, v in ev.items() if v not in (None, "") and k != "raw"}, default=str))
    return 1 if n and rejected == n else 0


def cmd_rules(args) -> int:
    rt = _rt(args)
    rules = rt.rules
    errs = getattr(rt, "rule_errors", [])
    for r in rules:
        print(f"{r.kind:11s} {r.level:8s} {r.id:32s} {r.title}  [{', '.join(r.mitre)}]")
    for e in errs:
        print(f"ERROR {e}", file=sys.stderr)
    print(f"{len(rules)} rules loaded, {len(errs)} error(s)")
    return 1 if (args.check and errs) else 0


def cmd_hunt(args) -> int:
    rt = _rt(args)
    out = asyncio.run(rt.agent_service.hunt(args.hypothesis, args.indicator or [], args.hours))
    print(json.dumps(out, indent=1, default=str))
    return 0 if out["outcome"] == "ok" else 1


def evaluate(rt, rows: list[dict]) -> tuple[float, float, list[dict]]:
    """Golden-set evaluation: run the triage agent on labelled alerts; returns (accuracy, cost, per-alert results).
    Gate every model / prompt change on this (CI or the release pipeline)."""
    from .agents.runtime import run_agent
    from .models import Alert
    defn = rt.agent_service.agents["triage"]
    system = defn.system(*rt.agent_service.org_ctx)
    results: list[dict] = []

    async def go():
        async with rt.agent_service.hub_factory("triage") as hub:
            for row in rows:
                a = Alert.model_validate(row["alert"])
                res = await run_agent(defn, {"alert": json.loads(a.model_dump_json())}, rt.providers["fast"], hub,
                                      system=system, pricing=rt.agent_service.pricing)
                got = (res.output or {}).get("verdict")
                results.append({"alert": a.rule_id, "expected": row["expected"], "got": got, "ok": got in row["expected"],
                                "outcome": res.outcome, "cost": res.cost_usd})
    asyncio.run(go())
    acc = sum(r["ok"] for r in results) / max(1, len(results))
    return acc, sum(r["cost"] for r in results), results


def cmd_halt(args) -> int:
    """Kill switch for agents (no model calls; deterministic fallback keeps triage running)."""
    from .agents.definitions import DEFAULT_AGENTS
    rt = _rt(args)
    if args.agent != "all" and args.agent not in DEFAULT_AGENTS:
        print(f"unknown agent {args.agent}; one of {sorted(DEFAULT_AGENTS)} or all", file=sys.stderr)
        return 2
    key = f"halt:{args.agent}"
    if args.resume:
        rt.store.delete_cursor(key)
    else:
        rt.store.set_cursor(key, json.dumps({"by": args.by, "at": datetime.now(timezone.utc).isoformat()}))
    rt.store.audit(f"operator:{args.by}", "agent_resumed" if args.resume else "agent_halted", {"agent": args.agent})
    print(f"{args.agent}: {'resumed' if args.resume else 'HALTED'}")
    return 0


def cmd_baseline(args) -> int:
    """Print the approved-baseline table: agent, model tier, tool scope and constitution fingerprint."""
    from .agents.definitions import DEFAULT_AGENTS
    rows = [{"agent": k, "tier": d.model_tier, "tools": d.tools, "limits": d.definition()["limits"],
             "sha256": d.fingerprint()} for k, d in DEFAULT_AGENTS.items()]
    if args.json:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            print(f"{r['agent']:12s} {r['tier']:5s} {r['sha256']}  tools={','.join(r['tools'])}")
    return 0


def cmd_tune(args) -> int:
    rt = _rt(args)
    out = asyncio.run(rt.agent_service.tune(args.rule, args.days))
    print(json.dumps(out, indent=1, default=str))
    return 0 if out["outcome"] in ("ok", "skipped") else 1


def cmd_eval(args) -> int:
    rt = _rt(args)
    rows = [json.loads(line) for line in Path(args.file).read_text().splitlines() if line.strip()]
    acc, cost, results = evaluate(rt, rows)
    for r in results:
        print(f"{'PASS' if r['ok'] else 'FAIL'} {r['alert']:32s} expected {r['expected']} got {r['got']} ({r['outcome']})")
    print(f"accuracy {acc:.0%} on {len(rows)} labelled alerts, cost ${cost:.4f} (threshold {args.min_accuracy:.0%})")
    return 0 if acc >= args.min_accuracy else 1


def cmd_doctor(args) -> int:
    from .doctor import doctor
    rep = doctor(getattr(args, "config", None))
    print(rep.render())
    return 1 if rep.failed else 0


def cmd_verify_audit(args) -> int:
    ok, n = _rt(args).store.verify_audit()
    print(f"audit chain {'VALID' if ok else 'BROKEN at entry ' + str(n + 1)} ({n} entries verified)")
    return 0 if ok else 2


def main(argv=None) -> int:
    level = os.environ.get("MERIDIAN_LOG", "INFO").upper()
    if os.environ.get("MERIDIAN_LOG_FORMAT", "").lower() == "json":
        class J(logging.Formatter):
            def format(self, r):
                return json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "level": r.levelname, "logger": r.name,
                                   "msg": r.getMessage()})
        h = logging.StreamHandler()
        h.setFormatter(J())
        logging.basicConfig(level=level, handlers=[h])
    else:
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("httpx", "httpx2", "mcp.server.streamable_http_manager", "mcp.server.lowlevel.server"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    p = argparse.ArgumentParser(prog="meridian", description="MERIDIAN - SIEM-less detection and response with AI agents")
    p.add_argument("--config", help="config file (default config/meridian.yaml or $MERIDIAN_CONFIG)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--serve", action="store_true"); d.add_argument("--keep", action="store_true")
    d.add_argument("--host", default="127.0.0.1"); d.add_argument("--port", type=int, default=8090); d.set_defaults(fn=cmd_demo)
    for name, fn in (("worker", cmd_worker), ("agents", cmd_agents), ("scheduler", cmd_scheduler), ("collect", cmd_collect)):
        x = sub.add_parser(name); x.add_argument("--once", action="store_true"); x.set_defaults(fn=fn)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8090)
    s.set_defaults(fn=cmd_serve)
    sy = sub.add_parser("syslog"); sy.add_argument("--source", required=True); sy.add_argument("--host", default="0.0.0.0")
    sy.add_argument("--port", type=int, default=5514, help="plain UDP+TCP port; 0 = off")
    sy.add_argument("--tls-port", type=int, default=0, help="TLS port (RFC 5425, usually 6514); 0 = off")
    sy.add_argument("--tls-cert"); sy.add_argument("--tls-key"); sy.add_argument("--tls-client-ca", help="require client certificates from this CA")
    sy.add_argument("--flush", type=float, default=30); sy.set_defaults(fn=cmd_syslog)
    pl = sub.add_parser("pull", help="run one API collector now"); pl.add_argument("--source", required=True)
    pl.add_argument("--reset", action="store_true", help="forget the cursor (re-read from start_minutes)"); pl.set_defaults(fn=cmd_pull)
    mt = sub.add_parser("map-test", help="preview how a sample file normalises (nothing is stored)")
    mt.add_argument("--file", required=True); mt.add_argument("--source", help="use this source's format and settings")
    mt.add_argument("--format", help="mapper: " + "|".join(["cef", "cloudtrail", "entra", "json", "leef", "mde", "ocsf", "syslog", "windows"]))
    mt.add_argument("--timezone"); mt.add_argument("--show", type=int, default=3); mt.set_defaults(fn=cmd_map_test)
    q = sub.add_parser("query"); q.add_argument("spec"); q.set_defaults(fn=cmd_query)
    rp = sub.add_parser("replay"); rp.add_argument("--prefix", required=True); rp.add_argument("--limit", type=int, default=100000)
    rp.set_defaults(fn=cmd_replay)
    r = sub.add_parser("rules"); r.add_argument("--check", action="store_true"); r.set_defaults(fn=cmd_rules)
    h = sub.add_parser("hunt"); h.add_argument("--hypothesis", required=True); h.add_argument("--indicator", action="append")
    h.add_argument("--hours", type=int, default=168); h.set_defaults(fn=cmd_hunt)
    ht = sub.add_parser("halt"); ht.add_argument("--agent", required=True, help="triage | investigate | hunt | tune | all")
    ht.add_argument("--resume", action="store_true"); ht.add_argument("--by", default=os.environ.get("USER", "operator"))
    ht.set_defaults(fn=cmd_halt)
    bl = sub.add_parser("baseline"); bl.add_argument("--json", action="store_true"); bl.set_defaults(fn=cmd_baseline)
    tn = sub.add_parser("tune"); tn.add_argument("--rule", required=True); tn.add_argument("--days", type=int, default=14)
    tn.set_defaults(fn=cmd_tune)
    e = sub.add_parser("eval"); e.add_argument("--file", default=str(ROOT / "tests" / "fixtures" / "eval_alerts.jsonl"))
    e.add_argument("--min-accuracy", type=float, default=0.8); e.set_defaults(fn=cmd_eval)
    sub.add_parser("doctor").set_defaults(fn=cmd_doctor)
    sub.add_parser("verify-audit").set_defaults(fn=cmd_verify_audit)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
