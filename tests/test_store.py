"""Audit chain, work queue leases, approvals (expiry, double decision, four-eyes, execution)."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from meridian.response import ApprovalError, decide
from meridian.store import Store
from meridian.store.db import approvals, audit


def test_audit_chain_detects_tampering(tmp_path):
    s = Store(f"sqlite:///{tmp_path}/a.db")
    for i in range(5):
        s.audit("u", "e", {"i": i})
    assert s.verify_audit() == (True, 5)
    with s.engine.begin() as c:
        c.execute(update(audit).where(audit.c.id == 3).values(details={"i": 99}))
    ok, n = s.verify_audit()
    assert not ok and n == 2


def test_work_queue_lease_retry(tmp_path):
    s = Store(f"sqlite:///{tmp_path}/w.db")
    s.enqueue("triage", "A1")
    s.enqueue("triage", "A1")                                   # de-duplicated while queued
    item = s.lease(["triage"], "w1", lease_s=60)
    assert item and s.lease(["triage"], "w2") is None           # leased to one worker only
    s.complete(item["id"], ok=False, error="boom", retry_s=0)
    item2 = s.lease(["triage"], "w2")
    assert item2["attempts"] == 2
    s.complete(item2["id"], ok=True)
    assert s.queue_depth() == {"triage:done": 1}


def test_approval_rules(tmp_path):
    s = Store(f"sqlite:///{tmp_path}/p.db")
    cid = s.create_case("t", 4, "ws1", [])
    aid = s.request_approval(cid, "block_indicator", "203.0.113.9", {}, "why", "agent:investigate")
    with pytest.raises(ApprovalError):
        decide(s, aid, True, "jane", "analyst", {})                      # role too low
    out = decide(s, aid, True, "jane", "responder", {"actions": {"block_indicator": {"dry_run": False}}})
    assert out["status"] == "executed" and s.list_blocks("ip") == ["203.0.113.9"]
    with pytest.raises(ApprovalError) as e:
        decide(s, aid, False, "bob", "responder", {})                    # already decided
    assert e.value.code == 409
    aid2 = s.request_approval(cid, "revoke_sessions", "x@corp.example", {}, "why", "jane")
    with pytest.raises(ApprovalError):
        decide(s, aid2, True, "jane", "admin", {})                      # four-eyes: requester cannot approve
    aid3 = s.request_approval(cid, "disable_user", "y@corp.example", {}, "why", "agent:investigate")
    with s.engine.begin() as c:
        c.execute(update(approvals).where(approvals.c.approval_id == aid3).values(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
    with pytest.raises(ApprovalError):
        decide(s, aid3, True, "jane", "responder", {})
    assert s.expire_approvals() == 1
    dry = decide(s, aid2, True, "bob", "responder", {"dry_run": True})
    assert dry["result"]["dry_run"] is True and "revokeSignInSessions" in dry["result"]["request"]["url"]


def test_scheduler_leader_lock_and_source_health(tmp_path):
    import time as _t

    from meridian.store import Store
    st = Store(f"sqlite:///{tmp_path / 's.db'}")
    assert st.try_lock("scheduler", "a", ttl_s=60)
    assert not st.try_lock("scheduler", "b", ttl_s=60)      # held by a
    assert st.try_lock("scheduler", "a", ttl_s=1)           # a renews (short lease)
    _t.sleep(1.2)
    assert st.try_lock("scheduler", "b", ttl_s=60)          # expired -> b takes over
    st.mark_batch("firewall/2026/10/01/x.log.gz", 10, 0)
    seen = st.source_last_seen(["firewall", "proxy"])
    assert seen["firewall"] is not None and seen["proxy"] is None


def test_lodestar_coverage_is_measured_not_assumed(tmp_path):
    from meridian.integrations import lodestar_payload
    from meridian.store import Store
    st = Store(f"sqlite:///{tmp_path / 's.db'}")
    st.mark_batch("firewall/2026/10/01/x.log.gz", 10, 0)
    h = lodestar_payload(st, sources=["firewall", "proxy", "mde", "entra"])["health"]
    assert h["coverage_pct"] == 25 and h["kpis"]["log_sources_silent"] == 3


def test_roadmap_issues_are_consistent():
    """docs/roadmap/issues.json drives scripts/create_roadmap_issues.ps1; ROADMAP.md must list every item."""
    import json

    from conftest import ROOT
    data = json.loads((ROOT / "docs" / "roadmap" / "issues.json").read_text())
    md = (ROOT / "docs" / "ROADMAP.md").read_text()
    titles = [i["title"] for i in data["issues"]]
    assert len(titles) == len(set(titles))
    for i in data["issues"]:
        assert i["milestone"] in data["milestones"] and i["phase"] in range(6)
        assert i["area"] in {"infra", "ingestion", "detection", "ai", "integration", "ux", "compliance", "security", "repo"}
        assert i["title"] in md
        assert all('"' not in str(v) for v in i.values())        # Windows PowerShell 5.1 mangles quotes in native args
