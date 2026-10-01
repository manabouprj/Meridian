"""API: auth, CSRF, roles, approvals, EDL, signed ingest, metrics, MCP gate."""
import gzip
import hashlib
import hmac
import json
import time

import pytest
import yaml
from conftest import ROOT, demo_overrides
from fastapi.testclient import TestClient

ADMIN, RESP, ANALYST = "a" * 32, "r" * 32, "n" * 32


@pytest.fixture
def client(demo_rt, monkeypatch, tmp_path):
    from meridian.api import app as appmod
    cfg = yaml.safe_load((ROOT / "config" / "meridian.yaml").read_text())
    cfg.update(demo_overrides(demo_rt.base))
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv("MERIDIAN_CONFIG", str(p))
    monkeypatch.setenv("MERIDIAN_API_KEYS", f"admin:{ADMIN},responder:{RESP},analyst:{ANALYST}")
    monkeypatch.setenv("MERIDIAN_INGEST_SECRET", "s" * 32)
    monkeypatch.setenv("MERIDIAN_EDL_TOKEN", "e" * 24)
    monkeypatch.setenv("MERIDIAN_METRICS_TOKEN", "m" * 24)
    monkeypatch.setenv("MERIDIAN_AGENT_TOKENS", "triage:" + "t" * 32 + ":lake:read+context:read")
    appmod.reset()
    appmod._MCP_APPS.clear()
    with TestClient(appmod.app, base_url="https://testserver") as c:
        yield c
    appmod.reset()
    appmod._MCP_APPS.clear()


def test_auth_roles_and_console(client):
    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/cases", headers={"X-API-Key": ANALYST}).status_code == 200
    assert client.get("/api/audit", headers={"X-API-Key": ANALYST}).status_code == 403
    audit = client.get("/api/audit", headers={"X-API-Key": ADMIN}).json()
    assert audit["chain_valid"] is True
    assert client.get("/", follow_redirects=False).status_code in (302, 307)
    assert "MERIDIAN" in client.get("/", headers={"X-API-Key": ANALYST}).text


def test_session_requires_csrf_and_responder_executes(client, demo_rt):
    pending = client.get("/api/approvals", headers={"X-API-Key": ANALYST}).json()
    target = next(a for a in pending if a["action"] == "revoke_sessions")
    assert client.post(f"/api/approvals/{target['approval_id']}/approve", headers={"X-API-Key": ANALYST}).status_code == 403
    client.post("/login", data={"key": RESP}, follow_redirects=False)
    assert client.post(f"/api/approvals/{target['approval_id']}/approve").status_code == 403          # no CSRF header
    r = client.post(f"/api/approvals/{target['approval_id']}/approve", headers={"X-CSRF-Token": client.cookies.get("meridian_csrf")})
    assert r.status_code == 200 and r.json()["status"] == "executed" and r.json()["result"]["dry_run"] is True
    case = client.get(f"/api/cases/{target['case_id']}").json()
    assert case["status"] == "contained" and any("DRY RUN" in n["body"] for n in case["notes"])


def test_edl_and_block_flow(client, demo_rt):
    st = demo_rt.store
    cid = st.list_cases()[0]["case_id"]
    aid = st.request_approval(cid, "block_indicator", "198.51.100.200", {}, "c2", "agent:investigate")
    r = client.post(f"/api/approvals/{aid}/approve", headers={"X-API-Key": RESP})
    assert r.json()["status"] == "executed"
    assert client.get("/edl/ip.txt").status_code == 401
    edl = client.get("/edl/ip.txt", auth=("panos", "e" * 24))
    assert edl.status_code == 200 and "198.51.100.200" in edl.text


def _signed(body: bytes, ts: str | None = None):
    ts = ts or str(int(time.time()))
    return {"X-Meridian-Timestamp": ts, "X-Meridian-Signature": "sha256=" + hmac.new(b"s" * 32, ts.encode() + b"." + body, hashlib.sha256).hexdigest()}


def test_signed_ingest(client, demo_rt):
    body = json.dumps([{"category": "SignInLogs", "properties": {"userPrincipalName": "x@kestrel.example", "ipAddress": "203.0.113.1",
                                                                 "status": {"errorCode": 0}}}]).encode()
    assert client.post("/api/ingest/entra", content=body).status_code == 401
    assert client.post("/api/ingest/entra", content=body, headers=_signed(body, str(int(time.time()) - 900))).status_code == 401
    r = client.post("/api/ingest/entra", content=body, headers=_signed(body))
    assert r.status_code == 202 and r.json()["accepted"] == 1
    assert client.post("/api/ingest/nope", content=body, headers=_signed(body)).status_code == 404
    key = r.json()["batch"]
    assert demo_rt.pipeline.process(key).events == 1


def test_metrics_and_mcp_gate(client, monkeypatch):
    from meridian.api import app as appmod
    monkeypatch.setattr(appmod.rt().settings, "lodestar", {"url": "https://lodestar.internal.example"})
    assert client.get("/metrics").status_code == 401
    m = client.get("/metrics", headers={"Authorization": "Bearer " + "m" * 24}).text
    assert "meridian_approvals_pending" in m and "meridian_cases" in m
    assert "meridian_lodestar_last_push_age_seconds" in m and "meridian_lodestar_last_push_status" in m
    assert client.post("/mcp/lake/", json={}).status_code == 401
    assert client.post("/mcp/cases/", json={}, headers={"Authorization": "Bearer " + "t" * 32}).status_code == 403
    assert client.get("/readyz").json()["ready"] is True


def test_readyz_refuses_placeholder_secrets_and_reports_heartbeats(client, demo_rt, monkeypatch):
    from meridian.cli import beat
    beat(demo_rt, "worker")
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["heartbeats"]["worker"] is not None
    monkeypatch.setenv("MERIDIAN_INGEST_SECRET", "set-me")              # Terraform placeholder left in Key Vault
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["placeholder_secrets"] == ["MERIDIAN_INGEST_SECRET"]


def test_hunts_are_queued_for_the_agents_service(client, demo_rt):
    import asyncio
    r = client.post("/api/hunt", json={"hypothesis": "beaconing to newly registered domains", "hours": 48},
                    headers={"X-API-Key": ANALYST})
    assert r.status_code == 202 and r.json()["status"] == "queued"
    hid = r.json()["hunt_id"]
    assert client.get(f"/api/hunt/{hid}", headers={"X-API-Key": ANALYST}).json()["status"] == "queued"
    for _ in range(50):                                         # the agents role drains the queue
        if asyncio.run(demo_rt.agent_service.work_once()) is None:
            break
    done = client.get(f"/api/hunt/{hid}", headers={"X-API-Key": ANALYST}).json()
    assert done["status"] in ("done", "failed") and "outcome" in done
    assert client.post("/api/hunt", json={"hypothesis": ""}, headers={"X-API-Key": ANALYST}).status_code == 400


def test_interactive_api_docs_are_off_by_default(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_kill_switch_halts_agents_and_keeps_triage_running(client, demo_rt):
    import asyncio
    assert client.post("/api/agents/triage/halt", headers={"X-API-Key": ANALYST}).status_code == 403
    assert client.post("/api/agents/triage/halt", headers={"X-API-Key": RESP}).json()["status"] == "halted"
    assert client.post("/api/agents/triage/resume", headers={"X-API-Key": RESP}).status_code == 403   # admin only
    from meridian.models import Alert
    a = Alert.model_validate({"alert_id": "AL-halt", "rule_id": "r", "title": "t", "severity": 2, "entity": "ws-9.example",
                              "entity_type": "device", "mitre": [], "description": "d", "event_count": 1, "sample": []})
    demo_rt.store.upsert_alert(a)
    calls = []

    class Spy:
        name, model = "spy", "spy"

        async def complete(self, *a, **k):
            calls.append(1)
            raise RuntimeError("must not be called while halted")
    old = demo_rt.agent_service.providers
    demo_rt.agent_service.providers = {"fast": Spy(), "deep": Spy()}
    try:
        asyncio.run(demo_rt.agent_service.triage("AL-halt"))
    finally:
        demo_rt.agent_service.providers = old
    assert not calls and demo_rt.store.get_alert("AL-halt")["status"] != "closed"     # degraded: never auto-closes
    assert "(degraded)" in demo_rt.store.list_runs(ref="AL-halt")[0]["provider"]
    assert client.post("/api/agents/triage/resume", headers={"X-API-Key": ADMIN}).json()["status"] == "running"
    assert not demo_rt.agent_service.halted("triage")


def test_token_push_gzip_and_hec(client, demo_rt, monkeypatch):
    tok, other = "w" * 40, "o" * 40
    monkeypatch.setenv("MERIDIAN_INGEST_TOKENS", f"windows:{tok},syslog:{other}")
    nd = "\n".join(json.dumps({"EventID": 4624, "Channel": "Security", "Hostname": "h", "TargetUserName": f"u{i}",
                               "EventTime": "2026-10-02T10:00:00Z"}) for i in range(3)).encode()
    auth = {"Authorization": f"Bearer {tok}"}
    assert client.post("/api/ingest/windows", content=nd, headers={"Authorization": f"Bearer {other}"}).status_code == 401
    r = client.post("/api/ingest/windows", content=gzip.compress(nd), headers={**auth, "Content-Encoding": "gzip"})
    assert r.status_code == 202 and r.json()["accepted"] == 3
    assert demo_rt.pipeline.process(r.json()["batch"]).events == 3
    bomb = gzip.compress(b"0" * (70 * 1024 * 1024))
    assert client.post("/api/ingest/windows", content=bomb, headers={**auth, "Content-Encoding": "gzip"}).status_code == 413
    assert client.get("/services/collector/health").json()["code"] == 17
    assert client.post("/services/collector/event", content=b'{"event":"x"}', headers={"Authorization": "Splunk " + "z" * 40}).status_code == 403
    hec = b'{"time": 1, "host": "fw01", "event": "<134>Oct 2 10:00:00 fw01 CEF:0|V|P|1|1|deny|5|src=10.0.0.1 dst=10.0.0.2"}' \
          b'{"event": {"EventID": 4625, "Channel": "Security", "Hostname": "h"}, "host": "h"}'
    r = client.post("/services/collector/event", content=hec, headers={"Authorization": f"Splunk {other}"})
    assert r.status_code == 200 and r.json() == {"text": "Success", "code": 0}
    r = client.post("/services/collector/raw", content=b"line one\nline two\n", headers={"Authorization": f"Splunk {other}"})
    assert r.json()["code"] == 0
