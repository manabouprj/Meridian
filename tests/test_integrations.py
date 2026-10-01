"""LODESTAR hand-off (signed, LODESTAR-compatible payload) and chat notifications."""
import hashlib
import hmac
import json

import httpx

from meridian.integrations import lodestar_payload, notify, push_lodestar


def test_lodestar_payload_and_signature(demo_rt):
    p = lodestar_payload(demo_rt.store)
    assert p["findings"] and p["health"]["kpis"]["incidents_open"] >= 1
    f = p["findings"][0]
    assert f["finding_type"] == "incident" and f["severity"] in ("info", "low", "medium", "high", "critical")
    assert f["status"] in ("open", "in_progress", "resolved", "false_positive") and f["finding_id"].startswith("meridian-")
    seen = {}

    def handler(req):
        seen["url"], seen["body"], seen["h"] = str(req.url), req.content, dict(req.headers)
        return httpx.Response(202, json={"accepted": len(p["findings"])})
    out = push_lodestar(demo_rt.store, {"url": "https://lodestar.example", "org": "kestrel", "webhook_secret": "w" * 32},
                        transport=httpx.MockTransport(handler))
    assert out["status"] == 202 and seen["url"].endswith("/api/ingest/soc?org=kestrel")
    ts = seen["h"]["x-lodestar-timestamp"]
    want = "sha256=" + hmac.new(b"w" * 32, ts.encode() + b"." + seen["body"], hashlib.sha256).hexdigest()
    assert seen["h"]["x-lodestar-signature"] == want and json.loads(seen["body"])["findings"]


def test_notify_never_raises():
    def boom(req):
        raise httpx.ConnectError("down")
    out = notify({"slack_webhook_url": "https://hooks.slack.example/x", "teams_workflow_url": "https://teams.example/y"},
                 "t", ["a"], "https://m.example", transport=httpx.MockTransport(boom))
    assert len(out) == 2 and all("error" in o for o in out)


def test_cross_account_response_assumes_member_role(monkeypatch):
    import boto3

    from meridian.response.actions import _aws_client
    calls = []

    class Fake:
        def __init__(self, service, **kw):
            calls.append((service, kw))

        def assume_role(self, **kw):
            calls.append(("assume", kw))
            return {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "S", "SessionToken": "T"}}
    monkeypatch.setattr(boto3, "client", lambda service, **kw: Fake(service, **kw))
    _aws_client("ec2", {"role_arn": "arn:aws:iam::111122223333:role/meridian-response", "region": "me-central-1"})
    assert calls[1][1]["RoleArn"].endswith("meridian-response") and calls[1][1]["DurationSeconds"] == 900
    assert calls[2][0] == "ec2" and calls[2][1]["aws_session_token"] == "T" and calls[2][1]["region_name"] == "me-central-1"


def test_scheduler_cycle_isolates_failures_and_persists_state(demo_rt, monkeypatch):
    from datetime import datetime, timedelta, timezone

    import meridian.integrations as integ
    from meridian.cli import scheduler_cycle
    sent = []
    monkeypatch.setattr(integ, "notify", lambda *a, **k: sent.append(a[1]))

    def down(*a, **k):
        raise ConnectionError("LODESTAR unreachable")
    monkeypatch.setattr(integ, "push_lodestar", down)
    st = demo_rt.store
    st.set_cursor("scheduler:lodestar_push", "")
    st.set_cursor("scheduler:correlations_until", (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat())
    out = scheduler_cycle(demo_rt)
    assert "error" in out["lodestar"] and "error" not in out["approvals"] and "error" not in out["correlations"]
    first = out["approvals"]["notified"]
    assert first >= 1 and sent                                        # pending approvals announced once ...
    assert scheduler_cycle(demo_rt)["approvals"]["notified"] == 0      # ... and not again after a restart
    until = datetime.fromisoformat(st.get_cursor("scheduler:correlations_until"))
    assert datetime.now(timezone.utc) - until < timedelta(minutes=1)  # catch-up window advanced


def test_lodestar_push_cursor_only_advances_after_success(demo_rt, monkeypatch):
    import meridian.integrations as integ
    from meridian.cli import scheduler_cycle
    st = demo_rt.store
    st.set_cursor("scheduler:lodestar_push", "")
    monkeypatch.setattr(integ, "notify", lambda *a, **k: [])
    monkeypatch.setattr(integ, "push_lodestar", lambda *a, **k: {"status": 401, "accepted": None})
    scheduler_cycle(demo_rt)
    assert not st.get_cursor("scheduler:lodestar_push")          # rejected -> retried next cycle
    assert st.get_cursor("lodestar:last_status") == "401"        # exported as meridian_lodestar_last_push_status
    monkeypatch.setattr(integ, "push_lodestar", lambda *a, **k: {"status": 202, "accepted": 5})
    assert scheduler_cycle(demo_rt)["lodestar"]["status"] == 202
    assert st.get_cursor("scheduler:lodestar_push")
    assert st.get_cursor("lodestar:last_status") == "202"
