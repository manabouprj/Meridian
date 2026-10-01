"""Tool-level security: scopes, limits, request-only containment, untrusted-data marking."""
import pytest

from meridian.mcp_servers import CALLER, Caller, ToolError


def as_caller(scopes):
    return CALLER.set(Caller("agent:test", set(scopes)))


def test_scopes_enforced(demo_rt):
    tb = demo_rt.toolbox
    tok = as_caller({"context:read"})
    try:
        with pytest.raises(ToolError):
            tb.search_events(last_minutes=10)
        assert tb.lookup_asset("db-fin-01")["criticality"] == 5
    finally:
        CALLER.reset(tok)
    with pytest.raises(ToolError):
        tb.describe_schema()                               # no caller at all


def test_query_limits_and_untrusted_notice(demo_rt):
    tok = as_caller({"lake:read"})
    try:
        r = demo_rt.toolbox.search_events(classes=[1007], last_minutes=600, limit=10000)
        assert r["row_count"] <= 200 and "UNTRUSTED" in r["notice"] and r["query_id"].startswith("Q-")
        with pytest.raises(ToolError):
            demo_rt.toolbox.search_events(last_minutes=60 * 24 * 90)            # beyond the agent window
        with pytest.raises(ToolError):
            demo_rt.toolbox.search_events(where=[{"field": "raw", "op": "contains", "value": "x"}])
    finally:
        CALLER.reset(tok)


def test_containment_is_request_only_and_validated(demo_rt):
    st = demo_rt.store
    case_id = st.list_cases()[0]["case_id"]
    tok = as_caller({"response:request"})
    try:
        with pytest.raises(ToolError):
            demo_rt.toolbox.request_containment(case_id, "block_indicator", "10.1.2.3", "internal IP must be refused")
        with pytest.raises(ToolError):
            demo_rt.toolbox.request_containment(case_id, "format_disk", "x", "not an action")
        r = demo_rt.toolbox.request_containment(case_id, "block_indicator", "evil-domain.example", "beaconing")
        assert r["status"] == "pending"
        again = demo_rt.toolbox.request_containment(case_id, "block_indicator", "evil-domain.example", "dup")
        assert again["approval_id"] == r["approval_id"]                              # de-duplicated
    finally:
        CALLER.reset(tok)
    assert st.get_approval(r["approval_id"])["status"] == "pending"
    assert "evil-domain.example" not in st.list_blocks("domain")                     # nothing executed


def test_four_eyes_holds_across_mcp_and_console_identities(demo_rt):
    """A responder who requests containment over MCP (API key or user JWT) cannot approve it on the console."""
    import os

    from meridian.api.mcp_auth import resolve_caller
    from meridian.identity import canonical_actor
    from meridian.response import ApprovalError, decide
    st = demo_rt.store
    case_id = st.list_cases()[0]["case_id"]
    key = "r" * 32
    old = os.environ.get("MERIDIAN_API_KEYS")
    os.environ["MERIDIAN_API_KEYS"] = f"responder:{key}"
    try:
        caller = resolve_caller(f"Bearer {key}")
        assert caller.kind == "human"
        tok = CALLER.set(caller)
        try:
            r = demo_rt.toolbox.request_containment(case_id, "block_indicator", "self-approve.example", "test")
        finally:
            CALLER.reset(tok)
        with pytest.raises(ApprovalError) as e:
            decide(st, r["approval_id"], True, "key:responder#1", "responder", {"dry_run": True})
        assert e.value.code == 403
    finally:
        if old is None:
            os.environ.pop("MERIDIAN_API_KEYS", None)
        else:
            os.environ["MERIDIAN_API_KEYS"] = old
    assert canonical_actor("user:idp:Jane@Corp.example") == canonical_actor("oidc:jane@corp.example") == \
        canonical_actor("bearer:jane@corp.example")


def test_indicator_validation_edge_cases(tmp_path):
    from meridian.response.actions import _block, _indicator
    for bad in ("::ffff:10.0.0.5", "::ffff:192.168.1.1", "169.254.169.254", "0.0.0.0", "240.0.0.1", "10.0.0.0/8",
                "203.0.113.0/16", "fe80::1"):
        assert _indicator(bad), bad
    for ok in ("203.0.113.9", "198.51.100.0/24", "bad.cafe", "evil-domain.example", "2001:db8::1"):
        assert _indicator(ok) is None, ok

    class S:
        def __init__(self):
            self.rows = []

        def add_block(self, value, kind, *a):
            self.rows.append((value, kind))
    st = S()
    _block("bad.cafe", {}, {"_store": st})
    _block("203.0.113.9", {}, {"_store": st})
    assert st.rows == [("bad.cafe", "domain"), ("203.0.113.9", "ip")]
