"""MERIDIAN -> LODESTAR integration contract (docs/integration/MERIDIAN-LODESTAR-Integration.md).

The unit tests run everywhere. The schema test also validates every finding with LODESTAR's own model when the
LODESTAR source tree is available (set LODESTAR_PATH, as the integration CI job does)."""
import os
import sys

import pytest

from meridian.integrations import lodestar_payload

SEVERITIES = {"info", "low", "medium", "high", "critical"}
STATUSES = {"open", "in_progress", "risk_accepted", "resolved", "false_positive"}


def _payload(demo_rt):
    return lodestar_payload(demo_rt.store, sources=["mde", "entra", "cloudtrail", "firewall", "proxy", "dns"],
                            context=demo_rt.context)


def test_payload_shape_and_identity_mapping(demo_rt):
    p = _payload(demo_rt)
    assert p["findings"] and set(p["health"]) >= {"coverage_pct", "kpis"}
    for f in p["findings"]:
        assert f["finding_id"].startswith("meridian-CASE-") and f["finding_type"] == "incident"
        assert f["severity"] in SEVERITIES and f["status"] in STATUSES and f["source"] == "meridian"
        et = f["evidence"]["entity_type"]
        if et in ("src_ip", "dst_ip"):                     # an attacker IP is never an asset
            assert f["asset_id"] is None and f["evidence"]["entity"] in f["entity_keys"]
        if et == "user":
            assert f["user_id"] == f["evidence"]["entity"]
        assert f["actively_exploited_in_env"] == (f["evidence"]["verdict"] == "malicious" and f["status"] != "resolved")


def test_most_critical_asset_is_reported(demo_rt):
    p = _payload(demo_rt)
    phish = next(f for f in p["findings"] if "ws-0142" in f["title"] or "fs-01" in f["title"])
    assert phish["asset_id"] == "fs-01.kestrel.example" or phish["asset_id"].startswith("fs-01")


def test_payload_validates_against_lodestar_model(demo_rt):
    path = os.environ.get("LODESTAR_PATH")
    if not path:
        pytest.skip("set LODESTAR_PATH to the LODESTAR source tree to run the cross-product schema test")
    sys.path.insert(0, path)
    import json

    from lodestar.models import Finding  # type: ignore
    for f in json.loads(json.dumps(_payload(demo_rt)["findings"], default=str)):
        Finding.model_validate({**f, "domain": "soc"})
