"""Sigma-subset rules: the shipped pack, condition logic, correlations."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from meridian.detect import RuleError, StreamDetector, load_rules, parse_rule
from meridian.detect.engine import correlation_spec, run_correlations
from meridian.lake import LocalStore, write_events
from meridian.lake.engines import DuckDBEngine
from meridian.ocsf import event

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def rules():
    r, errors = load_rules([ROOT / "config" / "rules"])
    assert not errors
    return r


def _hits(rules, ev):
    return {a.rule_id for a in StreamDetector(rules).evaluate([ev])}


def test_pack_loads_with_attack_mapping(rules):
    assert len(rules) >= 25 and sum(r.kind == "correlation" for r in rules) >= 6
    assert all(r.mitre or r.id == "vendor-detection" for r in rules)


def test_endpoint_rules(rules):
    enc = event(1007, time=NOW, process_name="powershell.exe", process_cmdline="powershell.exe -nop -enc SQBFAFgA", device="ws1")
    assert "mer-ep-encoded-powershell" in _hits(rules, enc)
    benign = event(1007, time=NOW, process_name="powershell.exe", process_cmdline="powershell.exe Get-Process", device="ws1")
    assert "mer-ep-encoded-powershell" not in _hits(rules, benign)
    dump = event(1007, time=NOW, process_name="rundll32.exe", process_cmdline="rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 624 x full")
    assert "mer-ep-lsass-dump" in _hits(rules, dump)
    office = event(1007, time=NOW, process_name="cmd.exe", parent_process_name="WINWORD.EXE", device="ws1")
    assert "mer-ep-office-child-shell" in _hits(rules, office)
    vss_list = event(1007, time=NOW, process_cmdline="vssadmin list shadows", device="jump")
    assert "mer-ep-inhibit-recovery" not in _hits(rules, vss_list)


def test_network_rules_exclude_private_sources(rules):
    pub = event(4001, time=NOW, src_ip="203.0.113.10", dst_ip="10.0.0.4", dst_port=3389, action="allow")
    priv = event(4001, time=NOW, src_ip="10.1.2.3", dst_ip="10.0.0.4", dst_port=3389, action="allow")
    assert "mer-net-inbound-admin" in _hits(rules, pub) and "mer-net-inbound-admin" not in _hits(rules, priv)
    ioc = event(4003, time=NOW, dns_query="bad.example", ioc_hits="bad.example (ISAC)", device="ws1")
    assert "mer-net-ioc-hit" in _hits(rules, ioc)
    exe = event(4002, time=NOW, url="http://198.51.100.4/payload.exe", user="u@x.example")
    assert "mer-net-exe-from-ip" in _hits(rules, exe)


def test_cloud_and_identity_rules(rules):
    stop = event(6003, time=NOW, api_operation="StopLogging", status="Success", cloud_account="1")
    assert "mer-aws-cloudtrail-stopped" in _hits(rules, stop)
    nomfa = event(3002, time=NOW, api_operation="ConsoleLogin", status="Success", mfa=False, user="alice")
    root = event(3002, time=NOW, api_operation="ConsoleLogin", status="Success", mfa=False, user="root")
    assert "mer-aws-console-no-mfa" in _hits(rules, nomfa) and "mer-aws-console-no-mfa" not in _hits(rules, root)
    assert "mer-aws-root-login" in _hits(rules, root)


def test_condition_grammar_and_errors():
    doc = {"title": "t", "id": "x", "logsource": {"category": "process_creation"},
           "detection": {"a": {"process_name": "a.exe"}, "b": {"process_name": "b.exe"}, "c": {"user": "root"},
                         "condition": "(a or b) and not c"}}
    r = parse_rule(doc)
    assert r.match(event(1007, process_name="b.exe", user="u")) and not r.match(event(1007, process_name="b.exe", user="root"))
    with pytest.raises(RuleError):
        parse_rule({**doc, "detection": {**doc["detection"], "condition": "a and missing"}})
    with pytest.raises(RuleError):
        parse_rule({**doc, "detection": {"a": {"CommandLine|base64offset|contains": "x"}, "condition": "a"}})
    with pytest.raises(RuleError):
        parse_rule({**doc, "detection": {"a": {"NotAField": "x"}, "condition": "a"}})


def test_suppression_groups_repeats(rules):
    evs = [event(1007, time=NOW + timedelta(minutes=i), process_name="powershell.exe", process_cmdline="powershell -enc AAAA",
                 device="ws1") for i in range(5)]
    alerts = [a for a in StreamDetector(rules).evaluate(evs) if a.rule_id == "mer-ep-encoded-powershell"]
    assert len(alerts) == 1 and alerts[0].event_count == 5


def test_correlations_on_the_lake(tmp_path, rules):
    st = LocalStore(str(tmp_path))
    evs = [event(3002, time=NOW - timedelta(minutes=10, seconds=i), user=f"user{i}@x.example", src_ip="203.0.113.77",
                 status="Failure") for i in range(20)]
    write_events(st, evs, "b")
    alerts, errors = run_correlations(rules, DuckDBEngine(str(tmp_path)), now=NOW)
    assert not errors
    spray = [a for a in alerts if a.rule_id == "mer-cor-password-spray"]
    assert spray and spray[0].entity == "203.0.113.77" and "20" in spray[0].description
    spec = correlation_spec(next(r for r in rules if r.id == "mer-cor-password-spray"), {r.id: r for r in rules}, NOW)
    assert spec.count_distinct == "user" and spec.group_by == ["src_ip"]
