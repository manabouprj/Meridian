"""Ingestion methods for hybrid estates: Windows / Sysmon, syslog (RFC 3164 / 5424, CEF, LEEF, patterns), TLS syslog,
token and HEC push, API pull, normalisation preview and housekeeping. All offline."""
from __future__ import annotations

import asyncio
import json
import ssl
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from meridian.mappers import get_mapper

WIN = get_mapper("windows")
SYS = get_mapper("syslog")


# ------------------------------------------------------------------ Windows
def test_windows_mapper_reads_every_common_shipper_shape():
    st = {"key": "windows", "timezone": "+04:00"}
    nxlog = {"EventTime": "2026-10-02 14:00:01", "Hostname": "FS-01.corp.example", "EventID": 4625, "Channel": "Security",
             "TargetUserName": "j.doe", "TargetDomainName": "CORP", "LogonType": "3", "IpAddress": "::ffff:10.20.1.44",
             "AuthenticationPackageName": "NTLM", "SubStatus": "0xc000006a"}
    e = WIN(nxlog, st)[0]
    assert (e["class_uid"], e["status"], e["user"], e["user_domain"], e["src_ip"]) == (3002, "Failure", "j.doe", "CORP", "10.20.1.44")
    assert e["time"] == datetime(2026, 10, 2, 10, 0, 1, tzinfo=timezone.utc)          # local +04:00 -> UTC
    winlogbeat = {"@timestamp": "2026-10-02T10:00:02.123Z", "winlog": {
        "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "computer_name": "WS-0142.corp.example",
        "event_data": {"UtcTime": "2026-10-02 10:00:02.120", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "CommandLine": "powershell.exe -enc SQBFAFgA", "ParentImage": "C:\\Office16\\WINWORD.EXE",
                       "User": "CORP\\j.doe", "Hashes": "MD5=AA,SHA256=BBCC"}}}
    e = WIN(winlogbeat, st)[0]
    assert (e["class_uid"], e["process_name"], e["parent_process_name"], e["file_sha256"], e["product"]) == \
        (1007, "powershell.exe", "WINWORD.EXE", "bbcc", "Microsoft Sysmon")
    fluentbit = {"TimeCreated": "2026-10-02T10:00:03Z", "EventID": 22, "Channel": "Microsoft-Windows-Sysmon/Operational",
                 "Computer": "ws-0142", "EventData": {"QueryName": "evil.example", "Image": "C:\\x\\rundll32.exe"}}
    e = WIN(fluentbit, st)[0]
    assert (e["class_uid"], e["dns_query"], e["process_name"]) == (4003, "evil.example", "rundll32.exe")
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
           '<EventID>4732</EventID><TimeCreated SystemTime="2026-10-02T10:00:04.5123456Z"/><Channel>Security</Channel>'
           '<Computer>DC-01</Computer></System><EventData><Data Name="TargetUserName">Administrators</Data>'
           '<Data Name="SubjectUserName">helpdesk1</Data><Data Name="MemberName">CN=Bob</Data></EventData></Event>')
    e = WIN(xml, st)[0]
    assert (e["class_uid"], e["resource"], e["user"], e["api_operation"]) == \
        (3005, "Administrators", "helpdesk1", "Add member to security group (local)")
    cleared = {"Event": {"System": {"EventID": "1102", "Channel": "Security", "Computer": "DC-01",
                                    "TimeCreated": {"@SystemTime": "2026-10-02T10:00:05Z"}},
                         "UserData": {"LogFileCleared": {"SubjectUserName": "attacker"}}}}
    e = WIN(cleared, st)[0]
    assert (e["class_uid"], e["api_operation"], e["user"], e["severity_id"]) == (6003, "Clear security log", "attacker", 4)
    wrapped = '<14>Oct  2 14:00:06 WEC-01 NXLog: ' + json.dumps({"EventTime": "2026-10-02 14:00:06", "Hostname": "SRV-9",
                                                                "EventID": 7045, "Channel": "System", "ServiceName": "PSEXESVC",
                                                                "ImagePath": "%SystemRoot%\\PSEXESVC.exe"})
    e = WIN(wrapped, st)[0]
    assert (e["class_uid"], e["resource"], e["device"]) == (6003, "PSEXESVC", "srv-9")
    other = WIN({"EventID": 5156, "Channel": "Security", "Hostname": "x", "EventTime": "2026-10-02T10:00:00Z"}, st)[0]
    assert other["class_uid"] == 0                                                     # kept, not dropped
    assert WIN({"EventID": 5156, "Channel": "Security"}, {**st, "keep_unmapped": False}) == []


def test_windows_xml_with_entities_is_refused():
    bomb = '<!DOCTYPE x [<!ENTITY a "aaaa">]><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>' \
           '<EventID>4624</EventID></System></Event>'
    assert WIN(bomb, {}) == []


def test_demo_on_premises_storyline_is_detected_from_windows_and_syslog(demo_rt):
    alerts = demo_rt.store.list_alerts(limit=500)
    rules = {(a["rule_id"], a["entity"]) for a in alerts}
    assert ("mer-cor-brute-force", "svc-sql") in rules                     # 30 x 4625 via NXLog
    assert ("mer-id-ad-priv-group-add", "svc-sql") in rules                # 4732 Administrators
    assert ("mer-ep-event-log-cleared", "db-fin-01.kestrel.example") in rules
    assert ("mer-ep-lolbin-download", "db-fin-01.kestrel.example") in rules  # Sysmon 1 certutil
    q = demo_rt.store.ingest_quality(24)
    assert q["windows"]["rejected"] == 0 and q["syslog"]["rejected"] == 0 and q["windows"]["events"] > 100


# ------------------------------------------------------------------ syslog
def test_syslog_headers_time_zones_and_year_rollover():
    from meridian.mappers.syslog import parse_syslog
    h = parse_syslog("<38>Dec 31 23:59:58 web-01 sshd[1]: hi", "Asia/Dubai", now=datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc))
    assert h["time"].year == 2026 and h["host"] == "web-01" and h["app"] == "sshd"
    h = parse_syslog('<165>1 2026-10-02T10:15:02.123+04:00 fw-9 app 77 ID47 [ex@32473 iut="3"] message here')
    assert (h["host"], h["app"], h["procid"], h["msg"]) == ("fw-9", "app", "77", "message here")
    e = SYS('<165>1 2026-10-02T10:15:02.123+04:00 fw-9 app 77 ID47 - message here', {"key": "s"})[0]
    assert e["time"] == datetime(2026, 10, 2, 6, 15, 2, 123000, tzinfo=timezone.utc)   # offset honoured with fraction


def test_syslog_routes_cef_leef_patterns_and_keeps_the_rest():
    st = {"key": "syslog", "timezone": "Asia/Dubai"}
    cef = SYS("<134>Oct 2 10:00:00 fw01 CEF:0|Fortinet|FortiGate|7.4|13|deny|5|src=10.1.1.5 dst=203.0.113.7 dpt=445 act=deny", st)[0]
    assert (cef["class_uid"], cef["dst_port"], cef["status"], cef["device"]) == (4001, 445, "Failure", "fw01")
    l2 = SYS("<13>Oct 2 10:00:00 q LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=10.0.1.8^dst=10.0.0.5^sev=5", st)[0]
    assert (l2["src_ip"], l2["dst_ip"], l2["product"]) == ("10.0.1.8", "10.0.0.5", "Lancope StealthWatch")
    l1 = SYS("LEEF:1.0|Microsoft|MSExchange|2016|15345|src=10.50.1.1\tusrName=joe\tsev=8", st)[0]
    assert (l1["user"], l1["severity_id"]) == ("joe", 4)
    ssh = SYS("<38>Oct  2 10:15:01 web-01 sshd[2]: Failed password for invalid user admin from 203.0.113.9 port 51022 ssh2", st)[0]
    assert (ssh["class_uid"], ssh["user"], ssh["src_ip"], ssh["status"]) == (3002, "admin", "203.0.113.9", "Failure")
    sudo = SYS("<86>Oct  2 10:15:02 web-01 sudo: j.doe : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", st)[0]
    assert (sudo["class_uid"], sudo["process_name"], sudo["resource"]) == (1007, "cat", "root")
    own = {**st, "patterns": [{"app": "asa", "match": r"Deny (?P<action>\w+) src \S+:(?P<src_ip>[\d.]+)/(?P<src_port>\d+) "
                                                     r"dst \S+:(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)",
                               "class_uid": 4001, "activity_name": "Traffic", "status": "Failure"}]}
    asa = SYS("<164>Oct  2 10:15:03 asa-01 asa: Deny tcp src outside:198.51.100.4/4444 dst inside:10.0.0.9/3389 by access-group", own)[0]
    assert (asa["class_uid"], asa["dst_port"], asa["action"]) == (4001, 3389, "tcp")
    other = SYS("<13>Oct 2 10:00:00 sw-core-01 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down", st)[0]
    assert other["class_uid"] == 0 and other["device"] == "sw-core-01" and "UPDOWN" in other["message"]
    assert SYS("<13>Oct 2 10:00:00 sw-core-01 %LINK-3-UPDOWN: x", {**st, "keep_unparsed": False}) == []


def _self_signed(tmp_path, cn="meridian-syslog"):
    crypto = pytest.importorskip("cryptography")
    del crypto
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / f"{cn}.crt", tmp_path / f"{cn}.key"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return c, k


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_tls_syslog_receiver_with_mutual_tls(tmp_path, monkeypatch):
    from meridian.ingest.landing import read_batch
    from meridian.ingest.syslog import serve, tls_context
    from meridian.lake.storage import open_store
    srv_c, srv_k = _self_signed(tmp_path, "server")
    cli_c, cli_k = _self_signed(tmp_path, "client")
    monkeypatch.setenv("MERIDIAN_SYSLOG_TLS_CERT", srv_c.read_text())                 # PEM from the environment
    monkeypatch.setenv("MERIDIAN_SYSLOG_TLS_KEY", srv_k.read_text())
    ctx = tls_context(client_ca=str(cli_c))
    landing = open_store(str(tmp_path / "landing"))
    port = _free_port()

    async def run():
        task = asyncio.create_task(serve(landing, "syslog", "127.0.0.1", 0, 0, 0.2, tls_port=port, tls=ctx))
        await asyncio.sleep(0.3)
        client = ssl.create_default_context(cafile=str(srv_c))
        client.load_cert_chain(str(cli_c), str(cli_k))
        r, w = await asyncio.open_connection("127.0.0.1", port, ssl=client, server_hostname="localhost")
        msg = b"<38>Oct  2 10:15:01 web-01 sshd[2]: Accepted publickey for ops from 10.0.0.5 port 1 ssh2"
        w.write(str(len(msg)).encode() + b" " + msg)                                 # RFC 5425 octet counting
        await w.drain()
        w.close()
        anon = ssl.create_default_context(cafile=str(srv_c))                            # no client certificate
        refused = False
        try:
            r2, w2 = await asyncio.open_connection("127.0.0.1", port, ssl=anon, server_hostname="localhost")
            w2.write(b"x\n")
            await w2.drain()
            refused = (await asyncio.wait_for(r2.read(1), 2)) == b""
        except (ssl.SSLError, ConnectionError, asyncio.IncompleteReadError):
            refused = True
        await asyncio.sleep(0.6)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return refused

    assert asyncio.run(run())
    keys = list(landing.list("syslog/"))
    lines = [x for k in keys for x in read_batch(k, landing.get(k))]
    assert any("Accepted publickey for ops" in x for x in lines)
    assert not any(x == "x" for x in lines)


# ------------------------------------------------------------------ API pull
class _Store:
    def __init__(self):
        self.c = {}

    def get_cursor(self, k):
        return self.c.get(k)

    def set_cursor(self, k, v):
        self.c[k] = v


class _Landing:
    def __init__(self):
        self.objs = {}

    def put(self, k, b):
        self.objs[k] = b


def _landed(landing):
    from meridian.ingest.landing import read_batch
    return [r for k, b in landing.objs.items() for r in read_batch(k, b)]


def test_pull_collector_link_pagination_cursor_and_failure():
    from meridian.ingest.pull import Collector
    seen = []

    def handler(req: httpx.Request):
        seen.append(str(req.url))
        assert req.headers["Authorization"] == "SSWS secret-value"
        if "page=2" in str(req.url):
            return httpx.Response(200, json=[{"published": "2026-10-02T10:05:00.000Z", "id": 3}])
        return httpx.Response(200, json=[{"published": "2026-10-02T10:01:00.000Z", "id": 1},
                                         {"published": "2026-10-02T10:02:00.000Z", "id": 2}],
                              headers={"Link": '<https://okta.example/api/v1/logs?page=2>; rel="next"'})
    src = {"key": "okta", "pull": {"url": "https://okta.example/api/v1/logs", "params": {"since": "{cursor}"},
                                   "auth": {"type": "bearer", "scheme": "SSWS", "token": "secret-value"},
                                   "cursor": {"field": "published", "start_minutes": 30}, "paginate": "link"}}
    st, land = _Store(), _Landing()
    now = datetime(2026, 10, 2, 10, 10, tzinfo=timezone.utc)
    res = Collector(src, land, st, httpx.MockTransport(handler)).run(now)
    assert res["records"] == 3 and res["pages"] == 2
    assert "since=2026-10-02T09%3A40%3A00.000Z" in seen[0]
    assert st.c["pull:okta:cursor"] == "2026-10-02T10:05:00.000Z"
    assert [r["id"] for r in _landed(land)] == [1, 2, 3]

    def failing(req):
        return httpx.Response(503)
    res = Collector(src, land, st, httpx.MockTransport(failing)).run(now)
    assert "stopped" in res and st.c["pull:okta:cursor"] == "2026-10-02T10:05:00.000Z"       # nothing lost


def test_pull_collector_two_step_api_with_oauth_and_window_cursor():
    """Microsoft 365 Management Activity style: list content blobs, fetch each contentUri; header pagination."""
    from meridian.ingest.pull import Collector
    calls = []

    def handler(req: httpx.Request):
        calls.append(str(req.url))
        if req.url.path.endswith("/token"):
            assert b"client_secret=s3cret" in req.content
            return httpx.Response(200, json={"access_token": "AT", "expires_in": 3600})
        assert req.headers["Authorization"] == "Bearer AT"
        if req.url.path.startswith("/blob/"):
            return httpx.Response(200, json=[{"CreationTime": "2026-10-02T09:00:00", "Operation": req.url.path}])
        if "next=1" in str(req.url):
            return httpx.Response(200, json=[{"contentUri": "https://m.example/blob/2", "contentCreated": "2026-10-02T09:30:00Z"}])
        return httpx.Response(200, json=[{"contentUri": "https://m.example/blob/1", "contentCreated": "2026-10-02T09:10:00Z"}],
                              headers={"NextPageUri": "https://m.example/content?next=1"})
    src = {"key": "m365", "pull": {
        "url": "https://m.example/content", "params": {"contentType": "Audit.General", "startTime": "{cursor}", "endTime": "{end}"},
        "auth": {"type": "oauth2", "endpoint": "https://login.example/t/token", "client_id": "c", "client_secret": "s3cret",
                 "scope": "https://manage.office.com/.default"},
        "paginate": {"type": "header", "name": "NextPageUri"}, "expand": "contentUri",
        "cursor": {"mode": "window", "start_minutes": 120, "max_window_minutes": 60, "format": "%Y-%m-%dT%H:%M:%S"}}}
    st, land = _Store(), _Landing()
    now = datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)
    res = Collector(src, land, st, httpx.MockTransport(handler)).run(now)
    assert res["records"] == 2 and {r["Operation"] for r in _landed(land)} == {"/blob/1", "/blob/2"}
    assert "startTime=2026-10-02T08%3A00%3A00&" in calls[1] and calls[1].endswith("endTime=2026-10-02T09%3A00%3A00")
    assert st.c["pull:m365:cursor"] == "2026-10-02T09:00:00.000Z"                # window end, capped at 60 min


def test_pull_auth_secrets_must_be_environment_references(tmp_path):
    import yaml

    from meridian.config import ConfigError, load_settings
    cfg = {"sources": [{"key": "okta", "format": "json", "pull": {"url": "https://x.example", "auth": {"type": "bearer", "token": "literal"}}}]}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ConfigError):
        load_settings(str(p))


# ------------------------------------------------------------------ preview and housekeeping
def test_map_test_previews_normalisation(tmp_path, capsys):
    from meridian.cli import main
    f = tmp_path / "sample.jsonl"
    f.write_text(json.dumps({"EventID": 4688, "Channel": "Security", "Hostname": "h", "NewProcessName": "C:\\w\\cmd.exe",
                             "CommandLine": "cmd /c whoami", "EventTime": "2026-10-02T10:00:00Z"}) + "\n")
    assert main(["map-test", "--file", str(f), "--format", "windows"]) == 0
    out = capsys.readouterr().out
    assert "records=1 events=1 rejected=0" in out and "1007 Process Activity" in out and "process_cmdline" in out


def test_housekeeping_removes_old_ledger_rows_only(tmp_path):
    from sqlalchemy import update

    from meridian.store import Store
    from meridian.store.db import processed
    st = Store(f"sqlite:///{tmp_path / 's.db'}")
    st.mark_batch("windows/2026/01/01/a.jsonl.gz", 5, 0)
    st.mark_batch("windows/2026/10/01/b.jsonl.gz", 5, 0, errors=1)
    with st.engine.begin() as c:
        c.execute(update(processed).where(processed.c.key.like("%/01/01/%")).values(
            processed_at=datetime.now(timezone.utc) - timedelta(days=200)))
    assert st.housekeeping(ledger_days=120)["processed_batches"] == 1
    assert st.batch_done("windows/2026/10/01/b.jsonl.gz") and not st.batch_done("windows/2026/01/01/a.jsonl.gz")
    assert st.ingest_quality(24)["windows"] == {"events": 5, "rejected": 1, "batches": 1}


def test_iso_offsets_with_fractions_are_honoured():
    from meridian.ocsf import _ts
    assert _ts("2026-10-02T10:15:02.000+04:00") == datetime(2026, 10, 2, 6, 15, 2, tzinfo=timezone.utc)
    assert _ts("2026-10-02T10:15:02.1234567Z").microsecond == 123456
    assert time.time() > 0


def test_structured_syslog_records_from_journald_and_vector():
    j = {"MESSAGE": "Failed password for root from 198.51.100.4 port 2222 ssh2", "_HOSTNAME": "web-02",
         "SYSLOG_IDENTIFIER": "sshd", "timestamp": "2026-10-02T10:00:00Z"}
    e = SYS(j, {"key": "linux"})[0]
    assert (e["class_uid"], e["device"], e["user"], e["status"]) == (3002, "web-02", "root", "Failure")
    v = SYS({"message": "job done", "host": {"name": "web-03"}, "appname": "CRON", "@timestamp": "2026-10-02T10:01:00Z"}, {"key": "linux"})[0]
    assert (v["class_uid"], v["device"], v["app_name"], v["time"].minute) == (0, "web-03", "CRON", 1)


def test_unknown_time_zones_fail_at_start_up_not_silently(tmp_path):
    import yaml

    from meridian.config import ConfigError, load_settings
    from meridian.mappers.common import UnknownTimeZone, zone
    assert zone("Asia/Dubai").utcoffset(datetime(2026, 10, 2)) == timedelta(hours=4)    # needs tzdata on Windows
    assert zone("+05:30").utcoffset(None) == timedelta(hours=5, minutes=30)
    for bad in ("Asia/Dubay", "+25:00"):
        with pytest.raises(UnknownTimeZone):
            zone(bad)
    for sources, msg in (([{"key": "s", "format": "syslog", "settings": {"timezone": "Asia/Dubay"}}], "unknown time zone"),
                         ([{"key": "s", "format": "sysl0g"}], "unknown format"),
                         ([{"key": "s", "format": "cef"}, {"key": "s", "format": "cef"}], "used twice")):
        p = tmp_path / "c.yaml"
        p.write_text(yaml.safe_dump({"sources": sources}))
        with pytest.raises(ConfigError, match=msg):
            load_settings(str(p))
