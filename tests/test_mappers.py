"""Vendor formats -> OCSF-flat events."""
from meridian.mappers import get_mapper
from meridian.mappers.cef import parse_cef


def test_cef_parse_and_map():
    line = ("<14>Oct  1 10:00:00 fw01 CEF:0|Palo Alto Networks|PAN-OS|11.1|threat|THREAT|8|rt=1759312800000 src=203.0.113.9 "
            "dst=10.0.0.5 spt=51515 dpt=3389 act=allow suser=jdoe@corp.example msg=Inbound RDP with spaces cs1=a\\=b")
    p = parse_cef(line)
    assert p["vendor"] == "Palo Alto Networks" and p["ext"]["msg"] == "Inbound RDP with spaces" and p["ext"]["cs1"] == "a=b"
    ev = get_mapper("cef")(line, {"key": "firewall"})[0]
    assert ev["class_uid"] == 4001 and ev["dst_port"] == 3389 and ev["action"] == "allow" and ev["user"] == "jdoe@corp.example"
    assert ev["severity_id"] == 4 and ev["source"] == "firewall"
    assert get_mapper("cef")("not a cef line", {}) == []


def test_cef_proxy_becomes_http():
    line = "CEF:0|Zscaler|NSSWeblog|6.0|Allowed|Allowed|5|suser=a@b.example dhost=x.example request=https://x.example/a requestMethod=GET act=Allowed"
    ev = get_mapper("cef")(line, {"key": "proxy"})[0]
    assert ev["class_uid"] == 4002 and ev["url"] == "https://x.example/a" and ev["dst_domain"] == "x.example"


def test_mde_tables():
    rec = {"category": "AdvancedHunting-DeviceProcessEvents", "properties": {
        "Timestamp": "2026-10-01T10:00:00.1234567Z", "DeviceName": "WS-1.corp.example", "DeviceId": "abc", "FileName": "powershell.exe",
        "ProcessCommandLine": "powershell -enc AAA", "InitiatingProcessFileName": "winword.exe", "AccountUpn": "J@corp.example"}}
    ev = get_mapper("mde")(rec, {"key": "mde"})[0]
    assert ev["class_uid"] == 1007 and ev["device"] == "ws-1.corp.example" and ev["user"] == "j@corp.example"
    assert ev["parent_process_name"] == "winword.exe" and ev["time"].microsecond == 123456
    net = {"category": "AdvancedHunting-DeviceNetworkEvents", "properties": {"RemoteUrl": "https://evil.example:8443/x", "RemoteIP": "198.51.100.1"}}
    assert get_mapper("mde")(net, {})[0]["dst_domain"] == "evil.example"


def test_entra_signin_and_audit():
    s = {"category": "SignInLogs", "properties": {"userPrincipalName": "A@B.example", "ipAddress": "203.0.113.1",
         "status": {"errorCode": 50126, "failureReason": "Invalid password"}, "location": {"countryOrRegion": "NL"},
         "riskLevelDuringSignIn": "high"}}
    ev = get_mapper("entra")(s, {})[0]
    assert ev["class_uid"] == 3002 and ev["status"] == "Failure" and ev["severity_id"] == 4 and ev["src_country"] == "NL"
    a = {"category": "AuditLogs", "properties": {"operationName": "Add member to role", "result": "success",
         "initiatedBy": {"user": {"userPrincipalName": "admin@b.example"}}, "targetResources": [{"userPrincipalName": "x@b.example"}]}}
    ev = get_mapper("entra")(a, {})[0]
    assert ev["class_uid"] == 3005 and ev["resource"] == "x@b.example" and ev["api_operation"] == "Add member to role"


def test_cloudtrail_records():
    rec = {"Records": [
        {"eventTime": "2026-10-01T10:00:00Z", "eventName": "ConsoleLogin", "userIdentity": {"type": "Root", "arn": "arn:aws:iam::1:root"},
         "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}, "recipientAccountId": "1"},
        {"eventTime": "2026-10-01T10:01:00Z", "eventName": "StopLogging", "userIdentity": {"type": "IAMUser", "userName": "bob"},
         "requestParameters": {"name": "trail"}, "errorCode": "AccessDenied"}]}
    evs = get_mapper("cloudtrail")(rec, {})
    assert evs[0]["class_uid"] == 3002 and evs[0]["user"] == "root" and evs[0]["mfa"] is False
    assert evs[1]["class_uid"] == 6003 and evs[1]["status"] == "Failure" and evs[1]["resource"] == "trail"


def test_ocsf_nested_and_json_map():
    rec = {"class_uid": 1007, "time": 1759312800000, "actor": {"user": {"name": "Svc"}}, "device": {"hostname": "H1"},
           "process": {"name": "a.exe", "cmd_line": "a.exe /x", "file": {"hashes": [{"algorithm_id": 3, "value": "ab" * 32}]}},
           "metadata": {"product": {"name": "CrowdStrike Falcon"}, "uid": "evt-1"}}
    ev = get_mapper("ocsf")(rec, {})[0]
    assert ev["process_cmdline"] == "a.exe /x" and ev["file_sha256"] == "ab" * 32 and ev["event_uid"] == "evt-1"
    j = get_mapper("json")({"t": "2026-10-01T00:00:00Z", "who": {"mail": "X@Y.example"}, "act": "delete", "risk": "high"},
                           {"class_uid": 6003, "field_map": {"time": "t", "user": "who.mail", "api_operation": "act", "severity_id": "risk"}})[0]
    assert j["user"] == "x@y.example" and j["api_operation"] == "delete" and j["severity_id"] == 4


def test_event_rejects_unknown_columns():
    import pytest

    from meridian.ocsf import event
    with pytest.raises(KeyError):
        event(1007, not_a_column=1)
