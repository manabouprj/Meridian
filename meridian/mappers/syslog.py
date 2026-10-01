"""Syslog in any common shape: RFC 5424, RFC 3164 (BSD), CEF, LEEF, JSON payloads, plus your own patterns.

One `format: syslog` source can take a mixed feed (a relay forwarding firewalls, Linux servers and appliances):
  1. the syslog header is parsed (priority, time, host, app) - RFC 5424 or RFC 3164, with or without <PRI>;
  2. the message is routed: CEF -> cef mapper, LEEF -> LEEF parser, JSON -> Windows mapper or field_map;
  3. otherwise built-in patterns (sshd, sudo, useradd) and your `patterns` are tried, in order;
  4. anything still unrecognised is kept as an OCSF Base Event (class 0) with host, app and message, so nothing
     you were sent is dropped. Set keep_unparsed: false to discard it instead.

settings:
  timezone: Asia/Dubai            zone for RFC 3164 timestamps (they carry no zone and no year)
  keep_unparsed: true
  patterns:                       named groups must be MERIDIAN column names
    - {app: asa, match: 'Deny (?P<action>\\w+) src \\S+:(?P<src_ip>[\\d.]+)/(?P<src_port>\\d+) dst \\S+:(?P<dst_ip>[\\d.]+)/(?P<dst_port>\\d+)',
       class_uid: 4001, activity_name: Traffic, status: Failure}
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from ..ocsf import COLUMNS, event
from .cef import map_cef, parse_cef
from .common import basename, zone

_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(.*)$", re.S)
_3164 = re.compile(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}:\d{2}:\d{2}) (?:(\S+) )?(.*)$", re.S)
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) (.*)$", re.S)
_TAG = re.compile(r"^([A-Za-z0-9_.\-/]{1,48})(?:\[(\d+)\])?: ?(.*)$", re.S)
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_SEV = {0: 4, 1: 4, 2: 4, 3: 3, 4: 2}          # syslog severity -> security severity (operational, so capped at high)


def parse_syslog(line: str, tz: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"pri": None, "time": None, "host": None, "app": None, "procid": None, "msg": line}
    s = line.strip()
    m = _PRI.match(s)
    if m:
        pri = int(m.group(1))
        out["pri"], out["facility"], out["severity"] = pri, pri >> 3, pri & 7
        s = s[m.end():]
    m = _5424.match(s)
    if m:
        ts, host, app, procid, _msgid, _sd, msg = m.groups()
        out.update(time=None if ts == "-" else ts, host=None if host == "-" else host,
                   app=None if app == "-" else app, procid=None if procid == "-" else procid, msg=msg.lstrip("﻿"))
        return out
    m = _ISO.match(s)
    if m:
        out["time"], out["host"], rest = m.group(1), m.group(2), m.group(3)
    else:
        m = _3164.match(s)
        if not m:
            return out
        mon, day, hms, host, rest = m.groups()
        n = now or datetime.now(timezone.utc)
        z = zone(tz)
        t = datetime(n.year, _MONTHS.get(mon, 1), int(day), *map(int, hms.split(":")), tzinfo=z)
        if t - n > timedelta(days=1):                      # December logs read in January
            t = t.replace(year=n.year - 1)
        out["time"] = t
        if host and _TAG.match(host + " ") and host.endswith(":"):   # no host field: "sshd[12]: msg"
            rest, host = f"{host} {rest}", None
        out["host"] = host
    t = _TAG.match(rest)
    if t:
        out["app"], out["procid"], out["msg"] = t.group(1), t.group(2), t.group(3)
    else:
        out["msg"] = rest
    return out


# --------------------------------------------------------------------------- LEEF (IBM QRadar Log Event Extended Format)
_LEEF = re.compile(r"LEEF:(1\.0|2\.0)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$", re.S)


def parse_leef(line: str) -> dict[str, Any] | None:
    i = line.find("LEEF:")
    if i < 0:
        return None
    m = _LEEF.match(line[i:].strip("\r\n"))
    if not m:
        return None
    ver, vendor, product, version, eid, rest = m.groups()
    delim = "\t"
    if ver == "2.0":                                   # LEEF 2.0 adds a delimiter field: "^", "x5E" or "0x5E"
        d, sep, rest2 = rest.partition("|")
        if sep and "=" not in d and len(d) <= 4:
            hexd = d[2:] if d.lower().startswith("0x") else d[1:] if d.lower().startswith("x") and len(d) > 1 else None
            try:
                delim = bytes.fromhex(hexd).decode() if hexd else (d or "\t")
            except ValueError:
                delim = "\t"
            rest = rest2
    attrs = {}
    for part in rest.split(delim):
        k, _, v = part.partition("=")
        if k.strip():
            attrs[k.strip()] = v.strip()
    return {"vendor": vendor, "product": product, "version": version, "event_id": eid, "attrs": attrs}


def map_leef(record: Any, settings: dict[str, Any], header_time: Any = None, host: str | None = None) -> list[dict[str, Any]]:
    line = record if isinstance(record, str) else (record or {}).get("message") or ""
    p = parse_leef(line)
    if not p:
        return []
    a = p["attrs"]
    cat = f"{a.get('cat', '')} {p['event_id']}".lower()
    url = a.get("url") or a.get("URL")
    if url:
        cls, act = 4002, a.get("method") or "Traffic"
    elif "dns" in cat:
        cls, act = 4003, "Query"
    elif any(w in cat for w in ("auth", "login", "logon", "vpn")):
        cls, act = 3002, "Logon"
    else:
        cls, act = 4001, "Traffic"
    sev = a.get("sev")
    sev_id = min(5, max(1, (int(sev) + 1) // 2)) if sev and sev.isdigit() else 1
    action = (a.get("action") or a.get("act") or "").lower() or None
    return [event(cls, time=a.get("devTime") or header_time, source=settings.get("key", "leef"), raw=line,
                  activity_name=act, product=f"{p['vendor']} {p['product']}".strip(), severity_id=sev_id,
                  src_ip=a.get("src"), src_port=a.get("srcPort"), dst_ip=a.get("dst"), dst_port=a.get("dstPort"),
                  user=a.get("usrName") or a.get("accountName"), device=a.get("identHostName") or host, url=url,
                  dst_domain=a.get("dstHostName") or a.get("domain"), action=action, message=p["event_id"],
                  status="Failure" if action in ("deny", "denied", "blocked", "block", "drop", "failure", "failed") else "Success")]


# --------------------------------------------------------------------------- patterns
_IP = r"[0-9A-Fa-f:.]+"
BUILTIN: list[dict[str, Any]] = [
    {"app": "sshd", "match": rf"Accepted (?P<auth_protocol>\S+) for (?P<user>\S+) from (?P<src_ip>{_IP}) port (?P<src_port>\d+)",
     "class_uid": 3002, "activity_name": "Logon", "status": "Success"},
    {"app": "sshd", "match": rf"Failed (?P<auth_protocol>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>{_IP}) port (?P<src_port>\d+)",
     "class_uid": 3002, "activity_name": "Logon", "status": "Failure", "severity_id": 2},
    {"app": "sshd", "match": rf"Invalid user (?P<user>\S+) from (?P<src_ip>{_IP})",
     "class_uid": 3002, "activity_name": "Logon", "status": "Failure", "severity_id": 2},
    {"app": "sudo", "match": r"^\s*(?P<user>\S+) : .*?USER=(?P<resource>\S+) ; COMMAND=(?P<process_cmdline>.+)$",
     "class_uid": 1007, "activity_name": "Launch", "status": "Success"},
    {"app": "useradd", "match": r"new user: name=(?P<resource>[^,\s]+)",
     "class_uid": 3001, "activity_name": "Create", "api_operation": "Create user"},
    {"app": "usermod", "match": r"add '(?P<resource>[^']+)' to group '(?P<message>[^']+)'",
     "class_uid": 3005, "activity_name": "Add", "api_operation": "Add member to group"},
]


@lru_cache(maxsize=256)
def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def _apply(patterns: list[dict[str, Any]], app: str | None, msg: str) -> dict[str, Any] | None:
    for p in patterns:
        if p.get("app") and (app or "").lower() != str(p["app"]).lower():
            continue
        m = _rx(p["match"]).search(msg)
        if m:
            fields = {k: v for k, v in m.groupdict().items() if v is not None and k in COLUMNS and k not in ("time", "class_uid")}
            for k in ("activity_name", "status", "api_operation", "severity_id", "action"):
                if p.get(k) is not None and k not in fields:
                    fields[k] = p[k]
            if "process_cmdline" in fields and "process_name" not in fields:
                fields["process_name"] = basename(fields["process_cmdline"].split()[0])
            return {"class_uid": int(p.get("class_uid", 0)), **fields}
    return None


_HOST_KEYS = ("host", "hostname", "_HOSTNAME", "HOSTNAME", "computer")
_APP_KEYS = ("SYSLOG_IDENTIFIER", "appname", "app_name", "ident", "program", "_COMM", "app")
_TIME_KEYS = ("@timestamp", "timestamp", "time", "date")


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        v = d.get(k)
        if isinstance(v, dict):                    # Elastic-style {"host": {"name": ...}}
            v = v.get("name") or v.get("hostname")
        if v not in (None, ""):
            return v
    return None


def map_syslog(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    """Raw syslog lines, or structured records from journald / Fluent Bit / Vector / Logstash that carry the message
    in `message` (or MESSAGE / log) with host, program and time beside it."""
    meta: dict[str, Any] = {}
    if isinstance(record, dict):
        line = record.get("message") or record.get("MESSAGE") or record.get("log") or record.get("raw") or ""
        meta = {"host": _first(record, _HOST_KEYS), "app": _first(record, _APP_KEYS), "time": _first(record, _TIME_KEYS)}
    else:
        line = record if isinstance(record, str) else ""
    if not line:
        return []
    line = str(line)
    key = settings.get("key", "syslog")
    h = parse_syslog(line, settings.get("timezone"))
    for k, v in meta.items():                      # structured fields win over what a bare message lacks
        if v and not h.get(k):
            h[k] = v
    if meta.get("time") and h["time"] and isinstance(h["time"], datetime) and h.get("pri") is None:
        h["time"] = meta["time"]
    msg, host, app = h["msg"] or "", h["host"], h["app"]
    for marker in ("CEF:", "LEEF:"):           # "host CEF:0|..." would otherwise read as app "CEF"
        if marker in line and marker not in msg:
            msg = line[line.find(marker):]
    if "CEF:" in msg:
        evs = map_cef(msg, settings)
        x = (parse_cef(msg) or {}).get("ext") or {}
        for ev in evs:
            if h["time"] and not (x.get("rt") or x.get("end") or x.get("start")):
                ev["time"] = event(0, time=h["time"])["time"]
            ev["device"] = ev.get("device") or (host.lower() if host else None)
            ev["raw"] = line
        return evs
    if "LEEF:" in msg:
        return map_leef(msg, settings, h["time"], host)
    body = msg.strip()
    if body.startswith("{"):
        try:
            obj = json.loads(body)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            if any(k in obj for k in ("EventID", "winlog", "EventId")):
                from .windows import map_windows
                return map_windows(obj, settings)
            if settings.get("field_map"):
                from .json_map import map_json
                return map_json(obj, settings)
    hit = _apply(list(settings.get("patterns") or []) + BUILTIN, app, msg)
    sev = _SEV.get(h.get("severity"), 1) if h.get("severity") is not None else 1
    common = dict(time=h["time"], source=key, raw=line, device=host, app_name=app,
                  product=settings.get("product") or app)
    if hit:
        cls = hit.pop("class_uid")
        hit.setdefault("severity_id", sev)
        hit.setdefault("message", msg[:2000])
        return [event(cls, **common, **hit)]
    if settings.get("keep_unparsed", True):
        return [event(0, activity_name="Log", severity_id=sev, message=msg[:4000], **common)]
    return []

