"""MERIDIAN event schema: OCSF classes, stored as one flat, typed table ("OCSF-flat").

Why flat: the same columns must be queryable from DuckDB, Amazon Athena and Azure Data Explorer
without per-engine JSON paths, and agents get a small, documented vocabulary. The full original
record is kept in `raw` (JSON) for forensics; the OCSF class / activity keep the semantics.
Columns are an allow-list: queries, rules and MCP tools can only reference these names.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import pyarrow as pa

# OCSF 1.x classes used by MERIDIAN (class_uid -> (class_name, category_name))
CLASSES: dict[int, tuple[str, str]] = {
    0: ("Base Event", "Uncategorized"),          # kept, searchable, not yet classified (e.g. unparsed syslog)
    1001: ("File System Activity", "System Activity"),
    1007: ("Process Activity", "System Activity"),
    2004: ("Detection Finding", "Findings"),
    3001: ("Account Change", "Identity & Access Management"),
    3002: ("Authentication", "Identity & Access Management"),
    3005: ("User Access Management", "Identity & Access Management"),
    4001: ("Network Activity", "Network Activity"),
    4002: ("HTTP Activity", "Network Activity"),
    4003: ("DNS Activity", "Network Activity"),
    4009: ("Email Activity", "Network Activity"),
    6003: ("API Activity", "Application Activity"),
}
CLASS_BY_NAME = {v[0].lower(): k for k, v in CLASSES.items()}

# column -> (arrow type, description). Order is the storage order.
COLUMNS: dict[str, tuple[pa.DataType, str]] = {
    "time": (pa.timestamp("ms", tz="UTC"), "event time (UTC)"),
    "class_uid": (pa.int32(), "OCSF class id, e.g. 3002 Authentication"),
    "class_name": (pa.string(), "OCSF class name"),
    "activity_name": (pa.string(), "OCSF activity, e.g. Logon, Launch, Create, Traffic, Query"),
    "severity_id": (pa.int8(), "0 unknown .. 1 info, 2 low, 3 medium, 4 high, 5 critical, 6 fatal"),
    "status": (pa.string(), "Success | Failure | Unknown"),
    "product": (pa.string(), "reporting product, e.g. Microsoft Defender for Endpoint"),
    "source": (pa.string(), "MERIDIAN source key that collected the event"),
    "user": (pa.string(), "normalised user (UPN / e-mail, lower case)"),
    "user_domain": (pa.string(), "user domain"),
    "src_ip": (pa.string(), "source IP"),
    "src_port": (pa.int32(), "source port"),
    "src_country": (pa.string(), "source country (ISO-2)"),
    "dst_ip": (pa.string(), "destination IP"),
    "dst_port": (pa.int32(), "destination port"),
    "dst_domain": (pa.string(), "destination host / domain"),
    "device": (pa.string(), "device hostname (lower case FQDN or short name)"),
    "device_id": (pa.string(), "device id from the reporting tool"),
    "device_ip": (pa.string(), "device IP"),
    "process_name": (pa.string(), "process image name"),
    "process_cmdline": (pa.string(), "process command line"),
    "parent_process_name": (pa.string(), "parent process image name"),
    "file_name": (pa.string(), "file name"),
    "file_path": (pa.string(), "file path"),
    "file_sha256": (pa.string(), "file SHA-256"),
    "file_md5": (pa.string(), "file MD5"),
    "url": (pa.string(), "URL"),
    "http_method": (pa.string(), "HTTP method"),
    "dns_query": (pa.string(), "DNS query name"),
    "action": (pa.string(), "allowed | blocked | quarantined | ... as reported"),
    "auth_protocol": (pa.string(), "authentication protocol / method"),
    "mfa": (pa.bool_(), "multi-factor satisfied"),
    "app_name": (pa.string(), "application / service principal name"),
    "cloud_account": (pa.string(), "cloud account / subscription / tenant"),
    "cloud_region": (pa.string(), "cloud region"),
    "api_operation": (pa.string(), "API operation, e.g. StopLogging, Add member to role"),
    "resource": (pa.string(), "target resource"),
    "message": (pa.string(), "human-readable summary"),
    "tags": (pa.string(), "; separated tags (asset criticality, crown_jewel, ioc ...)"),
    "ioc_hits": (pa.string(), "; separated threat-intel indicators matched at ingestion"),
    "event_uid": (pa.string(), "stable event id (de-duplication)"),
    "raw": (pa.string(), "original record (JSON) for forensics"),
}
SCHEMA = pa.schema([pa.field(k, t) for k, (t, _) in COLUMNS.items()])
STRING_COLUMNS = {k for k, (t, _) in COLUMNS.items() if pa.types.is_string(t)}
NUMERIC_COLUMNS = {k for k, (t, _) in COLUMNS.items() if pa.types.is_integer(t)}
QUERYABLE = [k for k in COLUMNS if k != "raw"]


def _ts(v: Any) -> datetime:
    """Parse a timestamp and normalise it to UTC (partitions and windows are UTC; offsets would misplace events)."""
    return _parse_ts(v).astimezone(timezone.utc)


def _parse_ts(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
    if isinstance(v, str) and v:
        s = v.strip().replace("Z", "+00:00")
        if "." in s:               # trim nanoseconds that fromisoformat cannot parse; keep the offset after them
            head, _, tail = s.partition(".")
            n = len(tail) - len(tail.lstrip("0123456789"))
            digits, rest = tail[:n], tail[n:]
            s = f"{head}.{digits[:6]}{rest}" if digits else f"{head}{rest}"
        try:
            d = datetime.fromisoformat(s)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def event(class_uid: int, *, time: Any = None, source: str = "", raw: Any = None, **fields: Any) -> dict[str, Any]:
    """Build one OCSF-flat event; unknown fields are rejected so mappers cannot drift from the schema."""
    unknown = set(fields) - set(COLUMNS)
    if unknown:
        raise KeyError(f"not in the MERIDIAN schema: {sorted(unknown)}")
    cname = CLASSES.get(class_uid, ("Unknown", ""))[0]
    ev: dict[str, Any] = {k: None for k in COLUMNS}
    ev.update(fields)
    ev.update({"time": _ts(time), "class_uid": class_uid, "class_name": cname, "source": source})
    for k in ("user", "device", "dst_domain", "dns_query"):
        if ev.get(k):
            ev[k] = str(ev[k]).strip().lower().rstrip(".")
    for k in ("src_port", "dst_port", "severity_id"):
        if ev.get(k) not in (None, ""):
            try:
                ev[k] = int(ev[k])
            except (TypeError, ValueError):
                ev[k] = None
        else:
            ev[k] = None
    if ev.get("severity_id") is None:
        ev["severity_id"] = 1
    for k in STRING_COLUMNS:
        if ev.get(k) is not None and not isinstance(ev[k], str):
            ev[k] = str(ev[k])
    if raw is not None and ev.get("raw") is None:
        ev["raw"] = raw if isinstance(raw, str) else json.dumps(raw, default=str, separators=(",", ":"))[:65536]
    if not ev.get("event_uid"):
        basis = ev.get("raw") or json.dumps({k: str(v) for k, v in ev.items() if v is not None}, sort_keys=True)
        ev["event_uid"] = hashlib.sha256(f"{source}|{basis}".encode()).hexdigest()[:32]
    return ev


SEVERITY_WORDS = {"informational": 1, "info": 1, "low": 2, "medium": 3, "moderate": 3, "high": 4, "critical": 5, "fatal": 6}


def severity_id(v: Any) -> int:
    if v is None:
        return 1
    if isinstance(v, (int, float)):
        n = float(v)
        return 5 if n >= 9 else 4 if n >= 7 else 3 if n >= 4 else 2 if n > 0 else 1
    s = str(v).strip().lower()
    if s.isdigit():
        return min(6, max(0, int(s)))
    return SEVERITY_WORDS.get(s, 1)


def to_table(events: list[dict[str, Any]]) -> pa.Table:
    cols = {k: [e.get(k) for e in events] for k in COLUMNS}
    return pa.Table.from_pydict(cols, schema=SCHEMA)


def describe_schema() -> list[dict[str, str]]:
    """Schema as shown to agents (via the MCP lake server) - names, types and meaning."""
    return [{"name": k, "type": str(t), "description": d} for k, (t, d) in COLUMNS.items() if k != "raw"]
