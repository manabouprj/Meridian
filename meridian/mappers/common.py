"""Helpers shared by mappers: time zones for senders that log local time, path and account splitting."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache
from typing import Any

_HAS_ZONE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


@lru_cache(maxsize=32)
def zone(name: str | None) -> tzinfo:
    """'+04:00', 'UTC' or an IANA name ('Asia/Dubai'). Unknown -> UTC (and the event keeps its raw time)."""
    if not name or str(name).upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    m = _OFFSET.match(str(name).strip())
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(str(name))
    except Exception:
        return timezone.utc


def local_time(value: Any, tz_name: str | None) -> Any:
    """Attach the source's time zone to a naive timestamp string ('2026-10-02 14:00:00' from NXLog, RFC 3164 ...).
    Values that already carry a zone, numbers and datetimes with tzinfo are returned unchanged."""
    if value is None or not tz_name:
        return value
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=zone(tz_name))
    if isinstance(value, str):
        s = value.strip()
        if not s or _HAS_ZONE.search(s):
            return value
        try:
            d = datetime.fromisoformat(s.replace(" ", "T", 1) if "T" not in s else s)
        except ValueError:
            return value
        return d.replace(tzinfo=zone(tz_name))
    return value


def basename(path: Any) -> str | None:
    if not path:
        return None
    return str(path).replace("/", "\\").rstrip("\\").split("\\")[-1] or None


def split_account(value: Any, domain: Any = None) -> tuple[str | None, str | None]:
    """'CORP\\j.doe' -> ('j.doe', 'CORP'); 'j.doe@corp.example' stays a UPN; '-' and machine accounts' '$' kept."""
    if value in (None, "", "-"):
        return None, (str(domain) if domain not in (None, "", "-") else None)
    v = str(value)
    if "\\" in v:
        d, _, u = v.partition("\\")
        return u or None, d or None
    return v, (str(domain) if domain not in (None, "", "-") else None)
