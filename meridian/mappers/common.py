"""Helpers shared by mappers: time zones for senders that log local time, path and account splitting."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache
from typing import Any

_HAS_ZONE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


class UnknownTimeZone(ValueError):
    pass


@lru_cache(maxsize=32)
def zone(name: str | None) -> tzinfo:
    """'+04:00', 'UTC' or an IANA name ('Asia/Dubai').

    An unknown name raises UnknownTimeZone instead of silently using UTC: a typo, or a Windows host without the
    time-zone database, would otherwise shift every event by hours with no error. The `tzdata` package (a
    dependency) supplies the IANA database where the operating system has none (Windows)."""
    if not name or str(name).strip().upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    m = _OFFSET.match(str(name).strip())
    if m:
        hours, minutes = int(m.group(2)), int(m.group(3))
        if hours > 14 or minutes > 59:
            raise UnknownTimeZone(f"time zone offset out of range: {name!r}")
        sign = -1 if m.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=hours, minutes=minutes))
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        return ZoneInfo(str(name).strip())
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise UnknownTimeZone(f"unknown time zone {name!r}: use an offset such as '+04:00' or an IANA name such as "
                              f"'Asia/Dubai' (on Windows, install the 'tzdata' package)") from exc


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
