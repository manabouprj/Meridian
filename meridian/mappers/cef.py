"""ArcSight Common Event Format (CEF) over syslog: firewalls, proxies, WAF, VPN, IPS."""
from __future__ import annotations

import re
from typing import Any

from ..ocsf import event, severity_id

_HEADER = re.compile(r"CEF:(\d+)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|"
                     r"((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|(.*)$")
_KEY = re.compile(r"(?:^|\s)([A-Za-z0-9_.\-]+)=")


def _unescape(s: str) -> str:
    return s.replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\").replace("\\n", "\n").strip()


def parse_extension(ext: str) -> dict[str, str]:
    keys = list(_KEY.finditer(ext))
    out = {}
    for i, m in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(ext)
        out[m.group(1)] = _unescape(ext[m.end():end])
    return out


def parse_cef(line: str) -> dict[str, Any] | None:
    i = line.find("CEF:")
    if i < 0:
        return None
    m = _HEADER.match(line[i:].strip())
    if not m:
        return None
    _, vendor, product, version, sig, name, sev, ext = m.groups()
    return {"vendor": _unescape(vendor), "product": _unescape(product), "version": version, "signature": _unescape(sig),
            "name": _unescape(name), "severity": _unescape(sev), "ext": parse_extension(ext)}


_SEV_CEF = {"low": 2, "medium": 3, "high": 4, "very-high": 5, "very high": 5, "unknown": 0}


def map_cef(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    line = record if isinstance(record, str) else record.get("message") or record.get("raw") or ""
    p = parse_cef(line)
    if not p:
        return []
    x = p["ext"]
    sev_raw = p["severity"].lower()
    sev = _SEV_CEF.get(sev_raw) or (min(5, max(1, (int(sev_raw) + 1) // 2)) if sev_raw.isdigit() else severity_id(sev_raw))
    cat = (x.get("cat", "") + " " + p["name"]).lower()
    url = x.get("request") or x.get("requestURL")
    if url:
        cls, activity = 4002, x.get("requestMethod") or "Traffic"
    elif "dns" in cat or x.get("destinationDnsDomain"):
        cls, activity = 4003, "Query"
    elif any(w in cat for w in ("auth", "login", "logon", "vpn")):
        cls, activity = 3002, "Logon"
    else:
        cls, activity = 4001, "Traffic"
    act = (x.get("act") or x.get("deviceAction") or "").lower() or None
    return [event(
        cls, time=x.get("rt") or x.get("end") or x.get("start"), source=settings.get("key", "cef"), raw=line,
        activity_name=activity, severity_id=sev, product=f"{p['vendor']} {p['product']}".strip(),
        user=x.get("suser") or x.get("duser"), src_ip=x.get("src"), src_port=x.get("spt"), dst_ip=x.get("dst"),
        dst_port=x.get("dpt"), dst_domain=x.get("dhost") or x.get("destinationDnsDomain"), device=x.get("shost"),
        url=url, http_method=x.get("requestMethod"), dns_query=x.get("destinationDnsDomain") if cls == 4003 else None,
        action=act, app_name=x.get("app"), message=x.get("msg") or p["name"],
        status="Failure" if act in ("deny", "denied", "blocked", "block", "drop", "failure", "failed") else "Success",
    )]
