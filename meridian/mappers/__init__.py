"""Vendor record -> OCSF-flat event mappers. Register a new format with one function.

Each mapper takes one raw record (dict, or str for line formats) plus the source settings and
returns zero or more events. Mappers are deterministic and side-effect free; enrichment
(asset criticality, identity, IOC hits) happens afterwards in the pipeline.
"""
from __future__ import annotations

from typing import Any, Callable

from .cef import map_cef
from .cloudtrail import map_cloudtrail
from .entra import map_entra
from .json_map import map_json
from .mde import map_mde
from .ocsf_nested import map_ocsf
from .syslog import map_leef, map_syslog
from .windows import map_windows

Mapper = Callable[[Any, dict[str, Any]], list[dict[str, Any]]]
REGISTRY: dict[str, Mapper] = {
    "cef": map_cef,                 # firewalls, proxies, WAF, VPN, any syslog CEF sender
    "mde": map_mde,                 # Microsoft Defender XDR advanced-hunting streaming (Event Hubs / storage)
    "entra": map_entra,             # Entra ID sign-in + audit logs (diagnostic settings)
    "cloudtrail": map_cloudtrail,   # AWS CloudTrail records
    "ocsf": map_ocsf,               # any product that already emits OCSF (CrowdStrike, Okta, Zscaler, Security Lake ...)
    "syslog": map_syslog,           # mixed syslog feeds: RFC 5424/3164 + CEF / LEEF / JSON / patterns, nothing dropped
    "leef": map_leef,               # IBM LEEF 1.0 / 2.0 (QRadar-style senders)
    "windows": map_windows,         # Windows Security / System / Sysmon / PowerShell / Defender (NXLog, Winlogbeat, Fluent Bit, WEC XML)
    "json": map_json,               # anything else: field_map from the source config
}


def get_mapper(name: str) -> Mapper:
    try:
        return REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"unknown format '{name}'. Choose: {', '.join(sorted(REGISTRY))}") from exc
