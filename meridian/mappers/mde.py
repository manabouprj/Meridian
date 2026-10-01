"""Microsoft Defender XDR advanced-hunting events (streaming API to Event Hubs or Storage).

Record shape: {"time": ..., "category": "AdvancedHunting-DeviceProcessEvents", "properties": {...}}
(the properties hold the advanced-hunting columns). A bare properties dict with "Table" also works.
"""
from __future__ import annotations

from typing import Any

from ..ocsf import event, severity_id


def map_mde(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return []
    table = str(record.get("category") or record.get("Table") or "").replace("AdvancedHunting-", "")
    p = record.get("properties") or record
    src = settings.get("key", "mde")
    common = dict(source=src, raw=record, time=p.get("Timestamp") or record.get("time"),
                  product="Microsoft Defender for Endpoint", device=p.get("DeviceName"), device_id=p.get("DeviceId"),
                  user=p.get("AccountUpn") or p.get("InitiatingProcessAccountUpn") or p.get("AccountName"))
    if table == "DeviceProcessEvents":
        return [event(1007, activity_name="Launch", process_name=p.get("FileName"),
                      process_cmdline=p.get("ProcessCommandLine"), parent_process_name=p.get("InitiatingProcessFileName"),
                      file_sha256=p.get("SHA256"), file_md5=p.get("MD5"), file_path=p.get("FolderPath"),
                      message=p.get("ActionType"), **common)]
    if table == "DeviceNetworkEvents":
        url = p.get("RemoteUrl")
        return [event(4002 if url else 4001, activity_name=p.get("ActionType") or "Traffic", dst_ip=p.get("RemoteIP"),
                      dst_port=p.get("RemotePort"), src_ip=p.get("LocalIP"), dst_domain=_host(url), url=url,
                      process_name=p.get("InitiatingProcessFileName"), action="blocked" if "Blocked" in str(p.get("ActionType")) else "allowed",
                      **common)]
    if table == "DeviceFileEvents":
        return [event(1001, activity_name=p.get("ActionType") or "Create", file_name=p.get("FileName"),
                      file_path=p.get("FolderPath"), file_sha256=p.get("SHA256"), file_md5=p.get("MD5"),
                      process_name=p.get("InitiatingProcessFileName"), **common)]
    if table == "DeviceLogonEvents":
        return [event(3002, activity_name="Logon", src_ip=p.get("RemoteIP"), auth_protocol=p.get("LogonType"),
                      status="Success" if p.get("ActionType") == "LogonSuccess" else "Failure", **common)]
    if table in ("AlertInfo", "AlertEvidence"):
        return [event(2004, activity_name="Create", severity_id=severity_id(p.get("Severity")), message=p.get("Title"),
                      file_sha256=p.get("SHA256"), dst_ip=p.get("RemoteIP"), url=p.get("RemoteUrl"), **common)]
    return []


def _host(url: str | None) -> str | None:
    if not url:
        return None
    u = url.split("://", 1)[-1]
    return u.split("/", 1)[0].split(":", 1)[0] or None
