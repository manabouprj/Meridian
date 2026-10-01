"""Windows event logs: Security, System, Sysmon, PowerShell and Defender, from any common shipper.

Accepted record shapes (auto-detected, one mapper for all):
  * NXLog im_msvistalog + to_json()      {"EventID": 4624, "Channel": "Security", "Hostname": ..., "EventTime": ...,
                                           <event data fields at top level>}
  * Winlogbeat / Elastic Agent            {"@timestamp": ..., "winlog": {"event_id": .., "channel": .., "computer_name": ..,
                                           "event_data": {...}, "user_data": {...}}}
  * Fluent Bit winevtlog (event_data_as_map: true)  {"EventID": .., "Channel": .., "Computer": .., "TimeCreated": ..,
                                           "EventData": {...}}
  * Rendered XML (WEC ForwardedEvents, Fluent Bit render_event_as_xml, wevtutil)  "<Event xmlns=...>...</Event>"
  * Any of the above wrapped in a syslog line (NXLog CE om_ssl / om_tcp to MERIDIAN's syslog receiver).

settings:
  timezone: "+04:00" | Asia/Dubai     time zone of naive timestamps (NXLog EventTime is local time by default)
  keep_unmapped: true                 events without a specific mapping are kept as OCSF Base Event (class 0)

Sysmon's UtcTime is preferred when present: it is always UTC, whatever the shipper does with time zones.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import timezone
from typing import Any

from ..ocsf import event
from .common import basename, local_time, split_account

MAX_XML = 1 << 20
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _v(x: Any) -> Any:
    """Windows writes '-' or '%%1793'-style placeholders for empty values."""
    if x is None:
        return None
    if isinstance(x, dict):                       # xmltodict-style {"#text": "4624"}
        x = x.get("#text") or x.get("text") or x.get("Value")
    s = str(x).strip()
    return None if s in ("", "-", "N/A", "NULL") else s


def _ip(x: Any) -> str | None:
    s = _v(x)
    if not s:
        return None
    return s[7:] if s.lower().startswith("::ffff:") else s


def _hashes(s: Any) -> dict[str, str]:
    out = {}
    for part in str(s or "").split(","):
        k, _, v = part.partition("=")
        if v:
            out[k.strip().upper()] = v.strip().lower()
    return out


def _data_list(items: Any) -> dict[str, Any]:
    """EventData as [{"Name": "TargetUserName", "#text": "j.doe"}, ...] (XML-to-JSON converters)."""
    out: dict[str, Any] = {}
    for it in items if isinstance(items, list) else [items]:
        if isinstance(it, dict) and ("Name" in it or "@Name" in it):
            out[str(it.get("Name") or it.get("@Name"))] = it.get("#text", it.get("Value", it.get("text")))
    return out


def _from_xml(text: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if len(text) > MAX_XML or "<!DOCTYPE" in text or "<!ENTITY" in text:       # no entity tricks, no huge documents
        return None
    try:
        root = ET.fromstring(text[text.find("<Event"):])
    except ET.ParseError:
        return None
    sysn = root.find(f"{_NS}System")
    if sysn is None:
        return None
    meta = {
        "event_id": (sysn.findtext(f"{_NS}EventID") or "").strip(),
        "channel": sysn.findtext(f"{_NS}Channel"),
        "computer": sysn.findtext(f"{_NS}Computer"),
        "provider": (sysn.find(f"{_NS}Provider").attrib.get("Name") if sysn.find(f"{_NS}Provider") is not None else None),
        "time": (sysn.find(f"{_NS}TimeCreated").attrib.get("SystemTime") if sysn.find(f"{_NS}TimeCreated") is not None else None),
        "message": root.findtext(f"{_NS}RenderingInfo/{_NS}Message"),
    }
    data: dict[str, Any] = {}
    ed = root.find(f"{_NS}EventData")
    if ed is not None:
        for d in ed:
            if d.attrib.get("Name"):
                data[d.attrib["Name"]] = d.text
    ud = root.find(f"{_NS}UserData")
    if ud is not None:
        for child in ud:
            for d in child:
                data[d.tag.split("}")[-1]] = d.text
    return meta, data


def _normalise(record: Any) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """-> (meta: event_id, channel, computer, provider, time, message ; data: event data fields)."""
    if isinstance(record, str):
        s = record.strip()
        if "<Event" in s:
            return _from_xml(s)
        i = s.find("{")
        if i < 0:
            return None
        try:
            record = json.loads(s[i:])
        except ValueError:
            return None
    if not isinstance(record, dict):
        return None
    if isinstance(record.get("Event"), dict):                           # xmltodict of the whole <Event>
        ev = record["Event"]
        sysn = ev.get("System") or {}
        prov = sysn.get("Provider") or {}
        tc = sysn.get("TimeCreated") or {}
        data = _data_list((ev.get("EventData") or {}).get("Data"))
        for v in (ev.get("UserData") or {}).values():
            if isinstance(v, dict):
                data.update({k: _v(x) for k, x in v.items() if not k.startswith("@")})
        return ({"event_id": _v(sysn.get("EventID")), "channel": sysn.get("Channel"), "computer": sysn.get("Computer"),
                 "provider": prov.get("@Name") or prov.get("Name"), "time": tc.get("@SystemTime") or tc.get("SystemTime"),
                 "message": (ev.get("RenderingInfo") or {}).get("Message")}, data)
    w = record.get("winlog")
    if isinstance(w, dict):                                              # Winlogbeat / Elastic Agent
        data = dict(w.get("event_data") or {})
        data.update(w.get("user_data") or {})
        return ({"event_id": w.get("event_id") or (record.get("event") or {}).get("code"), "channel": w.get("channel"),
                 "computer": w.get("computer_name") or (record.get("host") or {}).get("name"),
                 "provider": w.get("provider_name"), "time": record.get("@timestamp"), "message": record.get("message")}, data)
    eid = record.get("EventID", record.get("EventId", record.get("event_id")))
    if eid is None:
        return None
    ed = record.get("EventData")
    if isinstance(ed, dict) and "Data" in ed:
        data = _data_list(ed["Data"])
    elif isinstance(ed, dict):
        data = dict(ed)                                                  # Fluent Bit event_data_as_map
    else:
        data = {k: v for k, v in record.items() if not isinstance(v, (dict, list))}   # NXLog: data at top level
    tc = record.get("TimeCreated")
    if isinstance(tc, dict):
        tc = tc.get("SystemTime") or tc.get("@SystemTime")
    return ({"event_id": _v(eid), "channel": record.get("Channel"),
             "computer": record.get("Hostname") or record.get("Computer") or record.get("ComputerName"),
             "provider": record.get("SourceName") or record.get("ProviderName") or record.get("Provider"),
             "time": tc or record.get("EventTime") or record.get("@timestamp") or record.get("EventReceivedTime"),
             "message": record.get("Message")}, data)


_ACCOUNT_OPS = {4720: "Create user", 4722: "Enable user", 4723: "Change password", 4724: "Reset password",
                4725: "Disable user", 4726: "Delete user", 4738: "Change user", 4781: "Rename user"}
_GROUP_ADD = {4728: "Add member to security group (global)", 4732: "Add member to security group (local)",
              4756: "Add member to security group (universal)"}
_GROUP_DEL = {4729: "Remove member from security group (global)", 4733: "Remove member from security group (local)",
              4757: "Remove member from security group (universal)"}


def map_windows(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    norm = _normalise(record)
    if not norm:
        return []
    m, d = norm
    try:
        eid = int(str(m["event_id"]).strip())
    except (TypeError, ValueError):
        return []
    channel = str(m.get("channel") or "")
    prov = str(m.get("provider") or "")
    kind = ("sysmon" if "sysmon" in (channel + prov).lower() else
            "powershell" if "powershell" in channel.lower() else
            "defender" if "windows defender" in channel.lower() else channel.lower())
    tz = settings.get("timezone")
    t = d.get("UtcTime")
    when = local_time(t, "UTC") if t else local_time(m.get("time"), tz)
    if hasattr(when, "astimezone"):
        when = when.astimezone(timezone.utc)
    device = _v(m.get("computer"))
    product = "Microsoft Sysmon" if kind == "sysmon" else "Microsoft Windows"
    common: dict[str, Any] = dict(time=when, source=settings.get("key", "windows"), raw=record, device=device,
                                  product=product)

    def actor() -> dict[str, Any]:
        u, dom = split_account(_v(d.get("SubjectUserName")) or _v(d.get("User")), _v(d.get("SubjectDomainName")))
        return {"user": u, "user_domain": dom}

    def proc(image_key: str = "Image", parent_key: str = "ParentImage") -> dict[str, Any]:
        h = _hashes(d.get("Hashes"))
        u, dom = split_account(_v(d.get("User")))
        return {"process_name": basename(_v(d.get(image_key))), "file_path": _v(d.get(image_key)),
                "process_cmdline": _v(d.get("CommandLine")), "parent_process_name": basename(_v(d.get(parent_key))),
                "file_sha256": h.get("SHA256"), "file_md5": h.get("MD5"), "user": u, "user_domain": dom}

    if kind == "sysmon":
        if eid == 1:
            return [event(1007, activity_name="Launch", message=_v(d.get("Description")), **proc(), **common)]
        if eid == 3:
            u, dom = split_account(_v(d.get("User")))
            return [event(4001, activity_name="Traffic", src_ip=_ip(d.get("SourceIp")), src_port=_v(d.get("SourcePort")),
                          dst_ip=_ip(d.get("DestinationIp")), dst_port=_v(d.get("DestinationPort")),
                          dst_domain=_v(d.get("DestinationHostname")), process_name=basename(_v(d.get("Image"))),
                          user=u, user_domain=dom, action="allowed", **common)]
        if eid in (8, 10):
            return [event(1007, activity_name="Inject" if eid == 8 else "Open", process_name=basename(_v(d.get("SourceImage"))),
                          file_path=_v(d.get("SourceImage")), resource=_v(d.get("TargetImage")),
                          message=f"GrantedAccess={_v(d.get('GrantedAccess'))}" if eid == 10 else _v(d.get("StartFunction")),
                          **common)]
        if eid in (11, 15, 23, 26):
            path = _v(d.get("TargetFilename"))
            h = _hashes(d.get("Hashes") or d.get("Hash"))
            return [event(1001, activity_name="Delete" if eid in (23, 26) else "Create", file_path=path, file_name=basename(path),
                          process_name=basename(_v(d.get("Image"))), file_sha256=h.get("SHA256"), file_md5=h.get("MD5"),
                          **common)]
        if eid == 22:
            return [event(4003, activity_name="Query", dns_query=_v(d.get("QueryName")),
                          process_name=basename(_v(d.get("Image"))), message=_v(d.get("QueryResults")), **common)]
        if eid in (5, 25):
            return [event(1007, activity_name="Terminate" if eid == 5 else "Tamper", **proc(), **common)]
        if eid in (12, 13, 14):
            return [event(0, activity_name="Registry", resource=_v(d.get("TargetObject")), process_name=basename(_v(d.get("Image"))),
                          message=f"{_v(d.get('EventType'))} {_v(d.get('Details')) or ''}".strip(), **common)]
    if kind == "security":
        if eid in (4624, 4625, 4634, 4647):
            u, dom = split_account(_v(d.get("TargetUserName")), _v(d.get("TargetDomainName")))
            lt = _v(d.get("LogonType"))
            return [event(3002, activity_name="Logon" if eid in (4624, 4625) else "Logoff", user=u, user_domain=dom,
                          src_ip=_ip(d.get("IpAddress")), src_port=_v(d.get("IpPort")),
                          auth_protocol=_v(d.get("AuthenticationPackageName")) or _v(d.get("LogonProcessName")),
                          status="Failure" if eid == 4625 else "Success", severity_id=2 if eid == 4625 else 1,
                          message=" ".join(x for x in (f"logon type {lt}" if lt else "", f"workstation {_v(d.get('WorkstationName'))}"
                                                       if _v(d.get("WorkstationName")) else "",
                                                       f"status {_v(d.get('SubStatus')) or _v(d.get('Status'))}" if eid == 4625 else "")
                                           if x) or None, **common)]
        if eid == 4648:
            return [event(3002, activity_name="Explicit credentials", **actor(), resource=_v(d.get("TargetUserName")),
                          dst_domain=_v(d.get("TargetServerName")), src_ip=_ip(d.get("IpAddress")),
                          process_name=basename(_v(d.get("ProcessName"))), status="Success", **common)]
        if eid in (4768, 4769, 4771, 4776):
            u, dom = split_account(_v(d.get("TargetUserName")), _v(d.get("TargetDomainName")))
            st = (_v(d.get("Status")) or "0x0").lower()
            return [event(3002, activity_name={4768: "Kerberos TGT", 4769: "Kerberos service ticket", 4771: "Kerberos pre-auth",
                                               4776: "NTLM validation"}[eid], user=u, user_domain=dom,
                          src_ip=_ip(d.get("IpAddress")), auth_protocol="NTLM" if eid == 4776 else "Kerberos",
                          resource=_v(d.get("ServiceName")), status="Success" if st in ("0x0", "0") else "Failure",
                          message=f"encryption {_v(d.get('TicketEncryptionType'))}" if eid == 4769 else f"status {st}",
                          **common)]
        if eid == 4672:
            return [event(3005, activity_name="Assign privileges", **actor(), message=_v(d.get("PrivilegeList")), **common)]
        if eid == 4688:
            return [event(1007, activity_name="Launch", **actor(), process_name=basename(_v(d.get("NewProcessName"))),
                          file_path=_v(d.get("NewProcessName")), process_cmdline=_v(d.get("CommandLine")),
                          parent_process_name=basename(_v(d.get("ParentProcessName"))), **common)]
        if eid in _ACCOUNT_OPS or eid in (4740, 4767):
            if eid in (4740, 4767):
                u, dom = split_account(_v(d.get("TargetUserName")), _v(d.get("TargetDomainName")))
                return [event(3001, activity_name="Lock" if eid == 4740 else "Unlock", user=u, user_domain=dom,
                              api_operation="Account locked out" if eid == 4740 else "Account unlocked",
                              resource=_v(d.get("TargetUserName")), severity_id=3 if eid == 4740 else 1,
                              src_ip=None, message=_v(d.get("SubjectUserName")), **common)]
            return [event(3001, activity_name=_ACCOUNT_OPS[eid].split()[0], api_operation=_ACCOUNT_OPS[eid], **actor(),
                          resource=_v(d.get("TargetUserName")), **common)]
        if eid in _GROUP_ADD or eid in _GROUP_DEL:
            op = _GROUP_ADD.get(eid) or _GROUP_DEL[eid]
            return [event(3005, activity_name="Add" if eid in _GROUP_ADD else "Remove", api_operation=op, **actor(),
                          resource=_v(d.get("TargetUserName")), message=_v(d.get("MemberName")) or _v(d.get("MemberSid")),
                          severity_id=2, **common)]
        if eid in (4697, 4698, 4702):
            name = _v(d.get("ServiceName")) or _v(d.get("TaskName"))
            op = {4697: "Install service", 4698: "Create scheduled task", 4702: "Update scheduled task"}[eid]
            body = _v(d.get("ServiceFileName")) or _v(d.get("TaskContent"))
            return [event(6003, activity_name="Create", api_operation=op, **actor(), resource=name,
                          process_cmdline=(body or "")[:4000] or None, severity_id=2, **common)]
        if eid == 1102:
            return [event(6003, activity_name="Clear", api_operation="Clear security log", **actor(), severity_id=4,
                          message="The Security event log was cleared", **common)]
    if kind == "system":
        if eid == 7045:
            return [event(6003, activity_name="Create", api_operation="Install service", resource=_v(d.get("ServiceName")),
                          process_cmdline=_v(d.get("ImagePath")), user=_v(d.get("AccountName")), severity_id=2, **common)]
        if eid == 104:
            return [event(6003, activity_name="Clear", api_operation="Clear event log", resource=_v(d.get("Channel")),
                          user=_v(d.get("SubjectUserName")), severity_id=4, message="An event log was cleared", **common)]
    if kind == "powershell" and eid == 4104:
        return [event(1007, activity_name="Script", process_name="powershell.exe", file_path=_v(d.get("Path")),
                      message=(_v(d.get("ScriptBlockText")) or "")[:4000] or None, **common)]
    if kind == "defender" and eid in (1006, 1116, 1117):
        return [event(2004, activity_name="Create", severity_id=4, message=_v(d.get("Threat Name")) or _v(d.get("ThreatName")),
                      file_path=_v(d.get("Path")), action=_v(d.get("Action Name")) or ("detected" if eid == 1116 else "remediated"),
                      product="Microsoft Defender Antivirus", **{k: v for k, v in common.items() if k != "product"})]
    if settings.get("keep_unmapped", True):
        return [event(0, activity_name=f"{channel or prov or 'Windows'} {eid}", message=(_v(m.get("message")) or "")[:2000] or None,
                      **common)]
    return []
