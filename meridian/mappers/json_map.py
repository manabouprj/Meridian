"""Generic JSON mapper driven by configuration - any product without a dedicated mapper.

source settings:
  format: json
  class_uid: 4002                      # fixed class, or
  class_field: eventType               # take the class from a field ...
  class_map: {login: 3002, dns: 4003}  # ... through this map
  field_map: {user: actor.email, src_ip: client.ip, url: request.url, time: ts, severity_id: risk}
"""
from __future__ import annotations

from typing import Any

from ..ocsf import COLUMNS, event, severity_id
from .ocsf_nested import _get


def map_json(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return []
    fm: dict[str, str] = settings.get("field_map") or {}
    cls = settings.get("class_uid")
    if settings.get("class_field"):
        cls = (settings.get("class_map") or {}).get(str(_get(record, settings["class_field"])), cls)
    if not cls:
        return []
    fields = {k: _get(record, path) for k, path in fm.items() if k in COLUMNS and k not in ("time", "class_uid")}
    if "severity_id" in fields:
        fields["severity_id"] = severity_id(fields["severity_id"])
    return [event(int(cls), time=_get(record, fm["time"]) if "time" in fm else None, source=settings.get("key", "json"),
                  raw=record, **{k: v for k, v in fields.items() if v is not None})]
