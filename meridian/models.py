"""Core records shared by detection, agents, cases and the API."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

SEVERITY_NAMES = {0: "unknown", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}
Verdict = Literal["benign", "suspicious", "malicious", "inconclusive"]
CaseStatus = Literal["new", "triaged", "investigating", "awaiting_approval", "contained", "closed"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Alert(BaseModel):
    alert_id: str
    rule_id: str
    title: str
    severity: int = Field(3, ge=0, le=6)
    mitre: list[str] = Field(default_factory=list)
    source: Literal["stream", "correlation", "vendor", "hunt"] = "stream"
    entity_type: str = "device"
    entity: str = ""
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    event_count: int = 1
    sample: list[dict[str, Any]] = Field(default_factory=list)   # up to 20 events, selected columns only
    description: str = ""
    tags: list[str] = Field(default_factory=list)

    @staticmethod
    def make_id(rule_id: str, entity: str, bucket: str) -> str:
        return "AL-" + hashlib.sha256(f"{rule_id}|{entity}|{bucket}".encode()).hexdigest()[:16]

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, "medium")


SAMPLE_FIELDS = ["time", "class_name", "activity_name", "status", "product", "user", "device", "device_id", "src_ip", "src_country",
                 "dst_ip", "dst_port", "dst_domain", "process_name", "process_cmdline", "parent_process_name",
                 "file_path", "file_sha256", "url", "dns_query", "action", "api_operation", "resource", "message",
                 "tags", "ioc_hits", "event_uid"]


def sample_event(ev: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k in SAMPLE_FIELDS:
        v = ev.get(k)
        if v in (None, ""):
            continue
        out[k] = v.isoformat() if isinstance(v, datetime) else (v[:500] if isinstance(v, str) else v)
    return out
