"""Records that are already OCSF (nested JSON): Amazon Security Lake, CrowdStrike, Okta, Zscaler,
Palo Alto and many others can emit OCSF. This flattens them into the MERIDIAN columns."""
from __future__ import annotations

from typing import Any

from ..ocsf import CLASSES, event


def _get(d: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(d, list):
            d = d[0] if d else None
        if not isinstance(d, dict):
            return None
        d = d.get(part)
    return d


def _hash(file: dict | None, algo: int) -> str | None:
    for h in (file or {}).get("hashes") or []:
        if h.get("algorithm_id") == algo:
            return h.get("value")
    return None


def map_ocsf(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(record, dict) or "class_uid" not in record:
        return []
    cls = int(record["class_uid"])
    if cls not in CLASSES:
        return []
    g = lambda p: _get(record, p)  # noqa: E731
    file = g("file") or g("process.file")
    user = g("actor.user.email_addr") or g("actor.user.name") or g("user.email_addr") or g("user.name")
    return [event(
        cls, time=g("time") or g("time_dt"), source=settings.get("key", "ocsf"), raw=record,
        activity_name=g("activity_name"), severity_id=g("severity_id"), status=g("status"),
        product=g("metadata.product.name"), user=user, user_domain=g("actor.user.domain") or g("user.domain"),
        src_ip=g("src_endpoint.ip"), src_port=g("src_endpoint.port"), src_country=g("src_endpoint.location.country"),
        dst_ip=g("dst_endpoint.ip"), dst_port=g("dst_endpoint.port"),
        dst_domain=g("dst_endpoint.hostname") or g("dst_endpoint.domain") or g("http_request.url.hostname"),
        device=g("device.hostname") or g("device.name"), device_id=g("device.uid"), device_ip=g("device.ip"),
        process_name=g("process.name"), process_cmdline=g("process.cmd_line"),
        parent_process_name=g("process.parent_process.name"), file_name=(file or {}).get("name"),
        file_path=(file or {}).get("path"), file_sha256=_hash(file, 3) or _hash(file, 6), file_md5=_hash(file, 1),
        url=g("http_request.url.url_string") or g("url.url_string"), http_method=g("http_request.http_method"),
        dns_query=g("query.hostname"), action=g("disposition") or g("action"),
        auth_protocol=g("auth_protocol") or g("logon_type"), mfa=g("is_mfa"), app_name=g("service.name") or g("app_name"),
        cloud_account=g("cloud.account.uid"), cloud_region=g("cloud.region"), api_operation=g("api.operation"),
        resource=g("resources.name") or g("resources.uid"), message=g("message") or g("finding_info.title"),
        event_uid=g("metadata.uid"),
    )]
