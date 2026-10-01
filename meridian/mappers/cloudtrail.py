"""AWS CloudTrail records (S3 delivery, CloudTrail Lake export or EventBridge)."""
from __future__ import annotations

from typing import Any

from ..ocsf import event


def map_cloudtrail(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return []
    if "Records" in record:                      # a whole CloudTrail file
        return [e for r in record["Records"] for e in map_cloudtrail(r, settings)]
    if "eventName" not in record:
        return []
    ui = record.get("userIdentity") or {}
    user = ui.get("userName") or (ui.get("arn") or "").split("/")[-1] or ui.get("principalId")
    if ui.get("type") == "Root":
        user = "root"
    name = record["eventName"]
    failed = bool(record.get("errorCode")) or (record.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
    common = dict(time=record.get("eventTime"), source=settings.get("key", "cloudtrail"), raw=record,
                  product="AWS CloudTrail", user=user, src_ip=record.get("sourceIPAddress"),
                  cloud_account=record.get("recipientAccountId") or ui.get("accountId"),
                  cloud_region=record.get("awsRegion"), api_operation=name, status="Failure" if failed else "Success",
                  app_name=record.get("eventSource"), message=record.get("errorMessage") or name)
    if name == "ConsoleLogin":
        mfa = str((record.get("additionalEventData") or {}).get("MFAUsed", "No")).lower() == "yes"
        return [event(3002, activity_name="Logon", mfa=mfa, auth_protocol="console", **common)]
    req = record.get("requestParameters") or {}
    resource = (req.get("bucketName") or req.get("userName") or req.get("roleName") or req.get("groupId")
                or req.get("name") or req.get("instanceId") or (record.get("resources") or [{}])[0].get("ARN"))
    return [event(6003, activity_name=name, resource=str(resource) if resource else None, **common)]
