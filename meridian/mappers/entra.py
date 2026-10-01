"""Microsoft Entra ID sign-in and audit logs (diagnostic settings -> Event Hubs / Storage)."""
from __future__ import annotations

from typing import Any

from ..ocsf import event

_RISK = {"high": 4, "medium": 3, "low": 2, "none": 1, "hidden": 1}


def map_entra(record: Any, settings: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return []
    cat = str(record.get("category", "")).lower()
    p = record.get("properties") or record
    src = settings.get("key", "entra")
    if "signin" in cat or "userPrincipalName" in p and "ipAddress" in p:
        err = (p.get("status") or {}).get("errorCode", 0)
        loc = p.get("location") or {}
        mfa = (p.get("authenticationRequirement") == "multiFactorAuthentication") or bool(
            (p.get("mfaDetail") or {}).get("authMethod"))
        risk = str(p.get("riskLevelDuringSignIn") or "none").lower()
        return [event(3002, time=p.get("createdDateTime") or record.get("time"), source=src, raw=record,
                      activity_name="Logon", product="Microsoft Entra ID", user=p.get("userPrincipalName"),
                      src_ip=p.get("ipAddress"), src_country=loc.get("countryOrRegion"),
                      status="Success" if str(err) in ("0", "") else "Failure", mfa=mfa,
                      auth_protocol=p.get("clientAppUsed"), app_name=p.get("appDisplayName"),
                      device=(p.get("deviceDetail") or {}).get("displayName"), severity_id=_RISK.get(risk, 1),
                      message=(p.get("status") or {}).get("failureReason") or f"sign-in ({risk} risk)",
                      cloud_account=p.get("tenantId") or record.get("tenantId"))]
    if "audit" in cat or "operationName" in p:
        actor = ((p.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName") or \
            ((p.get("initiatedBy") or {}).get("app") or {}).get("displayName")
        targets = p.get("targetResources") or [{}]
        op = p.get("operationName") or ""
        cls = 3005 if "role" in op.lower() or "member" in op.lower() else 3001 if "user" in op.lower() else 6003
        return [event(cls, time=p.get("activityDateTime") or record.get("time"), source=src, raw=record,
                      activity_name=op, product="Microsoft Entra ID", user=actor, api_operation=op,
                      resource=targets[0].get("userPrincipalName") or targets[0].get("displayName"),
                      status="Success" if str(p.get("result", "success")).lower() == "success" else "Failure",
                      message=op, cloud_account=record.get("tenantId"))]
    return []
