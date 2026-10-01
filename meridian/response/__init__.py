"""Human-approved response: approvals become actions only through `execute_approved`."""
from __future__ import annotations

from typing import Any

from ..identity import canonical_actor
from .actions import ACTIONS


class ApprovalError(Exception):
    def __init__(self, msg: str, code: int = 400):
        super().__init__(msg)
        self.code = code


def decide(store, approval_id: str, approve: bool, decided_by: str, role: str, response_cfg: dict[str, Any]) -> dict[str, Any]:
    """Record a human decision and, if approved, execute the action exactly once."""
    if role not in ("responder", "admin"):
        raise ApprovalError("only responders or admins can decide containment", 403)
    ap = store.get_approval(approval_id)
    if not ap:
        raise ApprovalError("approval not found", 404)
    if canonical_actor(ap["requested_by"]) == canonical_actor(decided_by):
        raise ApprovalError("the requester cannot approve their own request (four-eyes)", 403)
    if not store.decide_approval(approval_id, "approved" if approve else "rejected", decided_by):
        raise ApprovalError(f"approval is {store.get_approval(approval_id)['status']}, not pending (or it expired)", 409)
    store.audit(decided_by, "approval_decided", {"approval_id": approval_id, "approved": approve, "action": ap["action"],
                                                 "target": ap["target"], "case_id": ap["case_id"]})
    if not approve:
        store.add_note(ap["case_id"], decided_by, "human", f"Rejected {ap['action']} on {ap['target']}.")
        if not [x for x in store.list_approvals("pending") if x["case_id"] == ap["case_id"]]:
            store.update_case(ap["case_id"], status="investigating")
        return {"approval_id": approval_id, "status": "rejected"}
    return execute_approved(store, approval_id, response_cfg, decided_by)


def execute_approved(store, approval_id: str, response_cfg: dict[str, Any], actor: str) -> dict[str, Any]:
    ap = store.get_approval(approval_id)
    action = ACTIONS[ap["action"]]
    cfg = {**(response_cfg.get("defaults") or {}), **((response_cfg.get("actions") or {}).get(ap["action"]) or {}),
           "_store": store, **{k: v for k, v in response_cfg.items() if k.startswith("_")}}
    cfg.setdefault("dry_run", response_cfg.get("dry_run", True))
    params = {**(ap["params"] or {}), "case_id": ap["case_id"], "approved_by": actor}
    try:
        result = action.run(ap["target"], params, cfg)
        store.finish_approval(approval_id, "executed", result)
        store.update_case(ap["case_id"], status="contained")
        store.add_note(ap["case_id"], actor, "system",
                       f"{'DRY RUN - ' if result.get('dry_run') else ''}Executed {ap['action']} on {ap['target']} after approval.",
                       [result])
        store.audit(actor, "action_executed", {"approval_id": approval_id, "action": ap["action"], "target": ap["target"],
                                               "dry_run": bool(result.get("dry_run"))})
        return {"approval_id": approval_id, "status": "executed", "result": result}
    except Exception as exc:
        store.finish_approval(approval_id, "failed", {"error": f"{type(exc).__name__}: {exc}"[:500]})
        store.audit(actor, "action_failed", {"approval_id": approval_id, "error": str(exc)[:300]})
        return {"approval_id": approval_id, "status": "failed", "error": str(exc)[:300]}
