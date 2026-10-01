"""Bearer-token gate in front of the MCP endpoints (/mcp/<server>/).

Who can call MCP tools, and with which scopes:
  * MERIDIAN agents running elsewhere (Foundry Agent Service, AgentCore Runtime, another container):
      MERIDIAN_AGENT_TOKENS="triage:<token>:lake:read+context:read,investigate:<token>:lake:read+context:read+..."
  * Microsoft Foundry / Amazon Bedrock AgentCore Gateway calling with an OIDC access token (managed identity /
    workload identity / OAuth client credentials): JWT verified against security.oidc; roles or groups are mapped
    to scopes by security.mcp_scope_map.
  * People (API keys, e.g. an analyst's MCP client in an IDE): role -> scopes (ROLE_SCOPES).
The server-side tool code checks the same scopes again (defence in depth).
"""
from __future__ import annotations

import hmac
import json
import os

from ..mcp_servers import CALLER, Caller
from .auth import principal_for_key

ROLE_SCOPES = {
    "viewer": {"lake:read", "context:read", "cases:read"},
    "analyst": {"lake:read", "context:read", "cases:read", "cases:write"},
    "responder": {"lake:read", "context:read", "cases:read", "cases:write", "response:request"},
    "admin": {"lake:read", "context:read", "cases:read", "cases:write", "response:request"},
}


def agent_tokens() -> dict[str, Caller]:
    out = {}
    for item in filter(None, os.environ.get("MERIDIAN_AGENT_TOKENS", "").split(",")):
        parts = item.strip().split(":", 2)
        if len(parts) != 3 or len(parts[1]) < 24:
            continue
        name, tok, scopes = parts
        out[tok] = Caller(f"agent:{name}", {s for s in scopes.split("+") if s}, "agent")
    return out


def resolve_caller(authz: str, oidc=None, scope_map: dict | None = None) -> Caller | None:
    if not authz.lower().startswith("bearer "):
        return None
    tok = authz[7:].strip()
    for known, caller in agent_tokens().items():
        if hmac.compare_digest(known.encode(), tok.encode()):
            return caller
    p = principal_for_key(tok)
    if p:
        return Caller(f"user:{p.actor}", ROLE_SCOPES.get(p.role, set()), "human")
    if oidc is not None and oidc.enabled and tok.count(".") == 2:
        try:
            claims = oidc.verify(tok, oidc.cfg.get("mcp_audience") or oidc.cfg.get("audience") or oidc.cfg["client_id"])
        except Exception:
            return None
        values = set()
        for c in ("roles", "groups", "scp"):
            v = claims.get(c)
            values |= set(v if isinstance(v, list) else str(v).split()) if v else set()
        scopes: set[str] = set()
        for v in values:
            scopes |= set((scope_map or {}).get(v, []))
        if not scopes:
            return None
        person = claims.get("preferred_username") or claims.get("email") or claims.get("upn")
        if person:                                 # delegated (user) token: a person, held to four-eyes
            return Caller(f"user:idp:{str(person).lower()}", scopes, "human")
        who = claims.get("azp") or claims.get("appid") or claims.get("client_id") or claims.get("sub")
        return Caller(f"service:{who}", scopes, "agent")
    return None


class MCPAuth:
    """ASGI middleware: authenticate, require the server's scope, bind the caller for the tool code."""

    def __init__(self, app, required_scope: str, oidc_getter=None, scope_map_getter=None, audit=None):
        self.app, self.required = app, required_scope
        self.oidc_getter, self.scope_map_getter, self.audit = oidc_getter, scope_map_getter, audit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        caller = resolve_caller(headers.get("authorization", ""), self.oidc_getter() if self.oidc_getter else None,
                                self.scope_map_getter() if self.scope_map_getter else None)
        if caller is None or self.required not in caller.scopes:
            code = 401 if caller is None else 403
            body = json.dumps({"error": "unauthorized" if code == 401 else f"missing scope {self.required}"}).encode()
            await send({"type": "http.response.start", "status": code,
                        "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
            await send({"type": "http.response.body", "body": body})
            if self.audit:
                self.audit(caller.id if caller else "anonymous", "mcp_denied", {"path": scope.get("path"), "code": code})
            return
        token = CALLER.set(caller)
        try:
            await self.app(scope, receive, send)
        finally:
            CALLER.reset(token)
