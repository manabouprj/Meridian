"""Canonical identities shared by the API, the MCP servers and the approval logic."""
from __future__ import annotations


def canonical_actor(actor: str) -> str:
    """One identity per person across every path (console session, REST bearer JWT, MCP bearer): used for the
    four-eyes check. `user:` (MCP wrapper) is dropped; IdP identities (oidc:/bearer:) become `idp:<name>`."""
    a = (actor or "").strip()
    if a.startswith("user:"):
        a = a[5:]
    for pre in ("oidc:", "bearer:", "idp:"):
        if a.startswith(pre):
            return "idp:" + a[len(pre):].lower()
    return a
