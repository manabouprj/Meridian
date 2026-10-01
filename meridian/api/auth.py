"""Authentication and authorisation for the MERIDIAN API, console and MCP endpoints.

(Shares its design with MERIDIAN: same OIDC / API-key / signed-session / CSRF model.)

Three ways in, one Principal out (actor, role, organisations):

1. API keys (automation, small teams)   MERIDIAN_API_KEYS="admin:<key>,responder:<key>,analyst:<key>,viewer:<key>"
   `role:key` sees every organisation, `role@org-key:key` only that organisation.
   Sent as header X-API-Key, or exchanged for a session at POST /login.
2. OIDC single sign-on (Entra ID, Okta, Google, Keycloak, Ping ...)   security.oidc in the config.
   Authorisation-code flow with PKCE; the ID token is verified against the issuer's JWKS.
   Roles and organisations come from token claims (groups / roles) through role_map / org_map.
3. Bearer JWT (service-to-service, e.g. an Entra app-role token)   Authorization: Bearer <jwt>,
   verified against the same issuer's JWKS and `audience`.

Browser sessions are an HMAC-signed cookie (MERIDIAN_SESSION_SECRET). Every state-changing request
authenticated by cookie must carry X-CSRF-Token equal to the meridian_csrf cookie (double submit);
header-authenticated calls (API key, bearer) are not exposed to CSRF.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from fastapi import HTTPException, Request

ROLE_RANK = {"viewer": 1, "analyst": 2, "responder": 3, "admin": 4}
SESSION_COOKIE, CSRF_COOKIE, FLOW_COOKIE = "meridian_session", "meridian_csrf", "meridian_oidc"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_EPHEMERAL = secrets.token_urlsafe(32)
_TRANSPORT = None


def set_transport(t) -> None:
    """Test hook: route identity-provider HTTP calls through an httpx transport."""
    global _TRANSPORT
    _TRANSPORT = t


def http_client(timeout: float = 15):
    import httpx
    kw = {"transport": _TRANSPORT} if _TRANSPORT is not None else {}
    return httpx.Client(timeout=timeout, trust_env=True, verify=True, **kw)


@dataclass
class Principal:
    actor: str
    role: str
    orgs: set[str] = field(default_factory=lambda: {"*"})
    via: str = "api-key"

    def can_see(self, org_key: str) -> bool:
        return "*" in self.orgs or org_key in self.orgs

    def at_least(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]


# ------------------------------------------------------------------ API keys
def api_keys() -> dict[str, Principal]:
    out: dict[str, Principal] = {}
    for i, pair in enumerate(filter(None, os.environ.get("MERIDIAN_API_KEYS", "").split(","))):
        who, _, key = pair.partition(":")
        role, _, org = who.strip().partition("@")
        key = key.strip()
        if role in ROLE_RANK and len(key) >= 16:
            out[key] = Principal(actor=f"key:{role}{'@' + org if org else ''}#{i + 1}", role=role,
                                 orgs={org} if org else {"*"}, via="api-key")
    return out


def principal_for_key(supplied: str) -> Principal | None:
    if not supplied:
        return None
    for key, p in api_keys().items():
        if secrets.compare_digest(key.encode(), supplied.encode()):
            return p
    return None


# ------------------------------------------------------------------ signed cookies
def _secret() -> bytes:
    return (os.environ.get("MERIDIAN_SESSION_SECRET") or _EPHEMERAL).encode()


def sign(data: dict[str, Any]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    mac = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def unsign(token: str | None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    body, mac = token.rsplit(".", 1)
    if not hmac.compare_digest(mac, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None
    return data if data.get("exp", 0) > time.time() else None


def session_cookie(p: Principal, hours: float = 8) -> str:
    return sign({"a": p.actor, "r": p.role, "o": sorted(p.orgs), "v": p.via, "exp": int(time.time() + hours * 3600)})


def principal_from_session(token: str | None) -> Principal | None:
    d = unsign(token)
    if not d or d.get("r") not in ROLE_RANK:
        return None
    return Principal(actor=d["a"], role=d["r"], orgs=set(d.get("o") or []), via=d.get("v", "session"))


def set_login_cookies(resp, p: Principal, secure: bool = True) -> None:
    resp.set_cookie(SESSION_COOKIE, session_cookie(p), httponly=True, samesite="lax", secure=secure, max_age=8 * 3600)
    resp.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(24), httponly=False, samesite="strict", secure=secure, max_age=8 * 3600)


def check_csrf(request: Request) -> None:
    if request.method in SAFE_METHODS:
        return
    cookie, header = request.cookies.get(CSRF_COOKIE, ""), request.headers.get("X-CSRF-Token", "")
    if not cookie or not hmac.compare_digest(cookie, header):
        raise HTTPException(403, "CSRF token missing or invalid - reload the dashboard")


# ------------------------------------------------------------------ OIDC
class OIDC:
    """Minimal, standards-based OIDC relying party (code + PKCE) with JWKS verification."""

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.issuer = str(cfg.get("issuer", "")).rstrip("/")
        self._meta: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._jwks_at = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True) and self.issuer and self.cfg.get("client_id"))

    def metadata(self) -> dict[str, Any]:
        if self._meta is None:
            with http_client(15) as c:
                r = c.get(self.cfg.get("discovery_url") or f"{self.issuer}/.well-known/openid-configuration")
                r.raise_for_status()
                self._meta = r.json()
        return self._meta

    def _key_for(self, token: str):
        """Signing key by kid from the issuer's JWKS (fetched through the corporate proxy / CA like every other call;
        refreshed hourly and immediately when an unknown kid appears - key rotation)."""
        import jwt
        kid = jwt.get_unverified_header(token).get("kid")
        stale = self._jwks is None or time.time() - self._jwks_at > 3600
        rotated = kid and self._jwks is not None and kid not in self._jwks and time.time() - self._jwks_at > 60
        if stale or rotated:            # unknown kid refetches at most once a minute (no amplification by bad tokens)
            with http_client(15) as c:
                r = c.get(self.metadata()["jwks_uri"])
                r.raise_for_status()
            keys = jwt.PyJWKSet.from_dict(r.json()).keys
            self._jwks = {k.key_id or "": k for k in keys}
            self._jwks_at = time.time()
        if kid in self._jwks:
            return self._jwks[kid].key
        if not kid and len(self._jwks) == 1:
            return next(iter(self._jwks.values())).key
        raise ValueError("token signed with an unknown key")

    def verify(self, token: str, audience: str | list[str], nonce: str | None = None) -> dict[str, Any]:
        import jwt
        claims = jwt.decode(token, self._key_for(token), algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"],
                            audience=audience, issuer=self.cfg.get("expected_issuer") or self.metadata().get("issuer", self.issuer),
                            options={"require": ["exp", "iat", "iss", "aud"]}, leeway=60)
        if nonce is not None and claims.get("nonce") != nonce:
            raise ValueError("nonce mismatch")
        return claims

    # authorisation-code flow
    def start(self, redirect_uri: str) -> tuple[str, str]:
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        q = {"response_type": "code", "client_id": self.cfg["client_id"], "redirect_uri": redirect_uri,
             "scope": self.cfg.get("scopes", "openid profile email"), "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        flow = sign({"s": state, "n": nonce, "v": verifier, "exp": int(time.time() + 600)})
        return f"{self.metadata()['authorization_endpoint']}?{urlencode(q)}", flow

    def finish(self, code: str, state: str, flow_cookie: str | None, redirect_uri: str) -> dict[str, Any]:
        flow = unsign(flow_cookie)
        if not flow or not hmac.compare_digest(flow["s"], state or ""):
            raise ValueError("login state expired or invalid - start again")
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": self.cfg["client_id"], "code_verifier": flow["v"]}
        if self.cfg.get("client_secret"):
            data["client_secret"] = self.cfg["client_secret"]
        with http_client(20) as c:
            tok = c.post(self.metadata()["token_endpoint"], data=data).json()
        if "id_token" not in tok:
            raise ValueError(f"token endpoint returned no id_token: {tok.get('error_description') or tok.get('error')}")
        return self.verify(tok["id_token"], self.cfg["client_id"], nonce=flow["n"])

    def principal(self, claims: dict[str, Any], via: str = "oidc") -> Principal:
        """Map claims to role + organisations. role_map / org_map keys are group ids, group names or app-role
        values found in the configured claims; the highest mapped role wins."""
        values: set[str] = set()
        for c in self.cfg.get("role_claims", ["groups", "roles"]):
            v = claims.get(c)
            values |= {str(x) for x in (v if isinstance(v, list) else [v] if v else [])}
        role_map, org_map = self.cfg.get("role_map") or {}, self.cfg.get("org_map") or {}
        roles = [role_map[v] for v in values if role_map.get(v) in ROLE_RANK]
        if not roles and self.cfg.get("default_role") in ROLE_RANK:
            roles = [self.cfg["default_role"]]
        if not roles:
            raise PermissionError("your account is not in any group mapped to a MERIDIAN role")
        orgs: set[str] = set()
        for v in values:
            m = org_map.get(v)
            orgs |= set(m if isinstance(m, list) else [m]) if m else set()
        if not org_map:
            orgs = {"*"}                       # single-organisation deployment
        if not orgs:
            raise PermissionError("your account is not in any group mapped to an organisation")
        actor = claims.get("preferred_username") or claims.get("email") or claims.get("upn") or claims.get("sub")
        return Principal(actor=f"{via}:{actor}", role=max(roles, key=ROLE_RANK.get), orgs=orgs, via=via)
