"""MERIDIAN API, analyst console and MCP endpoints.

  /healthz /readyz /metrics                         operations
  /login /logout /auth/login /auth/callback         sign-in (API key or OIDC SSO)
  /  /cases/<id>                                    analyst console (cases, approvals, alerts, agent runs)
  /api/cases /api/alerts /api/approvals /api/runs   REST (role-gated; POSTs need CSRF when cookie-authenticated)
  /api/approvals/<id>/approve|reject                human decision -> executes the action (four-eyes)
  /api/ingest/<source>                              HTTPS push into the landing zone (HMAC-signed or source token)
  /services/collector[/event|/raw]                  Splunk HEC-compatible push (token bound to one source)
  /edl/ip.txt /edl/domain.txt                       external dynamic block lists for firewalls / proxies
  /mcp/lake/ /mcp/context/ /mcp/cases/ /mcp/response/   MCP streamable HTTP for agents (bearer + scopes)
"""
from __future__ import annotations

import base64
import contextlib
import hmac
import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..runtime import Runtime
from .auth import (
    CSRF_COOKIE,
    FLOW_COOKIE,
    OIDC,
    SESSION_COOKIE,
    Principal,
    check_csrf,
    principal_for_key,
    principal_from_session,
    set_login_cookies,
)
from .mcp_auth import MCPAuth

MAX_INGEST = 10 * 1024 * 1024
TEMPLATES = Environment(loader=FileSystemLoader(str(Path(__file__).resolve().parent.parent / "web" / "templates")),
                        autoescape=select_autoescape(["html"]))


@lru_cache(maxsize=1)
def rt() -> Runtime:
    return Runtime.load()


@lru_cache(maxsize=1)
def oidc() -> OIDC:
    return OIDC(rt().settings.security.get("oidc") or {})


def reset() -> None:
    rt.cache_clear()
    oidc.cache_clear()


def _secure() -> bool:
    return bool(rt().settings.security.get("secure_cookies", True))


def principal(request: Request) -> Principal:
    s = rt().settings
    if not s.security.get("require_auth", True) and s.cloud == "local" and os.environ.get("MERIDIAN_DEV_OPEN") == "1":
        return Principal(actor="local-dev", role="admin", via="open")
    key = request.headers.get("X-API-Key")
    if key:
        p = principal_for_key(key)
        if p:
            return p
        raise HTTPException(401, "Invalid API key")
    authz = request.headers.get("Authorization", "")
    if authz.lower().startswith("bearer ") and oidc().enabled:
        try:
            return oidc().principal(oidc().verify(authz[7:].strip(), oidc().cfg.get("audience") or oidc().cfg["client_id"]), via="bearer")
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(401, "Invalid bearer token") from exc
    p = principal_from_session(request.cookies.get(SESSION_COOKIE))
    if p:
        check_csrf(request)
        return p
    raise HTTPException(401, "Sign in at /login, or send X-API-Key / Authorization: Bearer")


def need(role: str):
    def dep(request: Request) -> Principal:
        p = principal(request)
        if not p.at_least(role):
            raise HTTPException(403, f"Requires role '{role}'")
        return p
    return dep


# ------------------------------------------------------------------ MCP mounts + lifespan
_MCP_APPS: dict[str, object] = {}


def _mcp_apps():
    if not _MCP_APPS:
        from ..mcp_servers import SERVER_SCOPES
        for name, srv in rt().mcp_servers.items():
            inner = srv.streamable_http_app(streamable_http_path="/", stateless_http=True, json_response=True,
                                            host="0.0.0.0")
            _MCP_APPS[name] = (srv, MCPAuth(inner, SERVER_SCOPES[name], oidc,
                                             lambda: rt().settings.security.get("mcp_scope_map") or {}, rt().store.audit))
    return _MCP_APPS


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    async with contextlib.AsyncExitStack() as stack:
        for name, (srv, wrapped) in _mcp_apps().items():
            await stack.enter_async_context(srv.session_manager.run())
            app.mount(f"/mcp/{name}", wrapped)
        yield


app = FastAPI(title="MERIDIAN", version=__version__, lifespan=lifespan,
              description="SIEM-less detection, investigation and response with AI agents over MCP",
              # interactive API docs reveal the API surface: opt-in only (MERIDIAN_API_DOCS=1, e.g. in development)
              docs_url="/docs" if os.environ.get("MERIDIAN_API_DOCS") == "1" else None,
              redoc_url="/redoc" if os.environ.get("MERIDIAN_API_DOCS") == "1" else None,
              openapi_url="/openapi.json" if os.environ.get("MERIDIAN_API_DOCS") == "1" else None)
_STATS = {"requests": 0, "errors": 0}


@app.middleware("http")
async def headers_mw(request: Request, call_next):
    resp = await call_next(request)
    _STATS["requests"] += 1
    if resp.status_code >= 500:
        _STATS["errors"] += 1
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
    if _secure():
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


# ------------------------------------------------------------------ ops
@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"


@app.get("/readyz")
def readyz():
    checks = {}
    try:
        checks["store"] = rt().store.ping()
    except Exception as exc:
        return JSONResponse({"ready": False, "store": type(exc).__name__}, status_code=503)
    checks["rules"] = len(rt().rules)
    checks["rule_errors"] = len(getattr(rt(), "rule_errors", []))
    checks["heartbeats"] = heartbeat_ages(rt().store)
    unset = placeholder_secrets()
    if unset:                                   # Terraform placeholders never reach production traffic
        return JSONResponse({"ready": False, "placeholder_secrets": unset, **checks}, status_code=503)
    return JSONResponse({"ready": True, **checks})


PLACEHOLDERS = {"set-me", "replace_me", "replace-me", "changeme"}
SECRET_ENV = ("MERIDIAN_API_KEYS", "MERIDIAN_SESSION_SECRET", "MERIDIAN_INGEST_SECRET", "MERIDIAN_EDL_TOKEN",
              "MERIDIAN_METRICS_TOKEN", "MERIDIAN_AGENT_TOKENS", "MERIDIAN_INGEST_TOKENS", "OIDC_CLIENT_SECRET",
              "LODESTAR_WEBHOOK_SECRET")


def placeholder_secrets() -> list[str]:
    """Secrets still holding a Terraform placeholder or an .env.example value (change-me-...)."""
    def bad(v: str) -> bool:
        v = v.strip().lower()
        return v in PLACEHOLDERS or v.startswith(("change-me", "changeme", "set-me", "replace-me", "replace_me"))
    return [k for k in SECRET_ENV if bad(os.environ.get(k, ""))]


def heartbeat_ages(store) -> dict[str, int | None]:
    """Seconds since each background role last reported (None = never seen by this store)."""
    out: dict[str, int | None] = {}
    nowt = datetime.now(timezone.utc)
    for role in ("worker", "agents", "scheduler", "collector"):
        v = store.get_cursor(f"heartbeat:{role}")
        try:
            out[role] = int((nowt - datetime.fromisoformat(v)).total_seconds()) if v else None
        except ValueError:
            out[role] = None
    return out


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    tok = os.environ.get("MERIDIAN_METRICS_TOKEN", "")
    if not tok or not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {tok}"):
        raise HTTPException(401, "metrics token required")
    st = rt().store
    lines = [f'meridian_build_info{{version="{__version__}"}} 1']
    for k, v in st.queue_depth().items():
        kind, status = k.split(":")
        lines.append(f'meridian_work_items{{kind="{kind}",status="{status}"}} {v}')
    for status in ("new", "triaged", "investigating", "awaiting_approval", "contained", "closed"):
        lines.append(f'meridian_cases{{status="{status}"}} {len(st.list_cases(status=status, limit=10000))}')
    lines.append(f"meridian_approvals_pending {len(st.list_approvals('pending'))}")
    for src, seen in st.source_last_seen([(s.get("prefix") or s["key"]).strip("/") for s in rt().settings.sources]).items():
        age = int((datetime.now(timezone.utc) - seen).total_seconds()) if seen else -1
        lines.append(f'meridian_source_last_batch_age_seconds{{source="{src}"}} {age}')
    for src, q in sorted(st.ingest_quality(24).items()):     # normalisation health: alert on a rising reject ratio
        lines.append(f'meridian_ingest_events_24h{{source="{src}"}} {q["events"]}')
        lines.append(f'meridian_ingest_rejected_24h{{source="{src}"}} {q["rejected"]}')
    for s in rt().settings.sources:
        if isinstance(s.get("pull"), dict):
            ok = st.get_cursor(f"pull:{s['key']}:last_status")
            lines.append(f'meridian_pull_last_run_ok{{source="{s["key"]}"}} {1 if ok == "ok" else 0}')
    for role, age in heartbeat_ages(st).items():
        if age is not None:
            lines.append(f'meridian_heartbeat_age_seconds{{role="{role}"}} {age}')
    if (rt().settings.lodestar or {}).get("url"):        # LODESTAR hand-off: alert when age > 2 h or status != 2xx
        last = st.get_cursor("scheduler:lodestar_push")
        age = int((datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds()) if last else -1
        lines.append(f"meridian_lodestar_last_push_age_seconds {age}")
        code = st.get_cursor("lodestar:last_status")
        lines.append(f"meridian_lodestar_last_push_status {int(code) if code and code.isdigit() else 0}")
    day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    lines.append(f"meridian_model_spend_usd_today {st.spend_since(day):.4f}")
    lines.append(f"meridian_http_requests_total {_STATS['requests']}")
    lines.append(f"meridian_http_errors_total {_STATS['errors']}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ sign-in
@app.get("/login", response_class=HTMLResponse)
def login_form(error: str = ""):
    return TEMPLATES.get_template("login.html").render(sso=oidc().enabled, error=error[:200])


@app.post("/login")
def login(key: str = Form(...)):
    p = principal_for_key(key)
    if not p:
        raise HTTPException(401, "Invalid key")
    resp = RedirectResponse("/", status_code=303)
    set_login_cookies(resp, p, secure=_secure())
    rt().store.audit(p.actor, "login", {"via": "api-key"})
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    for c in (SESSION_COOKIE, CSRF_COOKIE):
        resp.delete_cookie(c)
    return resp


def _redirect_uri(request: Request) -> str:
    return oidc().cfg.get("redirect_uri") or str(request.url_for("oidc_callback"))


@app.get("/auth/login")
def oidc_login(request: Request):
    if not oidc().enabled:
        raise HTTPException(404, "single sign-on is not configured")
    url, flow = oidc().start(_redirect_uri(request))
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(FLOW_COOKIE, flow, httponly=True, samesite="lax", secure=_secure(), max_age=600)
    return resp


@app.get("/auth/callback", name="oidc_callback")
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse("/login?error=Sign-in was cancelled or refused", status_code=303)
    try:
        p = oidc().principal(oidc().finish(code, state, request.cookies.get(FLOW_COOKIE), _redirect_uri(request)))
    except PermissionError as exc:
        rt().store.audit("oidc", "login_denied", {"reason": str(exc)})
        return RedirectResponse("/login?error=Your account is not mapped to a MERIDIAN role", status_code=303)
    except Exception as exc:
        rt().store.audit("oidc", "login_failed", {"error": f"{type(exc).__name__}: {exc}"[:300]})
        return RedirectResponse("/login?error=Single sign-on failed", status_code=303)
    resp = RedirectResponse("/", status_code=303)
    set_login_cookies(resp, p, secure=_secure())
    resp.delete_cookie(FLOW_COOKIE)
    rt().store.audit(p.actor, "login", {"via": "oidc", "role": p.role})
    return resp


# ------------------------------------------------------------------ console
@app.get("/", response_class=HTMLResponse)
def console(request: Request):
    try:
        p = principal(request)
    except HTTPException:
        return RedirectResponse("/login")
    st = rt().store
    return TEMPLATES.get_template("console.html").render(
        me=p, org=rt().settings.org, cases=st.list_cases(active_only=True, limit=100), approvals=st.list_approvals("pending"),
        alerts=st.list_alerts(limit=60), runs=st.list_runs(limit=30), version=__version__)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_page(case_id: str, request: Request):
    try:
        p = principal(request)
    except HTTPException:
        return RedirectResponse("/login")
    case = rt().store.get_case(case_id)
    if not case:
        raise HTTPException(404, "case not found")
    return TEMPLATES.get_template("case.html").render(me=p, case=case, org=rt().settings.org, version=__version__,
                                                       runs=rt().store.list_runs(limit=20, ref=case_id))


# ------------------------------------------------------------------ REST
@app.get("/api/me")
def me(p: Principal = Depends(need("viewer"))):
    return {"actor": p.actor, "role": p.role, "via": p.via}


@app.get("/api/cases")
def api_cases(status: str | None = None, p: Principal = Depends(need("viewer"))):
    return rt().store.list_cases(status=status, active_only=status is None)


@app.get("/api/cases/{case_id}")
def api_case(case_id: str, p: Principal = Depends(need("viewer"))):
    c = rt().store.get_case(case_id)
    if not c:
        raise HTTPException(404, "case not found")
    return c


@app.post("/api/cases/{case_id}/close")
async def api_close(case_id: str, request: Request, p: Principal = Depends(need("analyst"))):
    body = await _json(request)
    if not rt().store.get_case(case_id):
        raise HTTPException(404, "case not found")
    verdict = body.get("verdict", "benign")
    if verdict not in ("benign", "malicious", "suspicious", "inconclusive"):
        raise HTTPException(400, "bad verdict")
    rt().store.update_case(case_id, status="closed", verdict=verdict)
    rt().store.add_note(case_id, p.actor, "human", f"Closed as {verdict}. {str(body.get('note', ''))[:2000]}")
    rt().store.audit(p.actor, "case_closed", {"case_id": case_id, "verdict": verdict})
    return {"case_id": case_id, "status": "closed"}


@app.get("/api/alerts")
def api_alerts(status: str | None = None, limit: int = Query(200, le=2000), p: Principal = Depends(need("viewer"))):
    return rt().store.list_alerts(status=status, limit=limit)


@app.get("/api/approvals")
def api_approvals(status: str | None = "pending", p: Principal = Depends(need("viewer"))):
    return rt().store.list_approvals(status)


@app.post("/api/approvals/{approval_id}/{decision}")
def api_decide(approval_id: str, decision: str, p: Principal = Depends(need("responder"))):
    from ..response import ApprovalError, decide
    if decision not in ("approve", "reject"):
        raise HTTPException(404, "use approve or reject")
    try:
        return decide(rt().store, approval_id, decision == "approve", p.actor, p.role, rt().settings.response)
    except ApprovalError as exc:
        raise HTTPException(exc.code, str(exc)) from exc


@app.get("/api/runs")
def api_runs(ref: str | None = None, p: Principal = Depends(need("analyst"))):
    return rt().store.list_runs(limit=200, ref=ref)


@app.post("/api/hunt")
async def api_hunt(request: Request, p: Principal = Depends(need("analyst"))):
    """Queue a hunt for the agents service; poll GET /api/hunt/{hunt_id} for the result."""
    body = await _json(request)
    hypothesis = str(body.get("hypothesis", "")).strip()[:2000]
    if not hypothesis:
        raise HTTPException(400, "hypothesis is required")
    try:
        hours = max(1, min(int(body.get("hours", 168)), 24 * 30))
    except (TypeError, ValueError):
        raise HTTPException(400, "hours must be an integer") from None
    hunt_id = rt().agent_service.request_hunt(hypothesis, [str(x) for x in body.get("indicators", [])][:200], hours, p.actor)
    rt().store.audit(p.actor, "hunt_requested", {"hunt_id": hunt_id, "hypothesis": hypothesis[:300]})
    return JSONResponse({"hunt_id": hunt_id, "status": "queued"}, status_code=202)


@app.get("/api/hunt/{hunt_id}")
def api_hunt_result(hunt_id: str, p: Principal = Depends(need("analyst"))):
    h = rt().agent_service.get_hunt(hunt_id)
    if not h:
        raise HTTPException(404, "hunt not found")
    return h


@app.post("/api/agents/{kind}/{action}")
def api_agent_switch(kind: str, action: str, request: Request, p: Principal = Depends(need("responder"))):
    """Kill switch: any responder may halt an agent (or all); only an admin may resume. Halting is always safe."""
    from ..agents.definitions import DEFAULT_AGENTS
    if kind != "all" and kind not in DEFAULT_AGENTS:
        raise HTTPException(404, "unknown agent")
    if action not in ("halt", "resume"):
        raise HTTPException(404, "action must be halt or resume")
    if action == "resume" and p.role != "admin":
        raise HTTPException(403, "only an admin can resume a halted agent")
    st = rt().store
    if action == "halt":
        st.set_cursor(f"halt:{kind}", json.dumps({"by": p.actor, "at": datetime.now(timezone.utc).isoformat()}))
    else:
        st.delete_cursor(f"halt:{kind}")
    st.audit(p.actor, "agent_halted" if action == "halt" else "agent_resumed", {"agent": kind})
    return {"agent": kind, "status": "halted" if action == "halt" else "running"}


@app.get("/api/audit")
def api_audit(limit: int = Query(200, le=5000), p: Principal = Depends(need("admin"))):
    ok, n = rt().store.verify_audit()
    return {"chain_valid": ok, "entries_verified": n, "recent": rt().store.recent_audit(limit)}


async def _json(request: Request) -> dict:
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "Body must be a JSON object") from exc
    if not isinstance(body, dict):
        raise HTTPException(400, "Body must be a JSON object")
    return body


# ------------------------------------------------------------------ ingestion (HTTPS push)
def _push_source(source: str) -> dict:
    src = next((s for s in rt().settings.sources if s["key"] == source and s.get("enabled", True)), None)
    if src is None or src.get("push") is False:
        raise HTTPException(404, "unknown source")
    return src


async def _read_body(request: Request) -> bytes:
    try:
        if int(request.headers.get("content-length") or 0) > MAX_INGEST:
            raise HTTPException(413, "payload too large")
    except ValueError as exc:
        raise HTTPException(400, "bad content-length") from exc
    body = await request.body()
    if len(body) > MAX_INGEST:
        raise HTTPException(413, "payload too large")
    return body


def _land(source: str, recs: list, method: str) -> str:
    from ..ingest import write_batch
    if len(recs) > 100_000:
        raise HTTPException(413, "too many records in one request")
    key = write_batch(rt().landing, source, recs)
    rt().store.audit(f"ingest:{source}", "ingest", {"records": len(recs), "key": key, "auth": method})
    return key


@app.post("/api/ingest/{source}")
async def ingest(source: str, request: Request):
    """Signed (HMAC) or token-authenticated push of JSON, NDJSON or text lines; gzip accepted."""
    from ..ingest.push import PushError, authenticate, decode, records
    _push_source(source)
    body = await _read_body(request)
    try:
        method = authenticate(source, request.headers, body)
        recs = records(decode(body, request.headers.get("content-encoding")))
    except PushError as exc:
        raise HTTPException(exc.status, str(exc)) from exc
    if not recs:
        return JSONResponse({"accepted": 0}, status_code=202)
    key = _land(source, recs, method)
    return JSONResponse({"accepted": len(recs), "batch": key}, status_code=202)


def _hec_error(status: int, text: str, code: int) -> JSONResponse:
    return JSONResponse({"text": text, "code": code}, status_code=status)


@app.get("/services/collector/health")
@app.get("/services/collector/health/1.0")
def hec_health():
    return {"text": "HEC is healthy", "code": 17}


@app.post("/services/collector")
@app.post("/services/collector/event")
@app.post("/services/collector/event/1.0")
@app.post("/services/collector/raw")
@app.post("/services/collector/raw/1.0")
async def hec(request: Request):
    """Splunk HEC-compatible intake, so existing HEC senders (Cribl, Vector, Fluent Bit, Logstash, SaaS exports)
    can be re-pointed without change. The token decides the MERIDIAN source; no indexer acknowledgement."""
    from ..ingest.push import PushError, bearer, decode, hec_records, records, source_for_token
    tok = bearer(request.headers) or request.query_params.get("token")
    if not tok:
        return _hec_error(401, "Token is required", 2)
    source = source_for_token(tok)
    if not source:
        return _hec_error(403, "Invalid token", 4)
    try:
        _push_source(source)
    except HTTPException:
        return _hec_error(403, "Token is not bound to an enabled source", 4)
    body = await _read_body(request)
    try:
        text = decode(body, request.headers.get("content-encoding"))
        recs = [r for r in records(text) if r != ""] if request.url.path.startswith("/services/collector/raw") \
            else hec_records(text)
    except PushError as exc:
        return _hec_error(exc.status, str(exc), 6)
    if not recs:
        return _hec_error(400, "No data", 5)
    _land(source, recs, "hec")
    return {"text": "Success", "code": 0}


# ------------------------------------------------------------------ external dynamic lists
@app.get("/edl/{kind}.txt", response_class=PlainTextResponse)
def edl(kind: str, request: Request):
    tok = os.environ.get("MERIDIAN_EDL_TOKEN", "")
    auth = request.headers.get("Authorization", "")
    supplied = ""
    if auth.lower().startswith("basic "):
        try:
            supplied = base64.b64decode(auth[6:]).decode().split(":", 1)[-1]
        except ValueError:
            supplied = ""
    elif auth.lower().startswith("bearer "):
        supplied = auth[7:]
    if not tok or not hmac.compare_digest(tok, supplied):
        raise HTTPException(401, "EDL token required", headers={"WWW-Authenticate": 'Basic realm="meridian-edl"'})
    if kind not in ("ip", "domain"):
        raise HTTPException(404, "use ip.txt or domain.txt")
    return "\n".join(rt().store.list_blocks(kind)) + "\n"
