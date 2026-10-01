"""API pull collector: polls SaaS and management APIs that cannot push (Okta System Log, Microsoft 365 Management
Activity, Microsoft Graph, GitHub audit log, Google Workspace reports, Atlassian, Salesforce ...) and writes what it
fetched to the landing zone as ordinary batches. Normalisation then happens in the worker like any other source.

    sources:
      - key: okta
        format: json
        settings: {class_uid: 3002, field_map: {time: published, user: actor.alternateId, src_ip: client.ipAddress, ...}}
        pull:
          url: https://acme.okta.example/api/v1/logs
          auth: {type: bearer, scheme: SSWS, token: ${MERIDIAN_OKTA_TOKEN}}
          params: {since: "{cursor}", limit: "1000"}
          cursor: {field: published, start_minutes: 60}         # {cursor} = newest value seen (mode: max)
          paginate: {type: link}                                # RFC 8288 Link rel="next"
          interval_minutes: 5

Options
  auth        bearer {scheme, token} | header {name, token} | oauth2 {endpoint, client_id, client_secret, scope}
              | basic {username, password} | none. Secrets are ${ENV} references (the config loader enforces it).
  params      query parameters; placeholders {cursor} (resume point), {end} (window end), {now}
  records     dotted path to the list in the JSON response ("" = the body is the list; e.g. "value", "items")
  paginate    link | next_field {path: "@odata.nextLink"} | header {name: NextPageUri} | none
  expand      field holding a URL to fetch per listed item (two-step APIs such as Microsoft 365 contentUri)
  cursor      field: record field holding the event time; mode: max (newest record) | window (always advance to {end})
              start_minutes: first-run look-back; max_window_minutes: cap on [cursor, end]
              format: strftime for the placeholders (default ISO 8601 with milliseconds and Z)
  max_pages   per run (default 50), so one slow API never stalls the scheduler

The cursor only advances after the fetched records are safely in the landing zone, so a failure re-fetches rather
than loses. APIs whose `since` is inclusive can re-deliver the boundary record; such duplicates carry the same
event_uid and are removed at query time.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..ocsf import _ts
from .landing import write_batch

log = logging.getLogger("meridian.pull")
BATCH = 10_000


def _get(d: Any, path: str) -> Any:
    if not path:
        return d
    for part in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(part)
    return d


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


class Collector:
    def __init__(self, source: dict[str, Any], landing, store, transport: httpx.BaseTransport | None = None):
        self.src, self.cfg = source, source["pull"]
        self.landing, self.store = landing, store
        self.transport = transport
        self._token: tuple[str, float] | None = None

    # ------------------------------------------------------------------ auth
    def _headers(self, client: httpx.Client) -> dict[str, str]:
        a = self.cfg.get("auth") or {}
        kind = str(a.get("type", "none")).lower()
        h = {"Accept": "application/json", "User-Agent": "MERIDIAN-collector"}
        if kind == "bearer":
            h["Authorization"] = f"{a.get('scheme', 'Bearer')} {a.get('token', '')}"
        elif kind == "header":
            h[a["name"]] = str(a.get("token", ""))
        elif kind == "basic":
            import base64
            h["Authorization"] = "Basic " + base64.b64encode(f"{a.get('username', '')}:{a.get('password', '')}".encode()).decode()
        elif kind == "oauth2":
            if not self._token or self._token[1] < time.time() + 60:
                r = client.post(a["endpoint"], data={"grant_type": "client_credentials", "client_id": a["client_id"],
                                                     "client_secret": a.get("client_secret", ""), "scope": a.get("scope", "")})
                r.raise_for_status()
                j = r.json()
                self._token = (j["access_token"], time.time() + int(j.get("expires_in", 3600)))
            h["Authorization"] = f"Bearer {self._token[0]}"
        return h

    # ------------------------------------------------------------------ run
    def run(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        key = self.src["key"]
        cur_cfg = self.cfg.get("cursor") or {}
        ckey = f"pull:{key}:cursor"
        stored = self.store.get_cursor(ckey)
        start = _ts(stored) if stored else now - timedelta(minutes=int(cur_cfg.get("start_minutes", 60)))
        end = now
        if cur_cfg.get("max_window_minutes"):
            end = min(now, start + timedelta(minutes=int(cur_cfg["max_window_minutes"])))
        fmt = cur_cfg.get("format")                 # strftime for APIs that reject milliseconds / "Z" (Microsoft 365)

        def show(t: datetime) -> str:
            return t.astimezone(timezone.utc).strftime(fmt) if fmt else _iso(t)
        subs = {"cursor": show(start), "end": show(end), "now": show(now)}
        params = {k: str(v).format(**subs) for k, v in (self.cfg.get("params") or {}).items()}
        pag = self.cfg.get("paginate") or {"type": "none"}
        if isinstance(pag, str):
            pag = {"type": pag}
        out: dict[str, Any] = {"source": key, "records": 0, "pages": 0, "batches": 0}
        newest: datetime | None = None
        pending: list[Any] = []
        kw = {"transport": self.transport} if self.transport else {}
        with httpx.Client(timeout=30, trust_env=True, follow_redirects=False, **kw) as client:
            url: str | None = self.cfg["url"]
            first = True
            while url and out["pages"] < int(self.cfg.get("max_pages", 50)):
                r = client.get(url, params=params if first else None, headers=self._headers(client))
                first = False
                if r.status_code == 429 or r.status_code >= 500:
                    out["stopped"] = f"HTTP {r.status_code}; resuming next run"
                    break
                r.raise_for_status()
                body = r.json()
                items = _get(body, self.cfg.get("records", ""))
                items = items if isinstance(items, list) else ([items] if isinstance(items, dict) else [])
                out["pages"] += 1
                for it in items:
                    recs = [it]
                    if self.cfg.get("expand"):
                        sub = client.get(str(_get(it, self.cfg["expand"])), headers=self._headers(client))
                        sub.raise_for_status()
                        recs = sub.json()
                        recs = recs if isinstance(recs, list) else [recs]
                    pending.extend(recs)
                    f = cur_cfg.get("field")
                    if f:
                        for rec in recs + ([it] if self.cfg.get("expand") else []):
                            v = _get(rec, f)
                            if v:
                                t = _ts(v)
                                newest = t if newest is None or t > newest else newest
                if len(pending) >= BATCH:
                    write_batch(self.landing, key, pending)
                    out["batches"] += 1
                    out["records"] += len(pending)
                    pending = []
                url = self._next(r, body, pag)
        if pending:
            write_batch(self.landing, key, pending)
            out["batches"] += 1
            out["records"] += len(pending)
        # advance only after everything fetched is in the landing zone
        if "stopped" not in out:
            if cur_cfg.get("mode") == "window":
                self.store.set_cursor(ckey, _iso(end))
            elif newest is not None and newest > start:
                self.store.set_cursor(ckey, _iso(newest))
            elif not stored:
                self.store.set_cursor(ckey, _iso(start))
        elif newest is not None and newest > start and cur_cfg.get("mode") != "window":
            self.store.set_cursor(ckey, _iso(newest))           # partial progress is still progress
        out["cursor"] = self.store.get_cursor(ckey)
        return out

    @staticmethod
    def _next(r: httpx.Response, body: Any, pag: dict[str, Any]) -> str | None:
        kind = pag.get("type", "none")
        if kind == "link":
            nxt = r.links.get("next", {}).get("url")
            return nxt if nxt and nxt != str(r.url) else None
        if kind == "next_field":
            v = _get(body, pag.get("path", "@odata.nextLink")) if isinstance(body, dict) else None
            return str(v) if v else None
        if kind == "header":
            return r.headers.get(pag.get("name", "NextPageUri")) or None
        return None


def due_sources(sources: list[dict[str, Any]], store, now: datetime) -> list[dict[str, Any]]:
    out = []
    for s in sources:
        if not s.get("enabled", True) or not isinstance(s.get("pull"), dict):
            continue
        last = store.get_cursor(f"pull:{s['key']}:last_run")
        every = timedelta(minutes=float(s["pull"].get("interval_minutes", 5)))
        if not last or now - _ts(last) >= every:
            out.append(s)
    return out


def run_due(rt, now: datetime | None = None, transport=None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    results = []
    for s in due_sources(rt.settings.sources, rt.store, now):
        try:
            res = Collector(s, rt.landing, rt.store, transport).run(now)
        except Exception as exc:                    # one broken API never stops the others
            log.error("pull %s failed: %s", s["key"], exc)
            res = {"source": s["key"], "error": f"{type(exc).__name__}: {exc}"[:300]}
        rt.store.set_cursor(f"pull:{s['key']}:last_run", now.isoformat())
        rt.store.set_cursor(f"pull:{s['key']}:last_status", "error" if "error" in res else "ok")
        results.append(res)
    return results
