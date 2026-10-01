"""HTTPS push: authentication and body decoding shared by /api/ingest/<source> and the HEC-compatible endpoint.

Two ways to authenticate, both scoped to ONE source (a sender can only write into its own landing prefix):
  * HMAC (preferred when the sender can compute it): X-Meridian-Timestamp + X-Meridian-Signature =
    sha256=HMAC(secret, "<ts>.<body>"), secret MERIDIAN_INGEST_SECRET_<SOURCE> or MERIDIAN_INGEST_SECRET; 5-minute window.
  * Bearer token (for log shippers that can only add a static header: Fluent Bit, Vector, NXLog Enterprise,
    Logstash, Cribl, anything that speaks Splunk HEC): MERIDIAN_INGEST_TOKENS = "source:token,source2:token2".
    "none" (or empty) disables token authentication. Tokens must be at least 32 characters.
Bodies: JSON (object, array, {"records": [...]}, {"events": [...]}), NDJSON, plain text lines, or Splunk HEC
(concatenated {"event": ...} objects). Content-Encoding: gzip is accepted with a decompressed-size cap.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import zlib
from typing import Any

MAX_DECOMPRESSED = 64 * 1024 * 1024
MIN_TOKEN = 32


class PushError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def ingest_tokens() -> dict[str, str]:
    """token -> source key, from MERIDIAN_INGEST_TOKENS ("source:token,..."); short tokens are ignored."""
    raw = os.environ.get("MERIDIAN_INGEST_TOKENS", "").strip()
    out: dict[str, str] = {}
    if not raw or raw.lower() == "none":
        return out
    for part in raw.split(","):
        src, _, tok = part.strip().partition(":")
        if src and len(tok) >= MIN_TOKEN:
            out[tok] = src
    return out


def source_for_token(token: str) -> str | None:
    found = None
    for tok, src in ingest_tokens().items():
        if hmac.compare_digest(tok.encode(), token.encode()):
            found = src
    return found


def bearer(headers: Any) -> str | None:
    h = headers.get("authorization") or ""
    scheme, _, val = h.partition(" ")
    if scheme.lower() in ("bearer", "splunk") and val.strip():
        return val.strip()
    return None


def authenticate(source: str, headers: Any, body: bytes) -> str:
    """Return the method used ('hmac' | 'token'); raise PushError(401) otherwise."""
    tok = bearer(headers)
    if tok:
        if source_for_token(tok) == source:
            return "token"
        raise PushError(401, "invalid token for this source")
    secret = os.environ.get(f"MERIDIAN_INGEST_SECRET_{source.upper().replace('-', '_')}") or os.environ.get("MERIDIAN_INGEST_SECRET", "")
    ts = headers.get("x-meridian-timestamp", "")
    try:
        fresh = abs(time.time() - int(ts)) <= 300
    except ValueError:
        fresh = False
    sig = headers.get("x-meridian-signature", "")
    want = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest() if secret else ""
    if not secret or not fresh or not hmac.compare_digest(want, sig):
        raise PushError(401, "invalid signature or stale timestamp")
    return "hmac"


def decode(body: bytes, content_encoding: str | None) -> str:
    enc = (content_encoding or "").lower().strip()
    if enc in ("gzip", "x-gzip", "deflate"):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
        try:
            out = d.decompress(body, MAX_DECOMPRESSED + 1)
        except zlib.error as exc:
            raise PushError(400, "body is not valid gzip/deflate") from exc
        if len(out) > MAX_DECOMPRESSED or d.unconsumed_tail:
            raise PushError(413, "decompressed body too large")
        body = out
    elif enc not in ("", "identity"):
        raise PushError(415, f"unsupported Content-Encoding {enc}")
    return body.decode("utf-8", "replace")


def records(text: str) -> list[Any]:
    """JSON document, NDJSON or plain lines -> list of records (dicts or strings)."""
    s = text.strip()
    if not s:
        return []
    try:
        data = json.loads(s)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("records", "events", "Records"):
                if isinstance(data.get(k), list):
                    return data[k]
            return [data]
    except ValueError:
        pass
    out: list[Any] = []
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] == "{":
            try:
                out.append(json.loads(line))
                continue
            except ValueError:
                pass
        out.append(line)
    return out


def hec_records(text: str) -> list[Any]:
    """Splunk HEC /services/collector/event: one or more concatenated {"event": ..., "time": .., "host": ..} objects.
    String events become lines (syslog / CEF / Windows XML ...); object events keep a `_hec` block with host and
    sourcetype so a field_map can use them."""
    dec, i, out, n = json.JSONDecoder(), 0, [], len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError as exc:
            raise PushError(400, "invalid HEC event JSON") from exc
        if not isinstance(obj, dict) or "event" not in obj:
            raise PushError(400, "each HEC object needs an 'event' field")
        ev = obj["event"]
        if isinstance(ev, dict):
            ev = {**ev, "_hec": {k: obj.get(k) for k in ("time", "host", "source", "sourcetype") if obj.get(k) is not None}}
        out.append(ev)
    return out
