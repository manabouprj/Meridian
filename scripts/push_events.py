"""Push events to MERIDIAN's signed ingest endpoint (for onboarding tests and simple integrations).

    python scripts/push_events.py --url https://meridian.example --source saas_audit --file events.json
    python scripts/push_events.py --url http://127.0.0.1:8090 --source firewall --line "CEF:0|Vendor|FW|1|100|deny|5|src=203.0.113.5 dst=10.0.0.1"

The HMAC secret is read from MERIDIAN_INGEST_SECRET_<SOURCE> or MERIDIAN_INGEST_SECRET (never pass it on the command
line). The signature is HMAC-SHA256 over "<unix timestamp>.<body>", sent as X-Meridian-Signature: sha256=<hex>.
To test a shipper-style source token instead, set MERIDIAN_INGEST_TOKEN (sent as Authorization: Bearer <token>).
--gzip compresses the body (Content-Encoding: gzip), as Fluent Bit, Vector and NXLog can.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--url", required=True, help="MERIDIAN base URL")
    p.add_argument("--source", required=True, help="source key configured in sources:")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="JSON file: one object, a list, or {records: [...]}; or a text file of lines")
    g.add_argument("--line", action="append", help="raw line (CEF / syslog); repeatable")
    p.add_argument("--ca-bundle", help="custom CA bundle for TLS verification (verification is never disabled)")
    p.add_argument("--gzip", action="store_true", help="send the body gzip-compressed")
    a = p.parse_args()
    secret = os.environ.get(f"MERIDIAN_INGEST_SECRET_{a.source.upper().replace('-', '_')}") or os.environ.get("MERIDIAN_INGEST_SECRET")
    token = os.environ.get("MERIDIAN_INGEST_TOKEN")
    if not secret and not token:
        print("set MERIDIAN_INGEST_SECRET[_<SOURCE>] (HMAC) or MERIDIAN_INGEST_TOKEN (bearer) in the environment", file=sys.stderr)
        return 2
    with open(a.file, "rb") if a.file else open(os.devnull, "rb") as fh:
        body = fh.read() if a.file else "\n".join(a.line).encode()
    headers = {"Content-Type": "application/json" if a.file and a.file.endswith(".json") else "text/plain"}
    if a.gzip:
        import gzip
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    if secret:
        ts = str(int(time.time()))
        headers["X-Meridian-Timestamp"] = ts
        headers["X-Meridian-Signature"] = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    else:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{a.url.rstrip('/')}/api/ingest/{a.source}", data=body, method="POST", headers=headers)
    ctx = None
    if a.ca_bundle:
        import ssl
        ctx = ssl.create_default_context(cafile=a.ca_bundle)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            print(r.status, json.loads(r.read().decode()))
            return 0
    except urllib.error.HTTPError as e:
        print(e.code, e.read().decode()[:500], file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
