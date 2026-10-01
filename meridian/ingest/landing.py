"""Landing zone: raw batches as delivered, before normalisation.

Everything arrives as files in object storage - this is what replaces the SIEM's ingestion tier:
  Azure  Defender / Entra / Azure activity -> diagnostic settings -> Event Hubs -> Capture (Avro) -> ADLS
  AWS    CloudTrail / VPC / Route 53 -> S3 (or Security Lake); SaaS -> Firehose -> S3 (JSON lines, gzip)
  Any    syslog/CEF -> MERIDIAN syslog receiver -> landing; HTTPS push -> /api/ingest/<source> -> landing
Batches are immutable and replayable; the lake can always be rebuilt from landing.
Layout: <source_key>/<YYYY>/<MM>/<DD>/<batch>.<ext>   (or any prefix mapped to a source in config)
"""
from __future__ import annotations

import gzip
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from ..lake.storage import ObjectStore


def batch_key(source_key: str, ext: str = "jsonl.gz", when: datetime | None = None) -> str:
    w = when or datetime.now(timezone.utc)
    return f"{source_key}/{w:%Y/%m/%d}/{w:%H%M%S}-{uuid.uuid4().hex[:10]}.{ext}"


def write_batch(store: ObjectStore, source_key: str, records: list[Any], when: datetime | None = None) -> str:
    """Persist a batch of raw records (dicts -> JSON lines, strings -> text lines), gzip-compressed."""
    lines = [r if isinstance(r, str) else json.dumps(r, separators=(",", ":"), default=str) for r in records]
    ext = "log.gz" if records and all(isinstance(r, str) for r in records) else "jsonl.gz"
    key = batch_key(source_key, ext, when)
    store.put(key, gzip.compress("\n".join(lines).encode("utf-8")))
    return key


def _unwrap(obj: Any) -> Iterator[Any]:
    """Azure diagnostic envelopes {"records": [...]}, CloudTrail {"Records": [...]}, Graph {"value": [...]}."""
    if isinstance(obj, list):
        for x in obj:
            yield from _unwrap(x)
    elif isinstance(obj, dict) and isinstance(obj.get("records"), list):
        yield from obj["records"]
    elif isinstance(obj, dict) and isinstance(obj.get("Records"), list) and len(obj) <= 2:
        yield from obj["Records"]
    elif isinstance(obj, dict) and isinstance(obj.get("value"), list) and len(obj) <= 3:
        yield from obj["value"]
    else:
        yield obj


def read_batch(key: str, data: bytes) -> Iterator[Any]:
    name = key.lower()
    if name.endswith(".gz"):
        data = gzip.decompress(data)
        name = name[:-3]
    if name.endswith(".avro"):                       # Event Hubs Capture
        import fastavro
        for rec in fastavro.reader(io.BytesIO(data)):
            body = rec.get("Body")
            if isinstance(body, (bytes, bytearray)):
                body = body.decode("utf-8", "replace")
            try:
                yield from _unwrap(json.loads(body))
            except (TypeError, ValueError):
                if body:
                    yield body
        return
    text = data.decode("utf-8-sig", "replace")
    if name.endswith(".json"):
        try:
            yield from _unwrap(json.loads(text))
            return
        except ValueError:
            pass                                     # fall through: may be JSON lines with a .json name
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] in "{[":
            try:
                yield from _unwrap(json.loads(line))
                continue
            except ValueError:
                pass
        yield line
