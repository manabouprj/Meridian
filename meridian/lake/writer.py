"""Write OCSF-flat events to the lake as Parquet, Hive-partitioned for every engine.

Layout:  events/cls=<class_uid>/dt=<YYYY-MM-DD>/hr=<HH>/<batch>.parquet  (partition columns: cls, dt, hr)
* DuckDB reads it with hive_partitioning, Athena with Glue partition projection, Azure Data Explorer
  with an external table (or ingestion) - no engine-specific copies.
* The file name is derived from the landing batch, so re-processing the same batch overwrites
  instead of duplicating (idempotent, at-least-once delivery safe).
* Object Lock (S3) / immutability policies (Azure) on the bucket give WORM retention for audit.
"""
from __future__ import annotations

import io
from collections import defaultdict
from datetime import timezone
from typing import Any

import pyarrow.parquet as pq

from ..ocsf import to_table
from .storage import ObjectStore


def partition_key(ev: dict[str, Any]) -> tuple[int, str, str]:
    t = ev["time"]
    t = t.astimezone(timezone.utc) if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return int(ev["class_uid"]), t.strftime("%Y-%m-%d"), t.strftime("%H")


def write_events(store: ObjectStore, events: list[dict[str, Any]], batch_id: str) -> list[str]:
    groups: dict[tuple[int, str, str], list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        groups[partition_key(ev)].append(ev)
    keys = []
    for (cls, dt, hr), evs in sorted(groups.items()):
        evs.sort(key=lambda e: e["time"])
        buf = io.BytesIO()
        pq.write_table(to_table(evs), buf, compression="zstd")
        key = f"events/cls={cls}/dt={dt}/hr={hr}/{batch_id}.parquet"
        store.put(key, buf.getvalue())
        keys.append(key)
    return keys
