"""Query engines over the lake. All run read-only, with row and time limits, and return plain dicts.

duckdb  embedded engine reading Parquet straight from the lake (local / S3 / ADLS). Lowest cost,
        no cluster - right for small and mid-size estates and for the agents' targeted queries.
athena  Amazon Athena (Trino) over the Glue table on S3; serverless, pay per TB scanned.
adx     Azure Data Explorer (KQL) over an external table on ADLS or an ingested table; for large
        estates that need sub-second interactive search.
"""
from __future__ import annotations

import threading
import time
from datetime import date, datetime
from typing import Any, Protocol

from .query import QueryError, QuerySpec, compile_kql, compile_sql


class Engine(Protocol):
    name: str

    def run(self, spec: QuerySpec, now: datetime | None = None) -> list[dict[str, Any]]: ...


def _plain(v: Any) -> Any:
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v


class DuckDBEngine:
    name = "duckdb"

    def __init__(self, lake_root: str, max_window_days: int = 400, threads: int = 4, memory_limit: str = "2GB"):
        import duckdb
        self.root = lake_root.rstrip("/")
        self.max_window_days = max_window_days
        self.con = duckdb.connect(":memory:", config={"threads": threads, "memory_limit": memory_limit})
        self._lock = threading.Lock()     # one connection, many callers (MCP tools run in a thread pool)
        self.con.execute("SET TimeZone = 'UTC'")
        if self.root.startswith("s3://"):
            self.con.execute("LOAD httpfs")
            self.con.execute("CREATE OR REPLACE SECRET lake (TYPE s3, PROVIDER credential_chain)")
        elif self.root.startswith(("abfss://", "az://")):
            self.con.execute("LOAD azure")
            self.con.execute("CREATE OR REPLACE SECRET lake (TYPE azure, PROVIDER credential_chain, ACCOUNT_NAME "
                             f"'{self.root.split('@')[1].split('.')[0]}')")

    def _source(self) -> str:
        glob = f"{self.root}/events/*/*/*/*.parquet".replace("'", "")
        return (f"read_parquet('{glob}', hive_partitioning = true, union_by_name = true, "
                "hive_types = {'cls': INTEGER, 'dt': VARCHAR, 'hr': VARCHAR})")

    def run(self, spec: QuerySpec, now: datetime | None = None) -> list[dict[str, Any]]:
        sql, params = compile_sql(spec, self._source(), now, self.max_window_days)
        with self._lock:                  # execute + fetch must not interleave with another caller's query
            try:
                cur = self.con.execute(sql, params)
            except Exception as exc:      # duckdb raises IOException when the lake has no files yet
                if "No files found" in str(exc):
                    return []
                raise QueryError(f"lake query failed: {exc}") from exc
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return [{c: _plain(v) for c, v in zip(cols, row, strict=True)} for row in rows]


def _sql_literal(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, datetime):
        return f"TIMESTAMP '{v.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}'"
    return "'" + str(v).replace("'", "''") + "'"


class AthenaEngine:
    name = "athena"

    def __init__(self, database: str, table: str = "events", workgroup: str = "meridian", client=None,
                 timeout_s: int = 120, max_window_days: int = 400):
        import boto3
        self.db, self.table, self.wg = database, table, workgroup
        self.client = client or boto3.client("athena")
        self.timeout_s, self.max_window_days = timeout_s, max_window_days

    def run(self, spec: QuerySpec, now: datetime | None = None) -> list[dict[str, Any]]:
        sql, params = compile_sql(spec, f'"{self.db}"."{self.table}"', now, self.max_window_days)
        kw = {"ExecutionParameters": [_sql_literal(p) for p in params]} if params else {}
        qid = self.client.start_query_execution(QueryString=sql, QueryExecutionContext={"Database": self.db},
                                                WorkGroup=self.wg, **kw)["QueryExecutionId"]
        deadline = time.monotonic() + self.timeout_s
        delay = 0.25
        while True:
            st = self.client.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            if st["State"] == "SUCCEEDED":
                break
            if st["State"] in ("FAILED", "CANCELLED"):
                raise QueryError(f"Athena query {st['State']}: {st.get('StateChangeReason', '')}")
            if time.monotonic() > deadline:
                self.client.stop_query_execution(QueryExecutionId=qid)
                raise QueryError("Athena query timed out")
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
        rows: list[dict[str, Any]] = []
        header: list[str] | None = None
        kw2: dict[str, Any] = {}
        while True:
            page = self.client.get_query_results(QueryExecutionId=qid, MaxResults=1000, **kw2)
            for r in page["ResultSet"]["Rows"]:
                vals = [c.get("VarCharValue") for c in r["Data"]]
                if header is None:
                    header = vals
                    continue
                rows.append(dict(zip(header, vals, strict=False)))
            if not page.get("NextToken") or len(rows) >= spec.limit:
                break
            kw2 = {"NextToken": page["NextToken"]}
        return rows[: spec.limit]


class ADXEngine:
    name = "adx"

    def __init__(self, cluster_uri: str, database: str, table: str = "MeridianEvents", token_provider=None,
                 transport=None, timeout_s: int = 60, max_window_days: int = 400):
        self.cluster, self.db, self.table = cluster_uri.rstrip("/"), database, table
        self.timeout_s, self.max_window_days, self.transport = timeout_s, max_window_days, transport
        if token_provider is None:
            from azure.identity import DefaultAzureCredential
            cred = DefaultAzureCredential()
            token_provider = lambda: cred.get_token(f"{self.cluster}/.default").token  # noqa: E731
        self.token = token_provider

    def run(self, spec: QuerySpec, now: datetime | None = None) -> list[dict[str, Any]]:
        import httpx
        kql, params = compile_kql(spec, self.table, now, self.max_window_days)
        body = {"db": self.db, "csl": kql, "properties": {
            "Options": {"servertimeout": f"00:00:{min(self.timeout_s, 59):02d}", "truncationmaxrecords": spec.limit},
            "Parameters": {k: str(v) for k, v in params.items()}}}
        kw = {"transport": self.transport} if self.transport else {}
        with httpx.Client(timeout=self.timeout_s + 5, trust_env=True, **kw) as c:
            r = c.post(f"{self.cluster}/v1/rest/query", json=body,
                       headers={"Authorization": f"Bearer {self.token()}", "Accept": "application/json"})
        if r.status_code >= 400:
            raise QueryError(f"ADX query failed: HTTP {r.status_code} {r.text[:300]}")
        t = r.json()["Tables"][0]
        cols = [c["ColumnName"] for c in t["Columns"]]
        return [dict(zip(cols, row, strict=True)) for row in t["Rows"]][: spec.limit]


def open_engine(settings) -> Engine:
    lake = settings.section("lake")
    mw = int(lake.get("max_window_days", 400))
    if settings.query_engine == "athena":
        a = lake.get("athena") or {}
        return AthenaEngine(a.get("database", "meridian"), a.get("table", "events"), a.get("workgroup", "meridian"),
                            max_window_days=mw)
    if settings.query_engine == "adx":
        a = lake.get("adx") or {}
        return ADXEngine(a["cluster_uri"], a.get("database", "meridian"), a.get("table", "MeridianEvents"), max_window_days=mw)
    return DuckDBEngine(settings.lake_root, max_window_days=mw)
