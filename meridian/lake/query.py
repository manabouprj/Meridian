"""Portable, injection-safe lake queries: one QuerySpec -> DuckDB SQL, Athena (Trino) SQL or ADX KQL.

Agents, rules and analysts never write raw SQL/KQL against the lake. They describe WHAT they want
(classes, time window, filters, fields, grouping); the compiler validates every field against the
schema allow-list, binds every value as a parameter and enforces row / time limits. This is what
makes it safe to hand the lake to an LLM through MCP, and what keeps the platform cloud-portable.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..ocsf import CLASSES, NUMERIC_COLUMNS, QUERYABLE

OPS = ("eq", "ne", "in", "not_in", "contains", "contains_any", "startswith", "endswith", "gt", "gte", "lt", "lte",
       "is_null", "not_null")
DEFAULT_FIELDS = ["time", "class_name", "activity_name", "severity_id", "status", "product", "user", "device",
                  "src_ip", "dst_ip", "dst_port", "dst_domain", "process_name", "process_cmdline", "file_sha256",
                  "url", "dns_query", "action", "api_operation", "resource", "message", "tags", "ioc_hits"]


class QueryError(ValueError):
    pass


class Cond(BaseModel):
    field: str
    op: Literal[OPS] = "eq"  # type: ignore[valid-type]
    value: Any = None

    @field_validator("field")
    @classmethod
    def _field(cls, v: str) -> str:
        if v not in QUERYABLE:
            raise ValueError(f"unknown field '{v}'")
        return v

    @model_validator(mode="after")
    def _value(self):
        if self.op in ("in", "not_in", "contains_any"):
            if not isinstance(self.value, list) or not self.value or len(self.value) > 1000:
                raise ValueError(f"{self.op} needs a list of 1-1000 values")
        elif self.op not in ("is_null", "not_null") and self.value is None:
            raise ValueError(f"{self.op} needs a value")
        if self.field in NUMERIC_COLUMNS and self.op not in ("is_null", "not_null"):
            vals = self.value if isinstance(self.value, list) else [self.value]
            try:
                [int(v) for v in vals]
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{self.field} takes integers") from exc
        return self


class QuerySpec(BaseModel):
    classes: list[int] = Field(default_factory=list, description="OCSF class ids; empty = all")
    last_minutes: int | None = Field(None, ge=1, le=60 * 24 * 400)
    since: datetime | None = None
    until: datetime | None = None
    where: list[Cond] = Field(default_factory=list, max_length=25)
    fields: list[str] = Field(default_factory=list, max_length=40)
    group_by: list[str] = Field(default_factory=list, max_length=5)
    count_distinct: str | None = None
    having_min_count: int | None = Field(None, ge=1)
    order_by: str | None = None
    descending: bool = True
    limit: int = Field(100, ge=1, le=10000)

    @field_validator("classes")
    @classmethod
    def _classes(cls, v):
        bad = [c for c in v if c not in CLASSES]
        if bad:
            raise ValueError(f"unknown OCSF classes {bad}; known: {sorted(CLASSES)}")
        return v

    @field_validator("fields", "group_by")
    @classmethod
    def _fields(cls, v):
        bad = [f for f in v if f not in QUERYABLE]
        if bad:
            raise ValueError(f"unknown fields {bad}")
        return v

    @field_validator("count_distinct")
    @classmethod
    def _cd(cls, v):
        if v is not None and v not in QUERYABLE:
            raise ValueError(f"unknown field '{v}'")
        return v

    def window(self, now: datetime | None = None) -> tuple[datetime, datetime]:
        now = now or datetime.now(timezone.utc)
        until = self.until or now
        since = self.since or (until - timedelta(minutes=self.last_minutes or 60))
        until, since = (until if until.tzinfo else until.replace(tzinfo=timezone.utc)), (since if since.tzinfo else since.replace(tzinfo=timezone.utc))
        if since >= until:
            raise QueryError("since must be before until")
        return since, until

    @property
    def aggregated(self) -> bool:
        return bool(self.group_by)


def _like(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _dates(since: datetime, until: datetime) -> tuple[str, str]:
    return since.strftime("%Y-%m-%d"), until.strftime("%Y-%m-%d")


def _q(col: str) -> str:
    """Double-quoted identifier (columns such as "user" and "time" are reserved words in Trino)."""
    return f'"{col}"'


def _k(col: str) -> str:
    """KQL bracketed column reference (safe for names that collide with KQL keywords)."""
    return f"['{col}']"


def compile_sql(spec: QuerySpec, table: str, now: datetime | None = None, max_window_days: int = 400) -> tuple[str, list[Any]]:
    """DuckDB / Trino (Athena) SQL with positional ? parameters. `table` is a trusted FROM expression."""
    since, until = spec.window(now)
    if until - since > timedelta(days=max_window_days):
        raise QueryError(f"time window larger than {max_window_days} days")
    params: list[Any] = []
    w: list[str] = []
    d0, d1 = _dates(since, until)
    w.append("dt BETWEEN ? AND ?")
    params += [d0, d1]
    w.append('"time" >= ? AND "time" < ?')
    params += [since, until]
    if spec.classes:
        w.append(f"cls IN ({', '.join('?' for _ in spec.classes)})")
        params += list(spec.classes)
    for c in spec.where:
        f = _q(c.field)
        num = c.field in NUMERIC_COLUMNS
        if c.op in ("eq", "ne"):
            if num:
                w.append(f"{f} {'=' if c.op == 'eq' else '<>'} ?")
                params.append(int(c.value))
            else:
                w.append(f"lower({f}) {'=' if c.op == 'eq' else '<>'} lower(?)")
                params.append(str(c.value))
        elif c.op in ("in", "not_in"):
            neg = "NOT " if c.op == "not_in" else ""
            if num:
                w.append(f"{f} {neg}IN ({', '.join('?' for _ in c.value)})")
                params += [int(v) for v in c.value]
            else:
                w.append(f"lower({f}) {neg}IN ({', '.join('lower(?)' for _ in c.value)})")
                params += [str(v) for v in c.value]
        elif c.op in ("contains", "startswith", "endswith"):
            pat = {"contains": "%{}%", "startswith": "{}%", "endswith": "%{}"}[c.op].format(_like(c.value))
            w.append(f"lower({f}) LIKE lower(?) ESCAPE '\\'")
            params.append(pat)
        elif c.op == "contains_any":
            ors = []
            for v in c.value:
                ors.append(f"lower({f}) LIKE lower(?) ESCAPE '\\'")
                params.append(f"%{_like(v)}%")
            w.append("(" + " OR ".join(ors) + ")")
        elif c.op in ("gt", "gte", "lt", "lte"):
            sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[c.op]
            w.append(f"{f} {sym} ?")
            params.append(int(c.value) if num else str(c.value))
        elif c.op == "is_null":
            w.append(f"({f} IS NULL OR {f} = '')" if not num else f"{f} IS NULL")
        elif c.op == "not_null":
            w.append(f"({f} IS NOT NULL AND {f} <> '')" if not num else f"{f} IS NOT NULL")
    where = " AND ".join(w)
    if spec.aggregated:
        g = ", ".join(_q(x) for x in spec.group_by)
        sel = f'{g}, count(*) AS event_count, min("time") AS first_seen, max("time") AS last_seen'
        if spec.count_distinct:
            sel += f", count(DISTINCT {_q(spec.count_distinct)}) AS distinct_count"
        sql = f"SELECT {sel} FROM {table} WHERE {where} GROUP BY {g}"
        if spec.having_min_count:
            sql += " HAVING count(*) >= ?"
            params.append(spec.having_min_count)
        order = spec.order_by if spec.order_by in (*spec.group_by, "event_count", "distinct_count", "first_seen", "last_seen") else "event_count"
        order = _q(order) if order in spec.group_by else order
    else:
        fields = spec.fields or DEFAULT_FIELDS
        sql = f"SELECT {', '.join(_q(x) for x in fields)} FROM {table} WHERE {where}"
        order = _q(spec.order_by if spec.order_by in QUERYABLE else "time")
    sql += f" ORDER BY {order} {'DESC' if spec.descending else 'ASC'} LIMIT {int(spec.limit)}"
    return sql, params


def compile_kql(spec: QuerySpec, table: str, now: datetime | None = None, max_window_days: int = 400) -> tuple[str, dict[str, Any]]:
    """Azure Data Explorer KQL with declared query parameters (no value is ever spliced into the text)."""
    since, until = spec.window(now)
    if until - since > timedelta(days=max_window_days):
        raise QueryError(f"time window larger than {max_window_days} days")
    params: dict[str, Any] = {}
    decl: list[str] = []

    def p(value: Any, kind: str) -> str:
        name = f"p{len(params)}"
        params[name] = value
        decl.append(f"{name}:{kind}")
        return name

    t0, t1 = p(since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "datetime"), p(until.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "datetime")
    lines = [f"{table}", f"| where {_k('time')} >= {t0} and {_k('time')} < {t1}"]
    if spec.classes:
        lines.append(f"| where {_k('class_uid')} in ({', '.join(p(int(c), 'int') for c in spec.classes)})")
    for c in spec.where:
        f = _k(c.field)
        num = c.field in NUMERIC_COLUMNS
        kind = "int" if num else "string"
        if c.op == "eq":
            lines.append(f"| where {f} {'==' if num else '=~'} {p(int(c.value) if num else str(c.value), kind)}")
        elif c.op == "ne":
            lines.append(f"| where {f} {'!=' if num else '!~'} {p(int(c.value) if num else str(c.value), kind)}")
        elif c.op in ("in", "not_in"):
            names = ", ".join(p(int(v) if num else str(v), kind) for v in c.value)
            op = ("in" if num else "in~") if c.op == "in" else ("!in" if num else "!in~")
            lines.append(f"| where {f} {op} ({names})")
        elif c.op in ("contains", "startswith", "endswith"):
            lines.append(f"| where {f} {c.op} {p(str(c.value), 'string')}")
        elif c.op == "contains_any":
            lines.append("| where " + " or ".join(f"{f} contains {p(str(v), 'string')}" for v in c.value))
        elif c.op in ("gt", "gte", "lt", "lte"):
            sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[c.op]
            lines.append(f"| where {f} {sym} {p(int(c.value) if num else str(c.value), kind)}")
        elif c.op == "is_null":
            lines.append(f"| where isempty({f})")
        elif c.op == "not_null":
            lines.append(f"| where isnotempty({f})")
    if spec.aggregated:
        aggs = f"event_count=count(), first_seen=min({_k('time')}), last_seen=max({_k('time')})"
        if spec.count_distinct:
            aggs += f", distinct_count=dcount({_k(spec.count_distinct)})"
        lines.append(f"| summarize {aggs} by {', '.join(_k(x) for x in spec.group_by)}")
        if spec.having_min_count:
            lines.append(f"| where event_count >= {p(int(spec.having_min_count), 'long')}")
        order = spec.order_by if spec.order_by in (*spec.group_by, "event_count", "distinct_count", "first_seen", "last_seen") else "event_count"
        order = _k(order) if order in spec.group_by else order
    else:
        lines.append(f"| project {', '.join(_k(x) for x in (spec.fields or DEFAULT_FIELDS))}")
        order = _k(spec.order_by if spec.order_by in QUERYABLE else "time")
    lines.append(f"| top {int(spec.limit)} by {order} {'desc' if spec.descending else 'asc'}")
    return f"declare query_parameters({', '.join(decl)});\n" + "\n".join(lines), params
