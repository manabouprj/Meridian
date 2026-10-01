"""Sigma-compatible detection rules, evaluated on the stream (per event) or on the lake (correlations).

Supported (enough for the large majority of community rules):
  logsource   category/product/service -> OCSF class (see LOGSOURCE)
  detection   named selections: a map (AND of fields) or a list of maps (OR); a value list is OR
              unless the |all modifier is used; a plain list of strings = keyword search
  modifiers   contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte, exists; wildcards * and ?
  condition   and / or / not / parentheses / "1 of sel*" / "all of sel*" / "1 of them" / "all of them"
  fields      MERIDIAN column names, or standard Sigma names mapped through FIELD_MAP
  correlation event_count / value_count over the lake (Sigma correlation-rule semantics), with
              group-by, timespan and a gte/gt/lte/lt condition; base events from `rules:` or `meridian.query`
Extension block `meridian:` - entity (alert grouping field), suppress_minutes, query (correlations).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from ..ocsf import COLUMNS, QUERYABLE

LOGSOURCE: dict[str, list[int]] = {
    "process_creation": [1007], "file_event": [1001], "file_delete": [1001], "file_rename": [1001],
    "network_connection": [4001, 4002], "firewall": [4001], "proxy": [4002], "webserver": [4002],
    "dns": [4003], "dns_query": [4003], "authentication": [3002], "signinlogs": [3002],
    "auditlogs": [3001, 3005, 6003], "cloudtrail": [6003, 3002], "detection": [2004], "email": [4009],
    "any": [],
}
FIELD_MAP = {
    "Image": "process_name", "CommandLine": "process_cmdline", "ParentImage": "parent_process_name",
    "OriginalFileName": "process_name", "TargetFilename": "file_path", "Hashes": "file_sha256", "sha256": "file_sha256",
    "DestinationIp": "dst_ip", "DestinationPort": "dst_port", "DestinationHostname": "dst_domain",
    "SourceIp": "src_ip", "SourcePort": "src_port", "QueryName": "dns_query", "User": "user", "TargetUserName": "user",
    "Computer": "device", "ComputerName": "device", "c-uri": "url", "cs-host": "dst_domain", "cs-method": "http_method",
    "eventName": "api_operation", "eventSource": "app_name", "awsRegion": "cloud_region",
    "OperationName": "api_operation", "operationName": "api_operation", "UserPrincipalName": "user",
    "IpAddress": "src_ip", "AppDisplayName": "app_name", "Action": "action",
}
LEVEL_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class RuleError(ValueError):
    pass


def _field(name: str) -> str:
    f = FIELD_MAP.get(name, name)
    if f not in COLUMNS:
        raise RuleError(f"field '{name}' is not mapped to a MERIDIAN column")
    return f


def _as_str(v: Any) -> str:
    return "" if v is None else str(v)


def _wild(pattern: str) -> Callable[[str], bool]:
    if "*" in pattern or "?" in pattern:
        rx = re.compile(fnmatch.translate(pattern.lower()), re.S)
        return lambda s: bool(rx.match(s.lower()))
    p = pattern.lower()
    return lambda s: s.lower() == p


def _image(pattern: str, column: str) -> str:
    """Sigma Image values carry a path ('\\powershell.exe'); process_name may be the bare file name."""
    if column in ("process_name", "parent_process_name"):
        return pattern.replace("/", "\\").split("\\")[-1] if "\\" in pattern or "/" in pattern else pattern
    return pattern


def _matcher(column: str, mods: list[str], values: list[Any]) -> Callable[[dict], bool]:
    mods = [m for m in mods if m]
    allm = "all" in mods
    kind = next((m for m in mods if m in ("contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte",
                                          "exists", "windash", "base64", "base64offset")), "eq")
    if kind in ("windash", "base64", "base64offset"):
        raise RuleError(f"modifier '{kind}' is not supported")
    preds: list[Callable[[Any], bool]] = []
    for raw in values:
        if kind == "exists":
            want = bool(raw)
            preds.append(lambda v, w=want: (v not in (None, "")) == w)
            continue
        if raw is None:
            preds.append(lambda v: v in (None, ""))
            continue
        val = _image(str(raw), column) if column in ("process_name", "parent_process_name") else str(raw)
        lv = val.lower()
        if kind == "contains":
            preds.append(lambda v, x=lv: x in _as_str(v).lower())
        elif kind == "startswith":
            preds.append(lambda v, x=lv: _as_str(v).lower().startswith(x))
        elif kind == "endswith":
            preds.append(lambda v, x=lv: _as_str(v).lower().endswith(x))
        elif kind == "re":
            rx = re.compile(val, re.I)
            preds.append(lambda v, r=rx: bool(r.search(_as_str(v))))
        elif kind == "cidr":
            net = ipaddress.ip_network(val, strict=False)
            preds.append(lambda v, n=net: _in_net(v, n))
        elif kind in ("gt", "gte", "lt", "lte"):
            num = float(val)
            op = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}[kind]
            preds.append(lambda v, n=num, o=op: _num(v) is not None and o(_num(v), n))
        else:
            w = _wild(val)
            preds.append(lambda v, f=w: v is not None and f(_as_str(v)))
    combine = all if allm else any
    return lambda ev: combine(p(ev.get(column)) for p in preds)


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _in_net(v: Any, net) -> bool:
    try:
        return ipaddress.ip_address(str(v)) in net
    except ValueError:
        return False


def _selection(sel: Any) -> Callable[[dict], bool]:
    if isinstance(sel, list) and all(isinstance(x, str) for x in sel):        # keywords
        kws = [k.lower() for k in sel]
        text_cols = ("process_cmdline", "message", "url", "dns_query", "file_path", "api_operation")
        return lambda ev: any(k in _as_str(ev.get(c)).lower() for c in text_cols for k in kws)
    if isinstance(sel, list):
        parts = [_selection(x) for x in sel]
        return lambda ev: any(p(ev) for p in parts)
    if not isinstance(sel, dict):
        raise RuleError("a selection must be a map or a list")
    preds = []
    for key, val in sel.items():
        name, *mods = key.split("|")
        col = _field(name)
        vals = val if isinstance(val, list) else [val]
        preds.append(_matcher(col, mods, vals))
    return lambda ev: all(p(ev) for p in preds)


# ------------------------------------------------------------------ condition parser
_TOK = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*]+)\s*", re.I)


def _compile_condition(cond: str, sels: dict[str, Callable[[dict], bool]]) -> Callable[[dict], bool]:
    toks = [t.lower() if t.lower() in ("and", "or", "not", "1 of", "all of") else t for t in _TOK.findall(cond)]
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def group(pattern: str) -> list[Callable[[dict], bool]]:
        names = list(sels) if pattern == "them" else [n for n in sels if fnmatch.fnmatch(n, pattern)]
        if not names:
            raise RuleError(f"condition references no selection: {pattern}")
        return [sels[n] for n in names]

    def atom():
        t = take()
        if t == "(":
            e = expr()
            if take() != ")":
                raise RuleError("unbalanced parentheses in condition")
            return e
        if t == "not":
            inner = atom()
            return lambda ev: not inner(ev)
        if t in ("1 of", "all of"):
            ps = group(take())
            return (lambda ev: any(p(ev) for p in ps)) if t == "1 of" else (lambda ev: all(p(ev) for p in ps))
        if t not in sels:
            raise RuleError(f"unknown selection '{t}' in condition")
        return sels[t]

    def conj():
        left = atom()
        while peek() == "and":
            take()
            right = atom()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def expr():
        left = conj()
        while peek() == "or":
            take()
            right = conj()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    fn = expr()
    if pos != len(toks):
        raise RuleError(f"could not parse condition '{cond}'")
    return fn


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    classes: list[int]
    entity: str
    suppress_minutes: int
    kind: str                                    # stream | correlation
    match: Callable[[dict], bool] | None = None
    correlation: dict[str, Any] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    source_file: str = ""
    falsepositives: list[str] = field(default_factory=list)
    detection: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> int:
        return LEVEL_SEVERITY.get(self.level, 3)

    @property
    def mitre(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if t.lower().startswith("attack.t")]


def _minutes(span: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(span).strip())
    if not m:
        raise RuleError(f"bad timespan '{span}'")
    n, u = int(m.group(1)), m.group(2)
    return max(1, {"s": n // 60, "m": n, "h": n * 60, "d": n * 1440}[u])


def parse_rule(doc: dict[str, Any], source_file: str = "") -> Rule:
    if not doc.get("title") or not doc.get("id"):
        raise RuleError("rule needs title and id")
    ext = doc.get("meridian") or {}
    ls = doc.get("logsource") or {}
    classes: list[int] = []
    for k in (ls.get("category"), ls.get("service"), ls.get("product")):
        if k and str(k).lower() in LOGSOURCE:
            classes = LOGSOURCE[str(k).lower()]
            break
    entity = ext.get("entity", "device")
    if entity not in QUERYABLE:
        raise RuleError(f"entity '{entity}' is not a MERIDIAN column")
    common = dict(id=str(doc["id"]), title=str(doc["title"]), level=str(doc.get("level", "medium")).lower(),
                  description=str(doc.get("description", "")), tags=[str(t) for t in doc.get("tags") or []],
                  classes=classes, entity=entity, suppress_minutes=int(ext.get("suppress_minutes", 60)),
                  source_file=source_file, falsepositives=[str(x) for x in doc.get("falsepositives") or []])
    if "correlation" in doc:
        c = doc["correlation"]
        if c.get("type") not in ("event_count", "value_count"):
            raise RuleError("correlation.type must be event_count or value_count")
        cond = c.get("condition") or {}
        if not any(k in cond for k in ("gte", "gt", "lte", "lt")):
            raise RuleError("correlation.condition needs gte / gt / lte / lt")
        if c["type"] == "value_count" and cond.get("field") not in QUERYABLE:
            raise RuleError("value_count needs condition.field (a MERIDIAN column)")
        gb = [_field(g) for g in c.get("group-by") or []]
        if not gb:
            raise RuleError("correlation needs group-by")
        return Rule(kind="correlation", correlation={**c, "group_by": gb, "minutes": _minutes(c.get("timespan", "15m"))},
                    query=ext.get("query") or {}, detection=doc.get("detection") or {}, **common)
    det = doc.get("detection") or {}
    cond = det.get("condition")
    if not cond:
        raise RuleError("detection.condition missing")
    sels = {k: _selection(v) for k, v in det.items() if k != "condition"}
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    match = _compile_condition(str(cond), sels)
    return Rule(kind="stream", match=match, detection=det, **common)


def load_rules(paths: list[Path]) -> tuple[list[Rule], list[str]]:
    rules, errors = [], []
    for p in paths:
        files = sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml")) if p.is_dir() else [p]
        for f in files:
            try:
                for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                    if doc:
                        rules.append(parse_rule(doc, f.name))
            except (RuleError, yaml.YAMLError, KeyError, ValueError, re.error) as exc:
                errors.append(f"{f.name}: {exc}")
    ids = [r.id for r in rules]
    errors += [f"duplicate rule id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    return rules, errors


def selection_to_where(sel: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate a simple selection (AND of fields, eq / contains / startswith / endswith, OR-lists) into
    QuerySpec conditions - used by correlation rules that reference a stream rule's selection."""
    out = []
    for key, val in sel.items():
        name, *mods = key.split("|")
        col = _field(name)
        vals = val if isinstance(val, list) else [val]
        kind = next((m for m in mods if m in ("contains", "startswith", "endswith")), "eq")
        if kind == "contains":
            out.append({"field": col, "op": "contains_any" if len(vals) > 1 else "contains",
                        "value": [str(v) for v in vals] if len(vals) > 1 else str(vals[0])})
        elif kind in ("startswith", "endswith") and len(vals) == 1:
            out.append({"field": col, "op": kind, "value": str(vals[0])})
        elif kind == "eq":
            out.append({"field": col, "op": "in" if len(vals) > 1 else "eq", "value": vals if len(vals) > 1 else vals[0]})
        else:
            raise RuleError(f"selection key '{key}' cannot be pushed down to the lake")
    return out
