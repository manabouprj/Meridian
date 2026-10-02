"""Configuration: one YAML file (config/meridian.yaml or $MERIDIAN_CONFIG) with ${ENV} references.

Secrets are never literal in YAML: any key that looks like a secret must be an ${ENV} reference,
otherwise loading fails. `.env` in the repository root is read for local runs (never overrides the
real environment).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
SECRET_KEY_RE = re.compile(r"(secret|password|token|api_key|apikey|access_key|private_key|connection_string|sas)", re.I)


class ConfigError(ValueError):
    pass


def _resolve(value: Any, path: str = "") -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            child = f"{path}.{k}" if path else str(k)
            if SECRET_KEY_RE.search(str(k)) and isinstance(v, str) and v and not ENV_RE.fullmatch(v.strip()):
                raise ConfigError(f"Literal secret at '{child}'. Use an environment reference like ${{MY_SECRET}}.")
            out[k] = _resolve(v, child)
        return out
    if isinstance(value, list):
        return [_resolve(v, path) for v in value]
    if isinstance(value, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    return value


def load_dotenv(path: Path | None = None) -> None:
    p = path or ROOT / ".env"
    if os.environ.get("MERIDIAN_NO_DOTENV") or not p.exists():
        return
    for line in p.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip().removeprefix("export ").strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ and v:
            os.environ[k] = v


@dataclass
class Settings:
    raw: dict[str, Any]
    org: str
    org_key: str
    cloud: str                       # local | azure | aws
    lake_root: str                   # file path, s3://bucket/prefix or abfss://container@account.dfs.core.windows.net/prefix
    landing_root: str
    query_engine: str                # duckdb | athena | adx
    database_url: str
    sources: list[dict[str, Any]] = field(default_factory=list)
    agents: dict[str, Any] = field(default_factory=dict)
    model: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    lodestar: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)

    def path(self, p: str | Path) -> Path:
        p = Path(p)
        return p if p.is_absolute() else ROOT / p

    def section(self, name: str) -> dict[str, Any]:
        return self.raw.get(name) or {}


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _db_from_env() -> str | None:
    """AWS: Aurora's managed master secret ({"username", "password"}) + host -> SQLAlchemy URL."""
    import json
    from urllib.parse import quote
    creds, host = os.environ.get("MERIDIAN_DB_CREDENTIALS"), os.environ.get("MERIDIAN_DB_HOST")
    if not creds or not host:
        return None
    try:
        c = json.loads(creds)
    except ValueError:
        return None
    return (f"postgresql+psycopg://{quote(c['username'], safe='')}:{quote(c['password'], safe='')}@{host}:5432/"
            f"{os.environ.get('MERIDIAN_DB_NAME', 'meridian')}?sslmode=require")


def _check_sources(sources: list[dict[str, Any]]) -> None:
    """Fail at start-up, not hours later in the worker: unique keys, known formats, valid time zones."""
    from .mappers import REGISTRY
    from .mappers.common import UnknownTimeZone, zone
    seen: set[str] = set()
    for i, s in enumerate(sources):
        key = s.get("key") if isinstance(s, dict) else None
        if not key:
            raise ConfigError(f"sources[{i}] needs a key")
        if key in seen:
            raise ConfigError(f"source key '{key}' is used twice")
        seen.add(key)
        fmt = s.get("format", "json")
        if fmt not in REGISTRY:
            raise ConfigError(f"source '{key}': unknown format '{fmt}'. Choose: {', '.join(sorted(REGISTRY))}")
        tz = (s.get("settings") or {}).get("timezone")
        if tz:
            try:
                zone(str(tz))
            except UnknownTimeZone as exc:
                raise ConfigError(f"source '{key}': {exc}") from exc


def load_settings(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    load_dotenv()
    p = Path(path or os.environ.get("MERIDIAN_CONFIG", ROOT / "config" / "meridian.yaml"))
    if not p.is_absolute():
        p = ROOT / p
    if not p.exists():
        raise ConfigError(f"Config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p.name} is not valid YAML: {exc}") from exc
    for k, v in (overrides or {}).items():
        raw[k] = v
    raw = _resolve(raw)
    raw["_path"] = str(p)
    org = (raw.get("org") or {}).get("name") or "Unnamed organisation"
    cloud = raw.get("cloud", "local")
    if cloud not in ("local", "azure", "aws"):
        raise ConfigError("cloud must be local, azure or aws")
    lake = raw.get("lake") or {}
    engine = lake.get("query_engine", "duckdb")
    if engine not in ("duckdb", "athena", "adx"):
        raise ConfigError("lake.query_engine must be duckdb, athena or adx")

    _check_sources(raw.get("sources") or [])

    def _root(v: str) -> str:
        if "://" in v:
            return v.rstrip("/")
        return str((ROOT / v) if not Path(v).is_absolute() else Path(v))
    return Settings(
        raw=raw, org=org, org_key=slugify(org), cloud=cloud,
        lake_root=_root(lake.get("root", "data/lake")), landing_root=_root(lake.get("landing", "data/landing")),
        query_engine=engine,
        database_url=(raw.get("store") or {}).get("url") or _db_from_env() or f"sqlite:///{ROOT / 'data' / 'meridian.db'}",
        sources=raw.get("sources") or [], agents=raw.get("agents") or {}, model=raw.get("model") or {},
        response=raw.get("response") or {}, lodestar=raw.get("lodestar") or {}, security=raw.get("security") or {},
    )
