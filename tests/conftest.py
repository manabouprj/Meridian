import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MERIDIAN_NO_DOTENV", "1")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("MERIDIAN_API_KEYS", "MERIDIAN_AGENT_TOKENS", "MERIDIAN_INGEST_SECRET", "MERIDIAN_EDL_TOKEN",
              "MERIDIAN_METRICS_TOKEN", "MERIDIAN_SESSION_SECRET", "MERIDIAN_DEV_OPEN"):
        monkeypatch.delenv(k, raising=False)


def _store_url(base: Path) -> str:
    """SQLite per test by default. With MERIDIAN_TEST_PG=postgresql+psycopg://user:pw@host/db the suite runs on
    PostgreSQL instead: every runtime gets its own fresh database (production parity: lengths, locks, JSON)."""
    admin = os.environ.get("MERIDIAN_TEST_PG")
    if not admin:
        return f"sqlite:///{base / 'm.db'}"
    if str(base) in _PG_URLS:                       # same runtime directory -> same database
        return _PG_URLS[str(base)]
    import uuid

    from sqlalchemy import create_engine
    name = "t_" + uuid.uuid4().hex[:12]
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.exec_driver_sql(f'CREATE DATABASE "{name}"')
    eng.dispose()
    _PG_URLS[str(base)] = admin.rsplit("/", 1)[0] + "/" + name
    return _PG_URLS[str(base)]


_PG_URLS: dict[str, str] = {}


def demo_overrides(base: Path) -> dict:
    return {"lake": {"root": str(base / "lake"), "landing": str(base / "landing"), "query_engine": "duckdb"},
            "store": {"url": _store_url(base)}, "cloud": "local", "queue": {"type": "local"},
            "org": {"name": "Kestrel Logistics (Demo)", "industry": "logistics", "crown_jewels": ["Finance ledger"]},
            "context": {"assets": str(base / "context" / "assets.csv"), "identities": str(base / "context" / "identities.csv"),
                        "intel_dir": str(base / "context" / "intel")},
            "model": {"provider": "scripted"}}


@pytest.fixture(scope="session")
def demo_rt(tmp_path_factory):
    """A runtime with the fictional demo estate ingested, detected and triaged (offline, scripted analyst)."""
    import asyncio

    from meridian.cli import drain_agents, drain_landing, run_correlations
    from meridian.demo import generate, write_context
    from meridian.runtime import Runtime
    base = tmp_path_factory.mktemp("demo")
    write_context(base / "context")
    rt = Runtime.load(None, **demo_overrides(base))
    generate(rt.landing, now=datetime.now(timezone.utc))
    rt.ingest_totals = drain_landing(rt)
    rt.correlations = run_correlations(rt, catchup_minutes=180)
    rt.agent_results = asyncio.run(drain_agents(rt))
    rt.base = base
    return rt
