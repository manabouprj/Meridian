"""Regenerate infra/azure/adx-schema.kql from the OCSF-flat schema (meridian/ocsf.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from meridian.ocsf import COLUMNS  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "infra" / "azure" / "adx-schema.kql"


def kql_type(t) -> str:
    s = str(t)
    return "datetime" if "timestamp" in s else "int" if "int" in s else "bool" if s == "bool" else "string"


def render() -> str:
    cols = ", ".join(f"['{c}']:{kql_type(t)}" for c, (t, _) in COLUMNS.items())
    mapping = ", ".join(f'{{"column":"{c}","Properties":{{"Path":"$.{c}"}}}}' for c in COLUMNS)
    return f"""// MERIDIAN on Azure Data Explorer (optional engine for large estates; set lake.query_engine: adx).
// Generated from meridian/ocsf.py by `python scripts/gen_adx_schema.py` - do not edit by hand.
// Run in the `meridian` database as a database admin, then create an Event Grid data connection on the
// lake storage account (container `lake`, prefix `events/`, event BlobCreated, format parquet,
// mapping MeridianParquet, managed identity) so every Parquet file the workers write is ingested.

.create-merge table MeridianEvents ({cols})

.create-or-alter table MeridianEvents ingestion parquet mapping 'MeridianParquet' '[{mapping}]'

// Hot cache and retention match the Terraform defaults (hot_cache_period P31D, soft_delete_period P400D)
.alter-merge table MeridianEvents policy retention softdelete = 400d recoverability = enabled

.alter table MeridianEvents policy caching hot = 31d

// The agents' identity needs only Viewer on the database:
// .add database meridian viewers ('aadapp=<workload identity client id>;<tenant id>') 'MERIDIAN agents'
"""


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8")
    print("wrote", OUT)
