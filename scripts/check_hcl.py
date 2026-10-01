"""Parse every Terraform file (syntax check without terraform). CI also runs `terraform fmt -check` and `validate`."""
import sys
from pathlib import Path

import hcl2

ROOT = Path(__file__).resolve().parent.parent
bad = 0
for f in sorted((ROOT / "infra").rglob("*.tf")):
    try:
        with f.open() as fh:
            hcl2.load(fh)
        print(f"ok   {f.relative_to(ROOT)}")
    except Exception as exc:
        bad += 1
        print(f"FAIL {f.relative_to(ROOT)}: {exc}")
sys.exit(1 if bad else 0)
