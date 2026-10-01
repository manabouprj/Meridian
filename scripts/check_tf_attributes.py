"""Check every argument / block used in infra/*.tf against the provider's published resource documentation
(main branch of the hashicorp provider repositories). Catches renamed or removed attributes without needing
`terraform init` (useful where the Terraform registry is not reachable). CI still runs `terraform validate`."""
import pathlib
import subprocess
import sys

import hcl2

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / ".tfdocs"
SKIP = {"depends_on", "count", "for_each", "lifecycle", "provider", "tags"}
uq = lambda s: s.strip('"') if isinstance(s, str) else s  # noqa: E731


def doc(rtype: str) -> str | None:
    CACHE.mkdir(exist_ok=True)
    p = CACHE / f"{rtype}.md"
    if p.exists() and p.stat().st_size > 100:
        return p.read_text()
    if rtype.startswith("azurerm_"):
        url = f"https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/main/website/docs/r/{rtype[8:]}.html.markdown"
    elif rtype.startswith("aws_"):
        url = f"https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r/{rtype[4:]}.html.markdown"
    else:
        url = f"https://raw.githubusercontent.com/hashicorp/terraform-provider-random/main/docs/resources/{rtype[7:]}.md"
    r = subprocess.run(["curl", "-sS", "-f", url], capture_output=True, text=True)
    if r.returncode:
        return None
    p.write_text(r.stdout)
    return r.stdout


def keys(body: dict) -> list[str]:
    out = []
    for k, v in body.items():
        k = uq(k)
        if k in SKIP or k.startswith("__"):
            continue
        if k == "dynamic":
            for dyn in v if isinstance(v, list) else [v]:
                for dn, dv in dyn.items():
                    out.append(uq(dn))
                    c = dv.get("content") or [{}]
                    out += [f"{uq(dn)}.{x}" for x in keys(c[0] if isinstance(c, list) else c)]
            continue
        out.append(k)
        if isinstance(v, list) and v and isinstance(v[0], dict) and k not in ("parameters", "environment"):
            for sub in v:
                out += [f"{k}.{x}" for x in keys(sub)]
        elif isinstance(v, dict) and k not in ("parameters", "environment"):
            out += [f"{k}.{x}" for x in keys(v)]
    return out


problems = []
for f in sorted((ROOT / "infra").rglob("*.tf")):
    for blk in hcl2.load(f.open()).get("resource", []):
        for rtype, insts in blk.items():
            d = doc(uq(rtype))
            if d is None:
                problems.append(f"{f.name}: no documentation found for {uq(rtype)}")
                continue
            for name, body in insts.items():
                for k in keys(body):
                    if f"`{k.split('.')[-1]}`" not in d:
                        problems.append(f"{f.relative_to(ROOT)} {uq(rtype)}.{uq(name)}: `{k}` not documented")
print("\n".join(problems) if problems else "every Terraform argument matches the provider documentation")
sys.exit(1 if problems else 0)
