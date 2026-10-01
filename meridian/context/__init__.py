"""Business and threat context: assets (CMDB), identities, threat-intel indicators.

Files use the same formats as LODESTAR, so one CMDB / identity export serves both products:
  config/assets.csv       asset_id,name,asset_type,business_service,owner,criticality,exposure,tags,aliases,ips
  config/identities.csv   identity_id,display_name,upn,email,sam,entra_object_id,aliases,privileged,department
  config/intel/*.csv      value,type,source,severity,expires   (type: ip | domain | url | sha256 | md5)
Enrichment runs at ingestion (cheap, deterministic): asset criticality / crown-jewel / internet tags
and IOC hits are written into every event, so rules and agents see them without extra lookups.
"""
from __future__ import annotations

import csv
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Asset:
    asset_id: str
    name: str = ""
    business_service: str = ""
    owner: str = ""
    criticality: int = 3
    exposure: str = "internal"
    tags: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)


@dataclass
class Identity:
    identity_id: str
    display_name: str = ""
    upn: str = ""
    email: str = ""
    sam: str = ""
    privileged: bool = False
    department: str = ""
    aliases: list[str] = field(default_factory=list)


@dataclass
class Indicator:
    value: str
    type: str
    source: str = ""
    severity: str = "high"
    expires: datetime | None = None


def _split(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(";") if x.strip()]


def _short(h: str) -> str:
    h = h.lower().strip().rstrip(".")
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        return h.split(".")[0]


class Context:
    def __init__(self, assets: list[Asset] | None = None, identities: list[Identity] | None = None,
                 indicators: list[Indicator] | None = None):
        self.assets = {a.asset_id: a for a in assets or []}
        self.identities = {i.identity_id: i for i in identities or []}
        self.by_name: dict[str, str] = {}
        self.by_short: dict[str, set[str]] = {}
        for a in self.assets.values():
            for n in [a.asset_id, a.name, *a.aliases, *a.ips]:
                if not n:
                    continue
                k = n.lower().strip().rstrip(".")
                self.by_name[k] = a.asset_id
                self.by_short.setdefault(_short(k), set()).add(a.asset_id)
        self.by_user: dict[str, str] = {}
        for i in self.identities.values():
            for n in [i.upn, i.email, i.sam, i.identity_id, *i.aliases]:
                if n:
                    self.by_user[n.lower()] = i.identity_id
                    if "\\" in n:
                        self.by_user[n.split("\\", 1)[1].lower()] = i.identity_id
        now = datetime.now(timezone.utc)
        self.iocs: dict[str, Indicator] = {}
        for ind in indicators or []:
            if ind.expires and ind.expires < now:
                continue
            self.iocs[ind.value.lower()] = ind

    # ---------------------------------------------------------------- loading
    @classmethod
    def load(cls, assets_path: Path | None, identities_path: Path | None, intel_dir: Path | None) -> "Context":
        assets, identities, indicators = [], [], []
        if assets_path and assets_path.exists():
            with assets_path.open(newline="", encoding="utf-8-sig") as fh:
                for r in csv.DictReader(fh):
                    try:
                        crit = int(r.get("criticality") or 3)
                    except ValueError:
                        crit = 3
                    assets.append(Asset(asset_id=r["asset_id"], name=r.get("name", ""), business_service=r.get("business_service", ""),
                                        owner=r.get("owner", ""), criticality=crit, exposure=r.get("exposure") or "internal",
                                        tags=_split(r.get("tags")), aliases=_split(r.get("aliases")), ips=_split(r.get("ips"))))
        if identities_path and identities_path.exists():
            with identities_path.open(newline="", encoding="utf-8-sig") as fh:
                for r in csv.DictReader(fh):
                    identities.append(Identity(identity_id=r["identity_id"], display_name=r.get("display_name", ""),
                                               upn=r.get("upn", ""), email=r.get("email", ""), sam=r.get("sam", ""),
                                               privileged=str(r.get("privileged", "")).lower() in ("true", "1", "yes"),
                                               department=r.get("department", ""), aliases=_split(r.get("aliases"))))
        if intel_dir and intel_dir.exists():
            for f in sorted(intel_dir.glob("*")):
                indicators += _load_intel(f)
        return cls(assets, identities, indicators)

    # ---------------------------------------------------------------- lookups
    def asset_for(self, *names: Any) -> Asset | None:
        for n in names:
            if not n:
                continue
            k = str(n).lower().strip().rstrip(".")
            if k in self.by_name:
                return self.assets[self.by_name[k]]
            hits = self.by_short.get(_short(k), set())
            if len(hits) == 1:
                return self.assets[next(iter(hits))]
        return None

    def identity_for(self, user: str | None) -> Identity | None:
        if not user:
            return None
        u = user.lower()
        iid = self.by_user.get(u) or self.by_user.get(u.split("@")[0]) or self.by_user.get(u.split("\\")[-1])
        return self.identities.get(iid) if iid else None

    def ioc(self, value: str | None) -> Indicator | None:
        if not value:
            return None
        v = str(value).lower().strip().rstrip(".")
        if v in self.iocs:
            return self.iocs[v]
        if "." in v and not v.replace(".", "").isdigit():            # parent domains: a.b.evil.example -> evil.example
            parts = v.split(".")
            for i in range(1, len(parts) - 1):
                p = ".".join(parts[i:])
                if p in self.iocs and self.iocs[p].type == "domain":
                    return self.iocs[p]
        return None

    # ---------------------------------------------------------------- enrichment
    def enrich(self, ev: dict[str, Any]) -> dict[str, Any]:
        tags = set(_split(ev.get("tags")))
        a = self.asset_for(ev.get("device"), ev.get("device_ip"), ev.get("dst_domain"), ev.get("dst_ip"), ev.get("resource"))
        if a:
            tags |= {f"asset:{a.asset_id}", f"crit:{a.criticality}"}
            if a.criticality >= 5 or "crown_jewel" in a.tags:
                tags.add("crown_jewel")
            if a.exposure == "internet":
                tags.add("internet_facing")
        ident = self.identity_for(ev.get("user"))
        if ident:
            tags.add(f"identity:{ident.identity_id}")
            if ident.privileged:
                tags.add("privileged_user")
        hits = []
        url = ev.get("url") or ""
        url_host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0] if url else None
        for v in (ev.get("dst_ip"), ev.get("src_ip"), ev.get("dst_domain"), ev.get("dns_query"), url_host, url,
                  ev.get("file_sha256"), ev.get("file_md5")):
            ind = self.ioc(v)
            if ind:
                hits.append(f"{ind.value} ({ind.source or ind.type})")
        if hits:
            tags.add("ioc")
            ev["ioc_hits"] = "; ".join(sorted(set(hits)))
        ev["tags"] = "; ".join(sorted(tags)) or None
        return ev


def _load_intel(f: Path) -> list[Indicator]:
    out: list[Indicator] = []
    if f.suffix.lower() == ".csv":
        with f.open(newline="", encoding="utf-8-sig") as fh:
            for r in csv.DictReader(fh):
                if not r.get("value"):
                    continue
                exp = None
                if r.get("expires"):
                    try:
                        exp = datetime.fromisoformat(r["expires"].replace("Z", "+00:00"))
                        exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
                    except ValueError:
                        exp = None
                out.append(Indicator(r["value"].strip(), (r.get("type") or "").lower(), r.get("source", f.stem),
                                     r.get("severity", "high"), exp))
    elif f.suffix.lower() == ".json":                 # STIX 2.1 bundle: simple equality patterns
        import re
        data = json.loads(f.read_text(encoding="utf-8"))
        for o in data.get("objects", []):
            if o.get("type") != "indicator":
                continue
            for m in re.finditer(r"\[(ipv4-addr|ipv6-addr|domain-name|url|file:hashes\.'SHA-256'|file:hashes\.MD5)"
                                 r"(?::value)?\s*=\s*'([^']+)'\]", o.get("pattern", "")):
                t = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url"}.get(m.group(1), "sha256" if "256" in m.group(1) else "md5")
                out.append(Indicator(m.group(2), t, o.get("created_by_ref", f.stem)))
    elif f.suffix.lower() == ".txt":
        for line in f.read_text(encoding="utf-8").splitlines():
            v = line.strip()
            if v and not v.startswith("#"):
                out.append(Indicator(v, "auto", f.stem))
    return out
