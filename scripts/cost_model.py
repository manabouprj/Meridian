"""MERIDIAN cost, TCO and ROI model (indicative, list prices, October 2026).

    python scripts/cost_model.py            # writes docs/cost/cost_model.json, docs/cost/*.md tables and charts

Every assumption is in ASSUMPTIONS below - change a number and re-run. Prices are public list prices (US East)
with a regional uplift for UAE North / me-central-1; they are NOT quotes. Enterprise agreements, reserved capacity
and savings plans typically reduce infrastructure lines by 20-40%.
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "cost"

# --------------------------------------------------------------------------------------------- assumptions
TIERS = {
    #            raw GB/day  alerts to triage/day  alerts reaching humans/day  investigations/day  hunts/month
    "Small":  dict(gb=50,   alerts=300,  human_alerts=150,  investigations=8,  hunts=20,
                   workers=2, agents=1, db_acu=1.0, db_gb=50,  pg_sku="D2ds_v5", pg_month=130.0, pg_gb=64,
                   eh_share=0.5, engine_azure="duckdb", siem_rate=3.23, siem_fte=1.0, mer_fte=2.0, build_fte=1.0,
                   aurora_io=20, plog=1, adx=0.0, one_time=60_000),
    "Medium": dict(gb=200,  alerts=800,  human_alerts=400,  investigations=20, hunts=40,
                   workers=4, agents=2, db_acu=2.0, db_gb=100, pg_sku="D4ds_v5", pg_month=260.0, pg_gb=128,
                   eh_share=0.5, engine_azure="adx", siem_rate=2.74, siem_fte=2.0, mer_fte=3.0, build_fte=2.0,
                   aurora_io=50, plog=2, adx=1100.0, one_time=120_000),
    "Large":  dict(gb=1000, alerts=2000, human_alerts=1000, investigations=50, hunts=80,
                   workers=12, agents=4, db_acu=4.0, db_gb=300, pg_sku="D8ds_v5", pg_month=520.0, pg_gb=512,
                   eh_share=0.5, engine_azure="adx", siem_rate=2.46, siem_fte=3.0, mer_fte=4.0, build_fte=2.0,
                   aurora_io=150, plog=5, adx=6000.0, one_time=200_000),
}

A = {
    "region_uplift": 1.15,            # UAE North / me-central-1 vs US East list prices (assumption; check calculator)
    "parquet_ratio": 6.0,             # raw -> Parquet (zstd)
    "gzip_ratio": 5.0,                # raw -> gzip landing batches
    "hours": 730,
    # AWS (US East list)
    "s3_std": 0.023, "s3_ia": 0.0125, "s3_gir": 0.004, "s3_put_per_1k": 0.005,
    "fargate_vcpu_h": 0.0000089944 * 3600, "fargate_gb_h": 0.0000009889 * 3600,   # ARM / Graviton
    "aurora_acu_h": 0.12, "aurora_gb": 0.10,"aurora_io_month": {"Small": 20, "Medium": 50, "Large": 150},
    "athena_tb": 5.0, "athena_cap_month": 5256.0,   # provisioned capacity floor (24 DPU) caps the large tier
    "vpce_h": 0.01, "vpce_count": 10, "azs": 3, "nat_h": 0.045, "alb_month": 45.0,
    "cw_logs_gb": 0.50, "platform_log_gb_day": {"Small": 1, "Medium": 2, "Large": 5},
    "secrets_kms_sqs_month": 25.0,
    # Azure (US East list)
    "adls_hot": 0.0228, "adls_cool": 0.0125, "adls_cold": 0.0045,     # ZRS approximations
    "aca_vcpu_h": 0.0864, "aca_gib_h": 0.0108,                         # active rates (conservative: always active)
    "pg_storage_gb": 0.115,
    "eh_tu_h": 0.03, "eh_capture_tu_h": 0.10, "eh_ingress_per_m": 0.028, "events_per_gb": 1.4e6,
    "pe_month": 7.3, "pe_count": 5, "pe_gb": 0.01,
    "log_analytics_gb": 2.30,
    "kv_eg_month": 15.0,
    # Models (Anthropic list rates; Bedrock / Foundry bill equivalent rates; 1.1x for in-region / data-zone)
    "haiku_in": 1.0, "haiku_out": 5.0, "sonnet_in": 2.0, "sonnet_out": 10.0,
    # Residency defaults (AZ-00 / AWS-00 section 6):
    #  Azure: both tiers Sonnet 5.5, Hosted on Azure, US Data Zone Standard (+10%); Haiku is Global Standard only.
    #  AWS:   Haiku 4.5 (fast) + Sonnet 5.5 (deep) via global cross-region inference from me-central-1 (list price).
    "model_plan": {"Azure": {"fast": "sonnet", "factor": 1.10}, "AWS": {"fast": "haiku", "factor": 1.00}},
    "triage_tokens": (25_000, 1_500), "investigate_tokens": (120_000, 8_000), "hunt_tokens": (150_000, 10_000),
    # Lake query behaviour (agents + correlations)
    "agent_queries_per_triage": 4, "agent_queries_per_investigation": 20, "agent_queries_per_hunt": 30,
    "scan_fraction_as_built": 0.25,   # share of one day of Parquet scanned per agent query today (wide windows)
    "scan_fraction_optimised": 0.02,  # after compaction + entity-sorted files + class-scoped queries (Phase 1)
    "correlation_queries_day": 7 * 288, "correlation_scan_fraction": 0.004,
    # Business
    "sentinel_payg": 4.30, "sentinel_lake_gb_month": 0.026,
    "splunk_per_gb_day_year": (600.0, 1500.0),  # public ranges for an enterprise term licence (low, high)
    "fte_cost": 140_000.0,            # fully loaded security engineer (UAE, assumption)
    "analyst_hour": 45.0,             # fully loaded SOC analyst hour (assumption)
    "minutes_saved_per_human_alert": 4.0, "productivity_realisation": 0.5,
    "growth": 0.20,                   # annual telemetry growth
    "price_escalation": 0.05,         # annual SIEM price uplift at renewal
    "parallel_run_months": 9,         # SIEM and MERIDIAN both run during phases 1-4
    "hybrid_share": 0.65,             # share of volume moved to MERIDIAN in the hybrid option (network, DNS, cloud)
}


# --------------------------------------------------------------------------------------------- helpers
def _lake_storage_per_gb_day(hot, cool, cold, h_days, c_days, total_days) -> float:
    """Steady-state monthly cost of storing ONE GB written per day, with tiering by age."""
    return hot * h_days + cool * (c_days - h_days) + cold * (total_days - c_days)


def _queries(t):
    q = (t["alerts"] * A["agent_queries_per_triage"] + t["investigations"] * A["agent_queries_per_investigation"]
         + t["hunts"] / 30 * A["agent_queries_per_hunt"])
    return q


def model_tokens(t, cloud: str) -> float:
    plan = A["model_plan"][cloud]
    f_in, f_out = (A["haiku_in"], A["haiku_out"]) if plan["fast"] == "haiku" else (A["sonnet_in"], A["sonnet_out"])
    tr_in, tr_out = A["triage_tokens"]
    iv_in, iv_out = A["investigate_tokens"]
    h_in, h_out = A["hunt_tokens"]
    day = (t["alerts"] * (tr_in * f_in + tr_out * f_out)
           + t["investigations"] * (iv_in * A["sonnet_in"] + iv_out * A["sonnet_out"])) / 1e6
    month = day * 30 + t["hunts"] * (h_in * A["sonnet_in"] + h_out * A["sonnet_out"]) / 1e6
    return month * plan["factor"]


def aws_month(t, optimised=True) -> dict[str, float]:
    u, H = A["region_uplift"], A["hours"]
    pq = t["gb"] / A["parquet_ratio"]
    lake = pq * _lake_storage_per_gb_day(A["s3_std"], A["s3_ia"], A["s3_gir"], 30, 180, 365)
    landing = t["gb"] / A["gzip_ratio"] * 90 * A["s3_std"]
    puts = 1.5e6 * (t["gb"] / 200) ** 0.5 / 1000 * A["s3_put_per_1k"]
    frac = A["scan_fraction_optimised"] if optimised else A["scan_fraction_as_built"]
    scan_tb_month = (_queries(t) * pq * frac + A["correlation_queries_day"] * pq * A["correlation_scan_fraction"]) * 30 / 1000
    athena = min(scan_tb_month * A["athena_tb"], A["athena_cap_month"])
    vcpu = 2 * 1 + t["workers"] * 1 + t["agents"] * 0.5 + 0.5 + 2 * 0.25
    gb = 2 * 2 + t["workers"] * 2 + t["agents"] * 1 + 1 + 2 * 0.5
    compute = (vcpu * A["fargate_vcpu_h"] + gb * A["fargate_gb_h"]) * H
    db = 2 * t["db_acu"] * A["aurora_acu_h"] * H + t["db_gb"] * A["aurora_gb"] + t["aurora_io"]
    net = A["vpce_h"] * A["vpce_count"] * A["azs"] * H + A["nat_h"] * H + A["alb_month"] + 0.01 * t["gb"] * 30 * 0.2
    ops = A["cw_logs_gb"] * t["plog"] * 30 + A["secrets_kms_sqs_month"]
    lines = {"Lake + landing storage (S3)": (lake + landing + puts) * u, "Query engine (Athena)": athena * u,
             "Compute (ECS Fargate, Graviton)": compute * u, "Database (Aurora Serverless v2)": db * u,
             "Networking (endpoints, NAT, ALB)": net * u, "Logs, secrets, keys, queues": ops * u,
             "AI models (Claude in Bedrock)": model_tokens(t, "AWS")}
    return {k: round(v) for k, v in lines.items()}


def azure_month(t, optimised=True) -> dict[str, float]:
    u, H = A["region_uplift"], A["hours"]
    pq = t["gb"] / A["parquet_ratio"]
    lake = pq * _lake_storage_per_gb_day(A["adls_hot"], A["adls_cool"], A["adls_cold"], 30, 90, 365)
    landing = t["gb"] / A["gzip_ratio"] * (7 * A["adls_hot"] + 83 * A["adls_cool"])
    eh_gb_day = t["gb"] * t["eh_share"]
    tus = max(2, -(-eh_gb_day // 70))             # ~70 GB/day per TU with headroom
    eh = tus * (A["eh_tu_h"] + A["eh_capture_tu_h"]) * H + eh_gb_day * 30 * A["events_per_gb"] / 1e6 * A["eh_ingress_per_m"] / 10
    vcpu = 2 * 1 + t["workers"] * 1 + t["agents"] * 0.5 + 0.5
    gib = 2 * 2 + t["workers"] * 2 + t["agents"] * 1 + 1
    compute = (vcpu * A["aca_vcpu_h"] + gib * A["aca_gib_h"]) * H + 60    # + a small syslog VM / ACI
    if t["engine_azure"] == "duckdb":
        # DuckDB inside the api/agents containers: scale those up instead of paying per scan
        engine = (2 if optimised else 8) * (A["aca_vcpu_h"] + 2 * A["aca_gib_h"]) * H
    else:
        engine = t["adx"] * (1.0 if optimised else 1.6)
    db = 2 * t["pg_month"] + t["pg_gb"] * A["pg_storage_gb"] * 2
    net = A["pe_month"] * A["pe_count"] + A["pe_gb"] * t["gb"] * 0.6 * 30
    ops = A["log_analytics_gb"] * t["plog"] * 30 + A["kv_eg_month"]
    lines = {"Lake + landing storage (ADLS)": (lake + landing) * u, "Query engine (DuckDB / ADX)": engine * u,
             "Ingestion (Event Hubs + Capture)": eh * u, "Compute (Container Apps)": compute * u,
             "Database (PostgreSQL Flexible, HA)": db * u, "Networking (private endpoints)": net * u,
             "Logs, Key Vault, Event Grid": ops * u, "AI models (Claude in Foundry)": model_tokens(t, "Azure")}
    return {k: round(v) for k, v in lines.items()}


def sentinel_month(t, gb=None) -> dict[str, float]:
    gb = t["gb"] if gb is None else gb
    ingest = gb * 30 * t["siem_rate"]
    retention = gb / A["parquet_ratio"] * 275 * A["sentinel_lake_gb_month"]     # days 91-365 in the data lake tier
    return {"Ingestion (commitment tier)": round(ingest), "Retention 91-365 days": round(retention)}


def splunk_month(t) -> tuple[int, int]:
    lo, hi = A["splunk_per_gb_day_year"]
    return round(t["gb"] * lo / 12), round(t["gb"] * hi / 12)


# --------------------------------------------------------------------------------------------- TCO / ROI
def tco(name: str, cloud: str, t: dict | None = None) -> dict:
    """3-year TCO for three options against the status quo (Microsoft Sentinel commitment tier)."""
    t = t or TIERS[name]
    run = sum((aws_month if cloud == "AWS" else azure_month)(t).values())
    sent = sum(sentinel_month(t).values())
    years = []
    for y in range(3):
        g = (1 + A["growth"]) ** y                     # volume growth
        esc = (1 + A["price_escalation"]) ** y
        status_quo = sent * 12 * g * esc + t["siem_fte"] * A["fte_cost"]
        # Full replacement: cloud run cost scales ~with volume (storage/query), engineering team, year-1 build + parallel run
        full = run * 12 * g + t["mer_fte"] * A["fte_cost"]
        if y == 0:
            full += t["build_fte"] * A["fte_cost"] + t["one_time"] + sent * A["parallel_run_months"]
        # Hybrid: high-volume sources move to MERIDIAN, SIEM keeps the rest at a smaller commitment tier
        hs = A["hybrid_share"]
        hybrid = (sent * (1 - hs) * 1.15 * 12 * g * esc          # smaller tier -> ~15% higher unit price
                  + run * 0.75 * 12 * g                          # lighter MERIDIAN footprint (no full content parity)
                  + (t["siem_fte"] + 0.5) * A["fte_cost"])
        if y == 0:
            hybrid += 0.5 * t["build_fte"] * A["fte_cost"] + 0.5 * t["one_time"] + sent * 4
        years.append({"year": y + 1, "status_quo": round(status_quo), "hybrid": round(hybrid), "full": round(full)})
    soft = (t["human_alerts"] * A["minutes_saved_per_human_alert"] / 60 * 365 * A["analyst_hour"]
            * A["productivity_realisation"])
    out = {"tier": name, "cloud": cloud, "years": years, "run_month": round(run), "sentinel_month": round(sent),
           "soft_value_year": round(soft)}
    for opt in ("hybrid", "full"):
        sq = sum(y["status_quo"] for y in years)
        cost = sum(y[opt] for y in years)
        invest_y1 = years[0][opt] - years[0]["status_quo"]          # extra spend in year 1
        saving = sq - cost
        cum, payback = 0.0, None
        for i, y in enumerate(years):
            delta = y["status_quo"] - y[opt]
            if cum + delta >= 0 and payback is None and cum < 0:
                payback = round(12 * (i + (-cum / delta if delta else 0)), 0)
            cum += delta
        if payback is None and years[0]["status_quo"] - years[0][opt] >= 0:
            payback = 0
        out[opt] = {"tco_3y": round(cost), "saving_3y": round(saving), "year1_extra": round(invest_y1),
                    "roi_3y_pct": round(100 * saving / max(1, abs(invest_y1))) if invest_y1 > 0 else None,
                    "payback_months": payback,
                    "saving_3y_with_soft": round(saving + 3 * soft * (0.5 if opt == "hybrid" else 1.0))}
    out["status_quo_3y"] = round(sum(y["status_quo"] for y in years))
    return out


def tier_at(gb: float) -> dict:
    """Tier parameters for any daily volume: numeric fields interpolated on log(GB/day) between the reference tiers
    (linear extrapolation in GB beyond them); engine choice and SIEM unit price follow the nearest tier."""
    import math
    ref = sorted(TIERS.values(), key=lambda x: x["gb"])
    lo = max([r for r in ref if r["gb"] <= gb] or [ref[0]], key=lambda r: r["gb"])
    hi = min([r for r in ref if r["gb"] >= gb] or [ref[-1]], key=lambda r: r["gb"])
    out = dict(lo if abs(math.log(gb / lo["gb"])) <= abs(math.log(hi["gb"] / gb)) else hi)
    out["gb"] = gb
    for k, v in lo.items():
        if k == "gb" or not isinstance(v, (int, float)) or isinstance(v, bool):
            continue
        if lo is hi:
            out[k] = v * (gb / lo["gb"]) if k in ("alerts", "human_alerts", "investigations", "hunts", "db_gb", "pg_gb") else v
        else:
            f = (math.log(gb) - math.log(lo["gb"])) / (math.log(hi["gb"]) - math.log(lo["gb"]))
            out[k] = v + (hi[k] - v) * f
    out["engine_azure"] = "duckdb" if gb < 100 else "adx"
    out["workers"] = max(1, round(out["workers"]))
    return out


def breakeven(cloud: str) -> list[dict]:
    rows = []
    for gb in (50, 100, 200, 300, 400, 500, 750, 1000, 1500):
        t = tier_at(gb)
        r = tco(f"{gb}", cloud, t)
        rows.append({"gb": gb, "status_quo": r["status_quo_3y"], "hybrid": r["hybrid"]["tco_3y"], "full": r["full"]["tco_3y"],
                     "full_saving": r["full"]["saving_3y"], "full_saving_with_soft": r["full"]["saving_3y_with_soft"]})
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    res = {"assumptions": {k: v for k, v in A.items()}, "tiers": {}}
    for name, t in TIERS.items():
        res["tiers"][name] = {
            "gb_day": t["gb"],
            "aws": aws_month(t), "aws_as_built": aws_month(t, optimised=False),
            "azure": azure_month(t), "azure_as_built": azure_month(t, optimised=False),
            "sentinel": sentinel_month(t), "splunk_month": splunk_month(t),
            "tco": {"Azure": tco(name, "Azure"), "AWS": tco(name, "AWS")},
        }
    res["breakeven"] = {"Azure": breakeven("Azure"), "AWS": breakeven("AWS")}
    (OUT / "cost_model.json").write_text(json.dumps(res, indent=1, default=str))
    for name, r in res["tiers"].items():
        az, aw = sum(r["azure"].values()), sum(r["aws"].values())
        print(f"{name:6s} {r['gb_day']:5d} GB/day  Azure ${az:>7,}/mo (as built ${sum(r['azure_as_built'].values()):,})"
              f"  AWS ${aw:>7,}/mo (as built ${sum(r['aws_as_built'].values()):,})  Sentinel ${sum(r['sentinel'].values()):,}/mo"
              f"  Splunk ${r['splunk_month'][0]:,}-{r['splunk_month'][1]:,}/mo")
        for c in ("Azure", "AWS"):
            tc = r["tco"][c]
            print(f"   {c:5s} 3y status quo ${tc['status_quo_3y']:,}  hybrid ${tc['hybrid']['tco_3y']:,} "
                  f"(save {tc['hybrid']['saving_3y']:,}, payback {tc['hybrid']['payback_months']})  full ${tc['full']['tco_3y']:,} "
                  f"(save {tc['full']['saving_3y']:,}, payback {tc['full']['payback_months']}, ROI {tc['full']['roi_3y_pct']}%)"
                  f"  soft/yr {tc['soft_value_year']:,}")

    for c in ("Azure", "AWS"):
        print(c, [(b["gb"], b["full_saving"], b["full_saving_with_soft"]) for b in res["breakeven"][c]])


if __name__ == "__main__":
    main()
