"""Generate MERIDIAN's architecture and flow diagrams (SVG, light + dark) and PNGs for the HLD / LLD documents.

    python scripts/make_diagrams.py            # writes docs/images/*.svg (and *.png when playwright is installed)
"""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent.parent / "docs" / "images"
FONT = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
THEMES = {
    "light": dict(bg="#ffffff", panel="#f6f8fa", panel2="#eef1f4", line="#d1d9e0", ink="#1f2328", ink2="#59636e",
                  a1="#0969da", a2="#1a7f37", a3="#9a6700", a4="#8250df", a5="#cf222e", a6="#0e7490", arrow="#6e7781"),
    "dark": dict(bg="#0d1117", panel="#161b22", panel2="#1c2128", line="#30363d", ink="#e6edf3", ink2="#9198a1",
                 a1="#4493f8", a2="#3fb950", a3="#d29922", a4="#ab7df8", a5="#f47067", a6="#39c5cf", arrow="#7d8590"),
}


class D:
    def __init__(self, w: int, h: int, theme: str, title: str, desc: str):
        self.w, self.h, self.t = w, h, THEMES[theme]
        t = self.t
        self.p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="{FONT}" '
                  f'role="img" aria-labelledby="t d"><title id="t">{escape(title)}</title><desc id="d">{escape(desc)}</desc>',
                  f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                  f'<path d="M0,0 L10,5 L0,10 z" fill="{t["arrow"]}"/></marker>'
                  f'<marker id="ahr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                  f'<path d="M0,0 L10,5 L0,10 z" fill="{t["a5"]}"/></marker></defs>',
                  f'<rect width="{w}" height="{h}" fill="{t["bg"]}"/>']

    def rect(self, x, y, w, h, fill=None, stroke=None, r=8, sw=1, dash=None):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill or self.t["panel"]}" '
                      f'stroke="{stroke or self.t["line"]}" stroke-width="{sw}"{da}/>')

    def text(self, x, y, s, size=13, color=None, weight=400, anchor="start"):
        self.p.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{color or self.t["ink"]}" '
                      f'text-anchor="{anchor}" xml:space="preserve">{escape(s)}</text>')

    def lines(self, x, y, items, size=12, color=None, gap=17):
        for i, s in enumerate(items):
            self.text(x, y + i * gap, s, size, color or self.t["ink2"])

    def group(self, x, y, w, h, title, accent, sub=""):
        self.rect(x, y, w, h)
        self.p.append(f'<rect x="{x}" y="{y + 10}" width="4" height="{h - 20}" rx="2" fill="{accent}"/>')
        self.text(x + 16, y + 24, title, 14, weight=650)
        if sub:
            self.text(x + 16, y + 42, sub, 11.5, self.t["ink2"])

    def box(self, x, y, w, h, title, items=(), accent=None, size=12.5):
        self.rect(x, y, w, h, self.t["panel2"], r=6)
        if accent:
            self.p.append(f'<circle cx="{x + 12}" cy="{y + 17}" r="4" fill="{accent}"/>')
        self.text(x + (22 if accent else 10), y + 21, title, size, weight=650)
        self.lines(x + 10, y + 40, list(items), 11.5)

    def arrow(self, pts, label="", color=None, dash=None, lx=None, ly=None, red=False):
        c = self.t["a5"] if red else (color or self.t["arrow"])
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.p.append(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="1.7"{da} marker-end="url(#{"ahr" if red else "ah"})"/>')
        if label:
            (x0, y0), (x1, y1) = pts[0], pts[1]
            self.text(lx if lx is not None else (x0 + x1) / 2 + 6, ly if ly is not None else (y0 + y1) / 2 - 6, label, 11,
                      self.t["a5"] if red else self.t["ink2"])

    def svg(self) -> str:
        return "\n".join(self.p + ["</svg>"])


# ----------------------------------------------------------------------------- logical architecture
def architecture(theme: str) -> str:
    W, H = 1280, 1060
    d = D(W, H, theme, "MERIDIAN logical architecture",
          "Security controls deliver telemetry into a landing zone; deterministic workers normalise it to OCSF, enrich it and "
          "detect threats; the lake keeps it in Parquet under WORM retention. Alerts go to AI agents that work only through "
          "MCP servers; containment is requested and executed only after a human approves. Cases feed LODESTAR.")
    t = d.t
    d.text(32, 44, "MERIDIAN", 24, weight=750)
    d.text(178, 44, "SIEM-less detection, investigation and response with AI agents over MCP", 15, t["ink2"])
    # sources
    d.group(24, 70, 1232, 120, "1  Sources", t["a1"])
    d.text(150, 94, "read-only; no agent on the data path", 11.5, t["ink2"])
    src = [("Endpoint / XDR", "Defender, CrowdStrike, S1"), ("Identity", "Entra ID, Okta"), ("Cloud control plane", "CloudTrail, Azure Activity"),
           ("Network", "firewall, proxy, DNS (syslog CEF)"), ("SaaS & e-mail", "M365, Google, Zscaler"), ("Threat intel", "ISAC / CERT / MISP lists")]
    for i, (a, b) in enumerate(src):
        d.box(40 + i * 202, 112, 192, 62, a, [b], t["a1"])
    # collection + landing
    d.group(24, 212, 610, 132, "2  Collection - native exports, no SIEM agents", t["a2"])
    for i, (a, b) in enumerate([("Event Hubs Capture", "Azure: XDR, diagnostics"), ("S3 / Security Lake", "AWS: CloudTrail, OCSF"),
                                ("syslog receiver", "CEF from appliances"), ("HTTPS push", "HMAC + timestamp")]):
        d.box(40 + i * 148, 256, 140, 70, a, [b], t["a2"], 12)
    d.group(650, 212, 606, 132, "3  Landing zone", t["a2"], "raw batches, immutable, replayable (90 days)")
    d.box(668, 262, 270, 64, "Object storage", ["ADLS Gen2 container / S3 bucket"], t["a2"])
    d.box(954, 262, 284, 64, "New-batch notification", ["Event Grid -> Storage Queue / S3 -> SQS"], t["a2"])
    # ingestion workers
    d.group(24, 366, 1232, 150, "4  Ingestion workers (deterministic, auto-scaled on queue depth)", t["a3"])
    steps = [("Map to OCSF", ["6 format mappers + field maps"]), ("Enrich", ["CMDB criticality, identity,", "threat-intel IOC hits"]),
             ("Write lake", ["Parquet (zstd), cls/dt/hr", "idempotent per batch"]), ("Stream detections", ["Sigma rules per event", "alert de-dup / suppression"])]
    for i, (a, items) in enumerate(steps):
        x = 40 + i * 304
        d.box(x, 412, 286, 86, a, items, t["a3"])
        if i:
            d.arrow([(x - 16, 455), (x - 2, 455)])
    # lake + engines | detections
    d.group(24, 538, 600, 168, "5  Security data lake", t["a6"], "OCSF-flat Parquet; WORM (Object Lock / immutability); tiered")
    d.box(40, 600, 176, 88, "DuckDB", ["embedded, no cluster", "small / mid estates"], t["a6"])
    d.box(228, 600, 176, 88, "Amazon Athena", ["serverless Trino", "pay per TB scanned"], t["a6"])
    d.box(416, 600, 192, 88, "Azure Data Explorer", ["KQL, large estates", "(optional)"], t["a6"])
    d.group(640, 538, 616, 168, "6  Detection & alerting", t["a3"])
    d.box(656, 582, 286, 106, "Correlation rules", ["every 5 min on the lake", "spray, brute force, MFA fatigue,", "DNS tunnel, mass change"], t["a3"])
    d.box(956, 582, 284, 106, "Alert store + work queue", ["PostgreSQL (Aurora / Flexible)", "dedupe -> triage queue", "audit hash chain"], t["a3"])
    # agents + MCP + models
    d.group(24, 728, 820, 190, "7  Agent layer - every tool call goes through MCP", t["a4"])
    for i, (a, b) in enumerate([("Triage", "every new alert"), ("Investigate", "cases sev >= 4"), ("Hunt", "IOC / hypothesis"), ("Tune", "noisy rules")]):
        d.box(40 + i * 120, 772, 112, 58, a, [b], t["a4"], 12)
    d.box(40, 842, 472, 60, "MCP servers (streamable HTTP, bearer + scopes)",
          ["lake (read) · context (read) · cases (notes) · response (REQUEST only)"], t["a4"])
    d.box(528, 772, 300, 130, "Models", ["Foundry: Claude, Azure-hosted, US Data Zone", "  (managed identity, private endpoint)",
                                          "Bedrock: Claude, cross-region profile", "  (IAM role, bedrock-runtime endpoint)",
                                          "Halted / over budget = rules analyst"], t["a4"])
    # humans + response + lodestar
    d.group(860, 728, 396, 190, "8  People decide", t["a5"])
    d.box(876, 772, 364, 56, "Console · Slack · Teams", ["cases, approvals, four-eyes, SSO + roles"], t["a5"])
    d.box(876, 842, 176, 60, "Response executor", ["after approval only"], t["a5"])
    d.box(1064, 842, 176, 60, "Targets", ["MDE, Entra, IAM, EDL"], t["a5"])
    d.arrow([(1052, 872), (1062, 872)], red=True)
    # bottom: lodestar + ops
    d.rect(24, 940, 1232, 96)
    d.text(40, 966, "Hand-offs and operations", 14, weight=650)
    d.lines(40, 990, ["LODESTAR: cases pushed as SOC findings (signed webhook) -> CISO Today list, KRIs (MTTD, incidents) and board reports",
                      "Ops: /healthz /readyz /metrics (Prometheus) · JSON logs · agent spend budgets · golden-set evaluation gates model changes",
                      "Security: no keys (managed identity / IAM roles), private endpoints, KMS / CMK, WORM lake, tamper-evident audit chain"], 12)
    # flow arrows between sections
    d.arrow([(330, 190), (330, 210)])
    d.arrow([(940, 190), (940, 210)])
    d.arrow([(634, 290), (666, 290)])
    d.arrow([(1096, 344), (1096, 364)], "notify")
    d.arrow([(924, 516), (924, 536)])
    d.arrow([(320, 516), (320, 536)])
    d.arrow([(1098, 706), (1098, 726), (700, 726)], "", lx=0, ly=0)
    d.arrow([(624, 645), (654, 645)])
    d.arrow([(844, 800), (874, 800)])
    return d.svg()


# ----------------------------------------------------------------------------- cloud deployments
def deployment(theme: str, cloud: str) -> str:
    W, H = 1280, 900
    az = cloud == "azure"
    name = "Microsoft Azure + Microsoft Foundry" if az else "Amazon Web Services + Amazon Bedrock"
    d = D(W, H, theme, f"MERIDIAN on {name}", f"Deployment of MERIDIAN on {name}: private networking, managed identities, "
          "landing and lake storage, queue-driven workers, PostgreSQL, model endpoint and the agent / approval path.")
    t = d.t
    d.text(32, 44, f"MERIDIAN on {name}", 22, weight=750)
    d.text(32, 66, "reference deployment - infra/" + cloud + " (Terraform)", 13, t["ink2"])
    region = "Region A (data residency, e.g. UAE North)" if az else "Region A (data residency, e.g. me-central-1)"
    d.rect(24, 86, 1232, 650, t["bg"], t["line"], dash="6 4")
    d.text(40, 108, region, 13, t["ink2"], 600)
    vnet = "VNet 10.60.0.0/16 (private endpoints, no public data plane)" if az else "VPC 10.70.0.0/16 (3 AZ private subnets, VPC endpoints)"
    d.rect(40, 120, 860, 600, t["panel"], t["a1"], dash="4 3")
    d.text(56, 142, vnet, 13, t["a1"], 650)
    # compute
    comp = "Container Apps environment (internal, zone-redundant)" if az else "ECS cluster on Fargate (ARM64, private subnets)"
    d.rect(56, 156, 828, 208, t["panel2"])
    d.text(72, 178, comp, 13, weight=650)
    roles = [("api", ["console, REST, MCP", "2-4 replicas"]), ("worker", ["ingestion + detection", "scales on queue"]),
             ("agents", ["triage / investigate", "model + MCP"]), ("scheduler", ["correlations, expiry", "LODESTAR push"]),
             ("syslog", ["CEF receiver", "UDP/TCP 5514"] if not az else ["CEF receiver", "(VM / ACI on VNet)"])]
    for i, (r, items) in enumerate(roles):
        d.box(72 + i * 162, 192, 150, 76, r, items, t["a3"])
    ident = "User-assigned managed identity (no keys): Blob Data Contributor, Queue Processor, Key Vault Secrets User, Azure AI User" if az \
        else "Task roles (no keys): app = lake/landing/SQS/Athena; agents = + bedrock:InvokeModel on approved models; api = tag-scoped response"
    d.text(72, 292, ident, 11.5, t["ink2"])
    lb = "Internal ingress -> Application Gateway WAF / Front Door Premium (Private Link) for users" if az else \
        "Internal ALB (TLS 1.3 policy) -> your edge / SSO for users; add your own NLB to expose syslog on-premises"
    d.text(72, 312, lb, 11.5, t["ink2"])
    sec = "Key Vault (RBAC, purge protection) holds API keys, session, ingest, EDL, metrics, OIDC, LODESTAR secrets" if az else \
        "Secrets Manager (KMS) holds API keys, session, ingest, EDL, metrics, OIDC, LODESTAR secrets; Aurora manages its own"
    d.text(72, 332, sec, 11.5, t["ink2"])
    # data
    d.rect(56, 380, 828, 200, t["panel2"])
    d.text(72, 402, "Data", 13, weight=650)
    if az:
        data = [("Event Hubs", ["mde / entra / activity hubs", "Capture -> Avro -> landing"]),
                ("ADLS Gen2", ["landing (90 d) + lake", "WORM immutability 365 d"]),
                ("Storage Queue", ["Event Grid BlobCreated", "-> worker trigger"]),
                ("PostgreSQL Flex", ["zone-redundant HA", "35 d PITR, geo backup"]),
                ("ADX (optional)", ["KQL over the lake", "large estates"])]
    else:
        data = [("S3 landing", ["raw batches, 90 d", "SSE-KMS, versioned"]), ("S3 lake", ["Parquet, Object Lock", "GOVERNANCE/COMPLIANCE"]),
                ("SQS (+DLQ)", ["S3 ObjectCreated", "-> worker trigger"]), ("Aurora PG v2", ["2 instances, 35 d", "managed secret"]),
                ("Glue + Athena", ["partition projection", "100 GB/query cap"])]
    for i, (r, items) in enumerate(data):
        d.box(72 + i * 162, 416, 150, 76, r, items, t["a6"])
    feed = ("Defender XDR streaming API, Entra diagnostic settings and Azure Activity -> Event Hubs; firewalls -> syslog; others -> HTTPS push"
            if az else "Org CloudTrail + Security Lake (OCSF) -> S3; firewalls -> syslog via NLB; SaaS -> Firehose / HTTPS push")
    d.text(72, 516, feed, 11.5, t["ink2"])
    d.text(72, 536, "Lifecycle: lake cool 30 d -> cold 90 d -> archive 400 d" if az else
           "Lifecycle: lake Standard-IA 30 d -> Glacier IR 180 d; landing expires 90 d", 11.5, t["ink2"])
    d.text(72, 556, "Platform logs only in Log Analytics (2 GB/day cap) - security telemetry never pays per-GB SIEM ingestion" if az else
           "Platform logs in CloudWatch (30 d, KMS) - security telemetry never pays per-GB SIEM ingestion", 11.5, t["ink2"])
    # private endpoints row
    d.rect(56, 596, 828, 110, t["panel2"])
    d.text(72, 618, "Private connectivity", 13, weight=650)
    pe = ["Private endpoints: blob, dfs, queue, Key Vault, Foundry (services.ai.azure.com / cognitiveservices)",
          "Private DNS zones linked to the VNet; storage, Key Vault and Foundry deny public network access",
          "Egress to vendor APIs (EDR, IdP, intel) through your firewall / NAT; inference is processed in the US data zone"] if az else \
         ["Gateway endpoint: S3.  Interface endpoints: SQS, Secrets Manager, Logs, ECR, STS, Athena, Glue, KMS, bedrock-runtime",
          "NAT gateway (optional) only for vendor SaaS APIs; Bedrock is called in-region, inference routed globally",
          "Security groups: app <- VPC only; DB <- app only; endpoints <- app only"]
    d.lines(72, 642, pe, 11.5)
    # right column: model + human
    d.group(916, 120, 324, 250, "Model platform", t["a4"])
    if az:
        d.lines(932, 168, ["Foundry account in a US region (eastus2)", "Claude is not offered in UAE North",
                           "meridian-fast / meridian-deep:", "  claude-sonnet-5-5, Hosted on Azure", "  Data Zone Standard (US) - pinned",
                           "local auth disabled -> Entra only", "private endpoint in the UAE VNet", "Agent Service (optional):",
                           "  MCP tool -> /mcp/<server>/"], 12, t["ink"])
    else:
        d.lines(932, 168, ["Amazon Bedrock, called in me-central-1", "bedrock-runtime VPC endpoint", "Claude via GLOBAL cross-region",
                           "  inference profiles (only option", "  from UAE for Sonnet 5.5)", "fast: Haiku 4.5 / deep: Sonnet 5.5",
                           "IAM: profile + model ARNs only", "AgentCore: not in UAE/Bahrain;", "  optional from another region"], 12, t["ink"])
    d.group(916, 390, 324, 330, "People and response", t["a5"])
    d.lines(932, 438, ["SSO (OIDC): Entra ID / Okta" if az else "SSO (OIDC): Entra ID / Okta / Cognito",
                       "roles: viewer, analyst, responder, admin", "approvals: four-eyes, 24 h expiry", "",
                       "Executed after approval (dry-run first):",
                       "  Defender isolate, Entra revoke / disable" if az else "  IAM key deactivate, EC2 quarantine SG",
                       "  EDL block list for firewalls / proxies", "  SOAR playbook (signed webhook)", "",
                       "Teams / Slack: approval requests,", "critical cases; LODESTAR hand-off"], 12, t["ink"])
    d.arrow([(884, 230), (914, 230)], "")
    d.arrow([(884, 470), (914, 470)], "")
    # region B note
    d.rect(24, 752, 1232, 126, t["panel"])
    d.text(40, 776, "Data flow and cost posture", 14, weight=650)
    d.lines(40, 800, [
        "1. Telemetry lands as files (no per-GB SIEM ingestion licence)  2. Workers normalise, enrich, detect and write Parquet  "
        "3. Alerts -> triage agent via MCP",
        "4. Cases sev >= 4 -> investigation agent; containment is requested  5. Responder approves in the console / chat  "
        "6. Executor acts; everything is audit-chained",
        "Model spend is bounded: per-run and daily budgets; when exceeded or the endpoint is down, triage degrades to the "
        "deterministic analyst (labelled)."], 12)
    return d.svg()


# ----------------------------------------------------------------------------- sequence diagrams
def sequence(theme: str, title: str, actors: list[str], msgs: list[tuple], desc: str, h_extra: int = 0) -> str:
    W = 1280
    H = 130 + len(msgs) * 46 + h_extra
    d = D(W, H, theme, title, desc)
    t = d.t
    d.text(32, 40, title, 20, weight=750)
    n = len(actors)
    xs = [90 + i * (W - 180) / (n - 1) for i in range(n)]
    for x, a in zip(xs, actors, strict=True):
        d.rect(x - 78, 58, 156, 40, t["panel2"], t["line"], r=6)
        for j, part in enumerate(a.split("\n")):
            d.text(x, 74 + j * 15 - (6 if "\n" in a else -4), part, 12, weight=650, anchor="middle")
        d.p.append(f'<line x1="{x}" y1="98" x2="{x}" y2="{H - 20}" stroke="{t["line"]}" stroke-width="1.2" stroke-dasharray="4 4"/>')
    y = 128
    for m in msgs:
        if m[0] == "note":
            d.rect(60, y - 18, W - 120, 30, t["panel"], t["a3"], r=5)
            d.text(W / 2, y + 2, m[1], 12, t["ink"], 600, "middle")
            y += 46
            continue
        a, b, label = m[0], m[1], m[2]
        style = m[3] if len(m) > 3 else ""
        xa, xb = xs[a], xs[b]
        red = style == "human"
        if a == b:
            d.p.append(f'<path d="M{xa},{y - 8} h40 v18 h-36" fill="none" stroke="{t["arrow"]}" stroke-width="1.6" marker-end="url(#ah)"/>')
            d.text(xa + 48, y + 4, label, 12, t["ink"])
        else:
            dash = "6 4" if style == "reply" else None
            d.arrow([(xa, y), (xb + (-4 if xb > xa else 4), y)], red=red, dash=dash)
            d.text((xa + xb) / 2, y - 7, label, 12, t["a5"] if red else t["ink"], 500, "middle")
        y += 46
    return d.svg()


FLOWS = {
    "flow-ingest": ("Flow 1 - Ingestion and streaming detection",
                    ["Security control", "Landing\n(ADLS / S3)", "Queue\n(Storage Q / SQS)", "Ingestion worker", "Lake\n(Parquet, WORM)",
                     "Alert store"],
                    [(0, 1, "export / Capture / syslog flush / HTTPS push (batch file)"),
                     (1, 2, "BlobCreated / ObjectCreated notification"),
                     (2, 3, "receive (visibility 15 min)"),
                     (3, 1, "get batch (Avro / JSON / CEF lines)"),
                     (3, 3, "map -> OCSF-flat, de-duplicate, enrich (CMDB, identity, IOC)"),
                     (3, 4, "write Parquet cls/dt/hr/<batch-hash> (idempotent)"),
                     (3, 3, "Sigma rules per event; group by rule + entity + window"),
                     (3, 5, "upsert alert; new alert -> enqueue 'triage'"),
                     (3, 2, "delete message (ack); mark batch processed", "reply"),
                     ("note", "Every 5 minutes: correlation rules run as aggregate queries on the lake (DuckDB / Athena / ADX) -> alerts")],
                    "Telemetry arrives as files, is normalised and enriched by deterministic workers, written to the lake and "
                    "evaluated by streaming rules; alerts are de-duplicated and queued for triage."),
    "flow-triage": ("Flow 2 - Alert triage, case and investigation",
                    ["Work queue", "Triage agent", "MCP servers\n(lake, context)", "Model\n(Foundry / Bedrock)", "Case store",
                     "Investigation\nagent"],
                    [(0, 1, "lease 'triage' item (alert id)"),
                     (1, 3, "system prompt + alert (untrusted data marked) + tool list"),
                     (3, 1, "tool_use: lookup_asset, related_alerts", "reply"),
                     (1, 2, "MCP tools/call with agent token (scopes: lake:read, context:read)"),
                     (2, 1, "results (row-capped, query_id, UNTRUSTED notice)", "reply"),
                     (1, 3, "tool results"),
                     (3, 1, "tool_use: submit_result {verdict, confidence, evidence}", "reply"),
                     (1, 1, "validate schema; policy decides (not the model)"),
                     (1, 4, "benign >= 0.8 -> close; else join / open case by shared entity"),
                     (4, 5, "sev >= 4 or malicious -> enqueue 'investigate'"),
                     ("note", "Budget guard: over the daily model budget or model unavailable -> deterministic analyst, labelled 'degraded'")],
                    "Every new alert is triaged by an agent that can only read through MCP; policy, not the model, closes alerts "
                    "and opens or joins cases; serious cases go to the investigation agent."),
    "flow-response": ("Flow 3 - Investigation, approval and containment",
                      ["Investigation\nagent", "MCP servers\n(cases, response)", "Approvals", "Responder\n(console / Teams)",
                       "Response\nexecutor", "Target\n(MDE, Entra, IAM, EDL)"],
                      [(0, 1, "get_case, entity_timeline, ioc_sweep (read)"),
                       (0, 1, "add_case_note (timeline, scope, root cause)"),
                       (0, 1, "request_containment(action, target, rationale)"),
                       (1, 2, "validate target (no internal ranges, id formats); create PENDING approval"),
                       (2, 3, "notify: Teams / Slack card + console queue", "human"),
                       (3, 2, "approve (SSO, role responder, CSRF, not the requester)", "human"),
                       (2, 4, "atomic pending -> approved (expiry checked); execute once"),
                       (4, 5, "dry-run first; then API call with managed identity / role"),
                       (5, 4, "result", "reply"),
                       (4, 2, "record result; case -> contained; audit chain entry"),
                       ("note", "The agent never holds credentials for the targets and cannot approve; rejection keeps the case open")],
                      "Agents request containment through MCP; a responder approves in the console or chat; only then does the "
                      "executor act, once, with the platform identity, and the outcome is recorded."),
    "flow-remote-agents": ("Flow 4 - Managed agent option: Foundry Agent Service / AgentCore Gateway calling MERIDIAN MCP",
                           ["Foundry Agent\nService / AgentCore", "Toolbox /\nGateway + Policy", "MERIDIAN /mcp/*\n(bearer gate)",
                            "Tool code\n(scope re-check)", "Lake / store"],
                           [(0, 1, "agent invokes tool lake.search_events"),
                            (1, 1, "Foundry: allowed_tools + require_approval | AgentCore: Cedar default-deny"),
                            (1, 2, "streamable HTTP POST + OAuth / Entra token (managed identity)"),
                            (2, 2, "verify JWT (issuer, audience, expiry) -> roles -> scopes (mcp_scope_map)"),
                            (2, 3, "caller bound; 403 if the server's scope is missing"),
                            (3, 4, "compiled, parameterised query (row / time limits)"),
                            (4, 3, "rows", "reply"),
                            (3, 0, "structured result + UNTRUSTED notice; audit 'tool:*' entry", "reply"),
                            ("note", "Response tools stay request-only: approval still happens in MERIDIAN with a human")],
                           "When agents run in Microsoft Foundry Agent Service or behind Amazon Bedrock AgentCore Gateway, they reach "
                           "MERIDIAN's MCP servers over private networking with OAuth tokens; MERIDIAN re-checks scopes and limits."),
}


def integration(theme: str) -> str:
    W, H = 1280, 760
    d = D(W, H, theme, "MERIDIAN and LODESTAR integration",
          "MERIDIAN detects, triages and contains; it pushes cases and SOC health to LODESTAR over a signed webhook. LODESTAR "
          "correlates them with the other control domains and puts them on the CISO's Today list and board reports. "
          "Both products read the same CMDB and identity exports.")
    t = d.t
    d.text(32, 44, "MERIDIAN -> LODESTAR", 22, weight=750)
    d.text(330, 44, "one-way, signed, idempotent hand-off of SOC cases and health", 14, t["ink2"])
    # MERIDIAN
    d.group(24, 70, 560, 480, "MERIDIAN  (SOC engine - detect, triage, investigate, contain)", t["a4"])
    d.box(44, 120, 250, 70, "Lake + rules", ["OCSF Parquet, Sigma, correlations"], t["a6"])
    d.box(314, 120, 250, 70, "Agents over MCP", ["triage, investigate, hunt"], t["a4"])
    d.box(44, 210, 520, 80, "Cases", ["entities, verdict, severity, MITRE, approvals, containment",
                                      "store: PostgreSQL (alerts, cases, audit chain)"], t["a3"])
    d.box(44, 310, 520, 110, "Scheduler: LODESTAR step (hourly, leader-locked)",
          ["lodestar_payload(): open cases + cases changed in 7 days", "identity mapping (most critical asset, user, entity_keys)",
           "health: coverage_pct, incidents_open, mttd_hours, mttr_hours,", "        log_sources_silent"], t["a4"])
    d.box(44, 440, 520, 90, "Signing", ["HMAC-SHA256 over '<unix ts>.<body>'  ->  X-Lodestar-Timestamp,",
                                        "X-Lodestar-Signature: sha256=<hex>; secret in Key Vault / Secrets Manager"], t["a5"])
    # LODESTAR
    d.group(696, 70, 560, 480, "LODESTAR  (CISO prioritisation and reporting)", t["a2"])
    d.box(716, 120, 520, 80, "POST /api/ingest/soc?org=<key>", ["verifies signature + 300 s timestamp window; 5 MB cap;",
                                                                   "upserts by finding_id (re-sends update, never duplicate)"], t["a5"])
    d.box(716, 220, 520, 70, "Webhook inbox -> SOC connector agent", ["adapter: webhook, product: MERIDIAN; health -> ControlHealth"], t["a2"])
    d.box(716, 310, 520, 90, "Correlation + scoring (LRS)", ["CMDB criticality, exposure, actively_exploited_in_env,",
                                                             "toxic combinations with VMDR / identity / EDR findings"], t["a2"])
    d.box(716, 420, 250, 110, "CISO Today / Week", ["prioritised list, owners,", "Slack / Teams digest"], t["a3"])
    d.box(986, 420, 250, 110, "KRIs + board reports", ["MTTD, incidents open,", "SOC coverage, trends"], t["a3"])
    # arrow
    d.arrow([(584, 485), (640, 485), (640, 160), (714, 160)], "")
    d.text(596, 300, "HTTPS", 12, t["ink2"], 650)
    d.text(596, 316, "hourly", 12, t["ink2"])
    d.arrow([(304, 190), (304, 208)])
    d.arrow([(304, 290), (304, 308)])
    d.arrow([(304, 420), (304, 438)])
    d.arrow([(976, 200), (976, 218)])
    d.arrow([(976, 290), (976, 308)])
    d.arrow([(976, 400), (976, 418)])
    # shared context
    d.rect(24, 570, 1232, 80, t["panel"], t["a1"], dash="5 4")
    d.text(40, 596, "Shared context (one source of truth, two readers)", 14, weight=650)
    d.lines(40, 620, ["CMDB export (assets.csv: asset_id, name, criticality, exposure, aliases, ips) and identity export (identities.csv) feed BOTH",
                      "products, so MERIDIAN's 'most critical asset' and LODESTAR's asset criticality agree. Deep link: evidence.case_id -> MERIDIAN console."], 12)
    d.rect(24, 666, 1232, 74, t["panel"])
    d.text(40, 690, "What does not cross", 14, weight=650)
    d.lines(40, 714, ["No raw telemetry, no command lines, no sample events, no credentials. Titles, severity, status, entities, verdict, MITRE and",
                      "aggregate KPIs only. LODESTAR never calls MERIDIAN; MERIDIAN never reads LODESTAR (phase 1)."], 12)
    return d.svg()


def ingestion(theme: str) -> str:
    W, H = 1280, 900
    d = D(W, H, theme, "MERIDIAN log ingestion for hybrid estates",
          "On-premises, cloud and SaaS sources reach MERIDIAN by six paths. All of them land raw batches in object storage; "
          "the ingestion worker normalises them to OCSF, enriches and de-duplicates them, and writes the WORM lake, "
          "where each class can have its own retention.")
    t = d.t
    d.text(32, 44, "Log ingestion: six ways in, one landing zone, one schema", 22, weight=750)
    # sources
    d.group(24, 70, 330, 660, "Where the logs are", t["a1"])
    d.box(44, 118, 290, 130, "On-premises", ["Windows servers + DCs (Security, Sysmon,", "  PowerShell, Defender)  -> WEF / WEC",
                                             "Linux (rsyslog, syslog-ng, journald, auditd)", "Firewalls, proxies, VPN, switches, WAF",
                                             "OT / port systems, appliances (CEF, LEEF)"], t["a1"])
    d.box(44, 266, 290, 150, "Cloud", ["Azure: Entra, Activity, Defender XDR,", "  VNet flow logs, Key Vault, resource logs",
                                       "AWS: CloudTrail (org), VPC Flow Logs,", "  Route 53 Resolver, GuardDuty, Security Lake",
                                       "Workloads: CloudWatch Logs, AKS / EKS,", "  containers, application logs"], t["a6"])
    d.box(44, 434, 290, 110, "SaaS and identity", ["Microsoft 365 audit, Okta, GitHub,", "Google Workspace, Salesforce, Atlassian,",
                                                    "Zscaler, Netskope, CrowdStrike (OCSF)"], t["a4"])
    d.box(44, 562, 290, 150, "Existing SIEM (migration)", ["Splunk HEC senders, Cribl, Logstash",
                                                            "QRadar / ArcSight forwarders (LEEF, CEF)",
                                                            "Sentinel: Log Analytics data export",
                                                            "Run side by side, then cut over",
                                                            "source by source"], t["a3"])
    # paths
    d.group(380, 70, 430, 660, "Six ways in (all private, all authenticated)", t["a4"])
    paths = [("1  Cloud-native export to object storage", ["diagnostic settings, org trail, flow logs, Security Lake;", "no agent, no MERIDIAN code in the path"]),
             ("2  Streaming -> capture", ["Event Hubs Capture (Avro) / Kinesis Firehose (JSON, gzip)", "for high-volume or near-real-time feeds"]),
             ("3  Syslog receiver", ["UDP / TCP 5514, TLS 6514 with optional mutual TLS;", "RFC 3164 / 5424, CEF, LEEF, JSON lines"]),
             ("4  HTTPS push", ["/api/ingest/<source>: HMAC or source token, gzip, NDJSON;", "/services/collector: Splunk HEC-compatible"]),
             ("5  API pull collector", ["polls SaaS APIs: OAuth2 / bearer, cursor, pagination,", "two-step (Microsoft 365 contentUri)"]),
             ("6  Shipper -> object storage", ["Fluent Bit, Vector, Cribl, Logstash, NXLog Agent", "write batches straight to Blob / S3"])]
    y = 118
    for title, items in paths:
        d.box(400, y, 390, 86, title, items, t["a4"])
        y += 102
    # landing -> lake
    d.group(836, 70, 420, 660, "Inside MERIDIAN", t["a2"])
    d.box(856, 118, 380, 96, "Landing zone (ADLS / S3)", ["raw batches exactly as received, gzip, immutable;",
                                                            "90 days, replayable: fix a mapper, then replay"], t["a2"])
    d.box(856, 232, 380, 120, "Ingestion worker (scales on queue depth)", ["mapper per source: windows | syslog | cef | leef | mde |",
                                                                           "  entra | cloudtrail | ocsf | json (field map)",
                                                                           "-> OCSF-flat (42 typed columns, raw record kept)",
                                                                           "-> UTC time, enrichment, de-duplication"], t["a2"])
    d.box(856, 370, 380, 110, "Security lake (Parquet, WORM)", ["events/cls=<class>/dt=<day>/hr=<hour>",
                                                               "Object Lock / immutability for the retention period",
                                                               "tiering: cool / IA at 30 d, archive / Glacier IR later"], t["a2"])
    d.box(856, 498, 380, 96, "Rotation", ["end of life per OCSF class (e.g. flows 13 months,", "authentication 7 years); never before WORM ends"], t["a3"])
    d.box(856, 612, 380, 100, "Detection and agents", ["streaming Sigma rules on every batch; correlations", "every 5 min; agents query through MCP only"], t["a5"])
    for yy in (214, 352, 480, 594):
        d.arrow([(1046, yy), (1046, yy + 16)])
    for yy in (161, 263, 365, 467, 569, 671):
        d.arrow([(790, yy), (812, yy), (812, 166), (854, 166)])
    for yy in (183, 341, 489, 637):
        d.arrow([(334, yy), (398, yy)])
    # bottom
    d.rect(24, 748, 1232, 138, t["panel"])
    d.text(40, 772, "What makes this different from a SIEM ingestion tier", 14, weight=650)
    d.lines(40, 796, ["No per-GB licence and no daily cap: storage is paid at object-storage prices, so nothing is filtered out to save money.",
                      "Nothing is lost to parsing: unparsed lines are kept as OCSF Base Events and every raw batch stays replayable for 90 days.",
                      "One schema for every engine (DuckDB, Athena, Azure Data Explorer) and every agent; mappers are tested code, previewed with map-test.",
                      "Retention is a storage setting, per log type, enforced by WORM - not a licence tier. Silent sources and reject rates are metrics."], 12)
    return d.svg()


LOG_FLOWS = {
    "flow-log-onprem": ("Ingestion flow - Windows and Linux on premises over TLS syslog",
                        ["Windows server\n(Security, Sysmon)", "WEC + NXLog\n(collector)", "MERIDIAN\nsyslog (TLS)", "Landing\nzone",
                         "Ingestion\nworker", "Lake +\ndetection"],
                        [(0, 1, "WEF subscription (Kerberos, HTTP 5985, encrypted): ForwardedEvents"),
                         (1, 1, "im_msvistalog -> to_json(); query filters to the event IDs you use"),
                         (1, 2, "om_ssl to 6514: mutual TLS (client certificate from the internal CA)"),
                         (2, 2, "buffer; flush every 30 s or 20,000 lines; storage outage = retry, not loss"),
                         (2, 3, "syslog/<yyyy>/<mm>/<dd>/<batch>.log.gz"),
                         (3, 4, "queue message (Event Grid / S3 event) -> worker"),
                         (4, 4, "syslog -> JSON -> windows mapper; local time -> UTC"),
                         (4, 5, "OCSF-flat Parquet; Sigma rules (process_creation, auditlogs, ...) -> alerts"),
                         ("note", "Linux hosts use rsyslog / syslog-ng with TLS to the same port; network devices send to a local relay.")],
                        "Windows events reach MERIDIAN without an agent on each server: Windows Event Forwarding to a collector, NXLog to the TLS syslog receiver."),
    "flow-log-pull": ("Ingestion flow - SaaS API pull (Microsoft 365 Management Activity)",
                      ["MERIDIAN\ncollector", "Store\n(cursor)", "Entra ID\n(token)", "Microsoft 365\nAPI", "Landing\nzone"],
                      [(0, 1, "lease lock held; source due (interval); read cursor"),
                       (0, 2, "client credentials (secret from Key Vault / Secrets Manager)"),
                       (2, 0, "access token (cached until expiry)", "reply"),
                       (0, 3, "GET content?contentType=Audit.General&startTime={cursor}&endTime={end}"),
                       (3, 0, "list of content blobs + NextPageUri", "reply"),
                       (0, 3, "GET each contentUri (two-step API)"),
                       (0, 4, "batches of up to 10,000 records (JSON lines, gzip)"),
                       (0, 1, "cursor = window end - only after the batches are written"),
                       ("note", "HTTP 429 or 5xx stops the run without moving the cursor; the next run resumes from the same point.")],
                      "The API collector pulls from SaaS APIs on a schedule and lands the results like any other batch."),
}


INT_FLOWS = {
    "flow-int-push": ("Integration flow 1 - hourly case and health hand-off",
                      ["MERIDIAN\nscheduler", "MERIDIAN\nstore", "Key Vault /\nSecrets Mgr", "LODESTAR\n/api/ingest/soc",
                       "LODESTAR\nstore", "LODESTAR\npipeline"],
                      [(0, 0, "leader lock held; 'lodestar' step due (>= 1 h since cursor)"),
                       (0, 1, "open cases + cases changed in 7 days; source freshness; MTTD / MTTR"),
                       (1, 0, "findings[] (finding_id = meridian-<case_id>) + health", "reply"),
                       (2, 0, "LODESTAR_WEBHOOK_SECRET (env, loaded at start)", "reply"),
                       (0, 3, "POST ?org=<key>  X-Lodestar-Timestamp + X-Lodestar-Signature"),
                       (3, 3, "size <= 5 MB; |now - ts| <= 300 s; HMAC(org secret) matches"),
                       (3, 4, "upsert by finding_id (domain=soc); set SOC health"),
                       (3, 0, "202 {accepted: n}  |  401 bad signature  |  404 unknown org  |  422 bad item", "reply"),
                       (0, 1, "cursor scheduler:lodestar_push = now (only after a 2xx)"),
                       (5, 4, "next run: SOC connector reads inbox (30-day retention) -> score -> Today list"),
                       ("note", "A failed push is logged and isolated; the next cycle retries. LODESTAR's freshness KRI shows the gap.")],
                      "MERIDIAN pushes its cases and SOC health to LODESTAR every hour over a signed, idempotent webhook."),
    "flow-int-lifecycle": ("Integration flow 2 - one incident, both products",
                           ["Analyst /\nresponder", "MERIDIAN", "LODESTAR", "CISO"],
                           [(1, 1, "alerts -> triage -> case (malicious) on ws-0142 + fs-01"),
                            (1, 2, "finding: critical, open, asset = fs-01 (most critical), actively_exploited_in_env = true"),
                            (2, 2, "LRS: severity + active exploitation + business-critical asset -> TODAY"),
                            (2, 3, "Today list / digest: 'why' = active exploitation, business-critical asset", "human"),
                            (0, 1, "approve isolate_device + revoke_sessions (four-eyes)", "human"),
                            (1, 2, "next push: status in_progress (contained)"),
                            (0, 1, "close case: verdict malicious, resolved"),
                            (1, 2, "next push: status resolved, actively_exploited_in_env = false"),
                            (2, 3, "item leaves Today; MTTD / MTTR KRIs and board report updated", "human")],
                           "A malicious case in MERIDIAN becomes a Today item in LODESTAR and leaves it when MERIDIAN resolves it."),
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    files = []
    for th in THEMES:
        files.append((OUT / f"architecture-{th}.svg", architecture(th)))
    for th in ("light",):
        files.append((OUT / f"azure-{th}.svg", deployment(th, "azure")))
        files.append((OUT / f"aws-{th}.svg", deployment(th, "aws")))
        for name, (title, actors, msgs, desc) in {**FLOWS, **INT_FLOWS, **LOG_FLOWS}.items():
            files.append((OUT / f"{name}-{th}.svg", sequence(th, title, actors, msgs, desc)))
        files.append((OUT / f"integration-{th}.svg", integration(th)))
        files.append((OUT / f"ingestion-{th}.svg", ingestion(th)))
    for p, s in files:
        p.write_text(s, encoding="utf-8")
        print("wrote", p.name)
    try:
        import asyncio

        from playwright.async_api import async_playwright

        async def png():
            async with async_playwright() as pw:
                b = await pw.chromium.launch()
                for p, s in files:
                    if "-dark" in p.name:
                        continue
                    w = int(s.split('width="')[1].split('"')[0])
                    h = int(s.split('height="')[1].split('"')[0])
                    pg = await b.new_page(viewport={"width": w, "height": h}, device_scale_factor=2)
                    await pg.goto(p.as_uri())
                    await pg.screenshot(path=str(p.with_suffix(".png")))
                    await pg.close()
                await b.close()
        asyncio.run(png())
        print("PNG renders written")
    except ImportError:
        print("playwright not installed - SVG only")


if __name__ == "__main__":
    main()
