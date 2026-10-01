"""Build the MERIDIAN engineering documents (PDF) from their markdown sources.

    python scripts/build_pdf_docs.py            # all documents
    python scripts/build_pdf_docs.py AZ-00      # one document

Sources (markdown with front matter):
    docs/cloud/MERIDIAN-AZ-00.md, docs/cloud/MERIDIAN-AWS-00.md, docs/integration/MERIDIAN-LODESTAR-INT-00.md
Output: docs/pdf/<file name from front matter>.pdf

Source conventions
    ## 3 Title                       numbered section (starts a new page)
    :::box red WHAT DOES NOT CHANGE  callout (red | green | amber | blue | grey | navy), closed by :::
    !fig images/x.svg 2.1 Caption    figure with numbered caption (path relative to docs/)
    {{AGENT_TABLE}} {{AGENT_APPENDIX}} {{VERSION}} {{DATE}}   generated from code at build time
Requires: markdown, playwright (Chromium), pdfplumber.
"""
from __future__ import annotations

import asyncio
import html
import re
import sys
from datetime import date
from pathlib import Path

import markdown
import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "pdf"
FONTS = Path.home() / ".fonts"
sys.path.insert(0, str(ROOT))

SOURCES = {
    "AZ-00": DOCS / "cloud" / "MERIDIAN-AZ-00.md",
    "AWS-00": DOCS / "cloud" / "MERIDIAN-AWS-00.md",
    "INT-00": DOCS / "integration" / "MERIDIAN-LODESTAR-INT-00.md",
    "LOG-00": DOCS / "ingestion" / "MERIDIAN-LOG-00.md",
}


def _font_faces() -> str:
    faces = []
    for fam, stem in (("Plex", "ibm-plex-sans"), ("PlexMono", "ibm-plex-mono")):
        for w in (400, 500, 600, 700):
            f = FONTS / f"{stem}-latin-{w}-normal.woff"
            if f.exists():
                faces.append(f"@font-face{{font-family:'{fam}';font-weight:{w};src:url('{f.as_uri()}') format('woff');}}")
    return "\n".join(faces)


CSS = """
:root { --navy:#0b1724; --navy2:#13283b; --teal:#1b7f8c; --ink:#1d2733; --ink2:#5b6672; --line:#d8dee4; --paper:#ffffff;
        --blue-bg:#dcecf1; --green-bg:#e3f1e6; --red-bg:#fbe6e6; --amber-bg:#fbf0dc; --grey-bg:#eceff2; }
@page { size: A4; margin: 24mm 17mm 20mm 17mm;
  @top-left { content: "__RUNNING__"; font: 700 6.6pt 'IBM Plex Sans', sans-serif; color:#7b8794;
              letter-spacing:.04em; vertical-align: bottom; padding-bottom: 3mm; border-bottom: .4pt solid #c9d1d8; }
  @top-right { content: "Confidential \\2014  Internal Use Only"; font: 400 6.6pt 'IBM Plex Sans', sans-serif; color:#7b8794;
               vertical-align: bottom; padding-bottom: 3mm; border-bottom: .4pt solid #c9d1d8; }
  @bottom-left { content: "__FOOTER__"; font: 400 6.4pt 'IBM Plex Sans', sans-serif; color:#8a96a3; border-top:.4pt solid #d8dee4; padding-top:2mm; vertical-align: top; }
  @bottom-right { content: counter(page); font: 700 8.5pt 'IBM Plex Sans', sans-serif; color: var(--navy); border-top:.4pt solid #d8dee4; padding-top:2mm; vertical-align: top; } }
@page cover { margin: 0; @top-left{content:none;border:none} @top-right{content:none;border:none} @bottom-left{content:none;border:none} @bottom-right{content:none;border:none} }
html { font-family: 'IBM Plex Sans', 'DejaVu Sans', sans-serif; font-size: 9.1pt; color: var(--ink); line-height: 1.5; }
body { margin: 0; }
.runstr { string-set: running content(); display:none }
.footstr { string-set: footer content(); display:none }
.cover { page: cover; height: 296.6mm; width: 210mm; background: var(--navy); color: #fff; position: relative; overflow: hidden; break-after: page; }
.cover .bar { position:absolute; top: 9mm; left:0; right:0; height: 3mm; background: var(--teal); }
.cover .ticks { position:absolute; top: 12mm; left: 47mm; height: 38mm; width: 140mm;
  background: repeating-linear-gradient(90deg, rgba(255,255,255,.18) 0 .3mm, transparent .3mm 25.5mm); }
.cover .rings { position:absolute; right:-70mm; bottom:-60mm; width: 190mm; height: 190mm; border-radius: 50%;
  background: repeating-radial-gradient(circle, transparent 0 6.6mm, rgba(120,150,170,.28) 6.6mm 6.9mm); }
.cover .kicker { position:absolute; top: 72mm; left: 23mm; font: 700 7.6pt 'IBM Plex Sans'; letter-spacing:.08em; color:#8fd0d9; }
.cover h1 { position:absolute; top: 79mm; left: 22mm; margin:0; font: 800 34pt 'Poppins', sans-serif; letter-spacing:.01em; }
.cover .rule { position:absolute; top: 103mm; left: 23mm; width: 31mm; height: 1mm; background: var(--teal); }
.cover .sub { position:absolute; top: 108mm; left: 23mm; font: 300 15pt 'Poppins'; color:#d4dde5; }
.cover .summary { position:absolute; top: 140mm; left: 23mm; width: 135mm; border-left: .6mm solid var(--teal); padding-left: 3mm;
  font: 400 7.9pt/1.6 'IBM Plex Sans'; color:#c5d0da; }
.cover .meta { position:absolute; top: 183mm; left: 23mm; width: 175mm; border-top: .3pt solid #3a4c5e; padding-top: 2mm;
  display: grid; grid-template-columns: repeat(5, 1fr); font: 400 6.8pt 'IBM Plex Sans'; color:#9fb0bf; }
.cover .meta b { display:block; color:#fff; font-weight:700; margin-top: 1.4mm; font-size: 7.4pt; }
h1.doc { font: 800 21pt 'Poppins'; color: var(--navy); margin: 0 0 1mm; }
.lede { font-size: 10.3pt; color: var(--ink2); margin: 0 0 4mm; }
h1.toc-title { font: 800 20pt 'Poppins'; color: var(--navy); margin: 0 0 5mm; padding-bottom: 1.5mm; border-bottom: 1.2mm solid var(--teal); display:inline-block; }
.toc { break-after: page; }
.toc a { display:flex; color: var(--ink); text-decoration:none; font-size: 9.4pt; margin: 0 0 4.2mm; }
.toc a .t { white-space: nowrap; }
.toc a .dots { flex: 1; border-bottom: 1.2pt dotted #9aa6b2; margin: 0 1.6mm 1.2mm; }
h2 { font: 700 15pt 'Poppins'; color: var(--navy); margin: 0 0 3mm; break-before: page; break-after: avoid; }
h2.first { break-before: auto; }
h2 .num { color: var(--teal); margin-right: 1.5mm; }
h3 { font: 600 11.2pt 'Poppins'; color: var(--teal); margin: 6mm 0 2mm; break-after: avoid; }
h4 { font: 700 9.4pt 'IBM Plex Sans'; color: var(--navy); margin: 4mm 0 1.5mm; break-after: avoid; }
p { margin: 0 0 2.6mm; text-align: justify; }
ul, ol { margin: 0 0 3mm; padding-left: 5.5mm; } li { margin: 0 0 1mm; }
ul li::marker { content: "\\25A0  "; color: var(--navy); font-size: 7.5pt; }
code { font-family: 'IBM Plex Mono', monospace; font-size: 8.1pt; color: #24323f; }
pre { background: var(--navy); color: #e1e9ef; padding: 3.5mm 4mm; border-radius: 1mm; font-size: 7.5pt; line-height: 1.55;
      white-space: pre-wrap; break-inside: avoid; margin: 0 0 4mm; }
pre code { color: inherit; font-size: inherit; }
table { width: 100%; border-collapse: collapse; margin: 1mm 0 4.5mm; font-size: 7.9pt; break-inside: auto; }
thead { display: table-header-group; }
th { background: var(--navy); color: #fff; text-align: left; font-weight: 700; padding: 2mm 2.2mm; }
td { padding: 1.9mm 2.2mm; border-bottom: .4pt solid var(--line); vertical-align: top; }
tr:nth-child(even) td { background: #f5f7f9; }
td:first-child { font-weight: 600; }
table.teal th { background: var(--teal); } table.red th { background: #a3283a; } table.green th { background: #2e6b3c; }
table.amber th { background: #b07214; } table.purple th { background: #5a4a9c; }
tr { break-inside: avoid; }
.box { border-left: 1.1mm solid; padding: 3mm 4mm 1mm; margin: 2mm 0 5mm; break-inside: avoid; }
.box .bt { font: 700 7.4pt 'IBM Plex Sans'; letter-spacing: .05em; text-transform: uppercase; margin-bottom: 1.6mm; }
.box p { text-align: left; }
.box-blue { background: var(--blue-bg); border-color: var(--teal); } .box-blue .bt { color: #135f69; }
.box-green { background: var(--green-bg); border-color: #2e7d42; } .box-green .bt { color: #276b38; }
.box-red { background: var(--red-bg); border-color: #b0283c; } .box-red .bt { color: #a3283a; }
.box-amber { background: var(--amber-bg); border-color: #c07c12; } .box-amber .bt { color: #a5670d; }
.box-grey { background: var(--grey-bg); border-color: var(--navy); } .box-grey .bt { color: var(--navy); }
.box-navy { background: var(--navy2); border-color: var(--teal); color: #dbe5ec; } .box-navy .bt { color: #fff; }
.box-navy code { color: #bfe3e8; }
figure { margin: 2mm 0 5mm; break-inside: avoid; }
figure img { width: 100%; border: .4pt solid var(--line); }
figcaption { font-size: 7.6pt; color: var(--ink2); font-style: italic; margin-top: 1.5mm; }
figcaption b { color: var(--teal); font-style: normal; }
.resid { margin: 2mm 0 2mm; }
.resid .row { display:flex; align-items:center; border: .5pt solid; border-left-width: 1.1mm; border-radius: 1mm; padding: 2.6mm 3.5mm; margin-bottom: 2mm; break-inside: avoid; }
.resid .row .w { flex:1 } .resid .row .h { font: 700 7.4pt 'IBM Plex Sans'; letter-spacing: .03em; }
.resid .row .d { font-size: 7.2pt; color: var(--ink2); margin-top: .8mm; }
.resid .row .loc { font: 600 7.4pt 'IBM Plex Sans'; margin-right: 3mm; white-space: nowrap; }
.resid .row .tag { font: 700 6.8pt 'IBM Plex Sans'; color:#fff; padding: 1.2mm 2.6mm; border-radius: .8mm; white-space: nowrap; }
.resid .in { border-color:#2e7d42; background:#f1f8f2 } .resid .in .h,.resid .in .loc { color:#276b38 } .resid .in .tag { background:#2e7d42 }
.resid .out { border-color:#b0283c; background:#fdf2f3 } .resid .out .h,.resid .out .loc { color:#a3283a } .resid .out .tag { background:#a3283a }
.resid .warn { border-color:#c07c12; background:#fdf6ea } .resid .warn .h,.resid .warn .loc { color:#a5670d } .resid .warn .tag { background:#c07c12 }
.hash { font-family: 'IBM Plex Mono'; font-size: 7.2pt; color: var(--ink2); word-break: break-all; }
.agent { break-before: page; }
.agent h3 { margin-top: 0; }
.sources td:last-child { font-family: 'IBM Plex Mono'; font-size: 7pt; word-break: break-all; }
"""


# ----------------------------------------------------------------------------------------------- generated blocks
def agent_table() -> str:
    from meridian.agents.definitions import DEFAULT_AGENTS
    rows = ["| # | Agent | Model tier | Tools (MCP allow-list) | Limits (turns / tools / s) | Definition SHA-256 |",
            "| --- | --- | --- | --- | --- | --- |"]
    for i, (k, d) in enumerate(DEFAULT_AGENTS.items(), 1):
        rows.append(f"| {i:02d} | **{k.upper()}** | {d.model_tier} | `{'`, `'.join(d.tools)}` | "
                    f"{d.max_turns} / {d.max_tool_calls} / {d.timeout_s} | `{d.fingerprint()[:12]}` |")
    return "\n".join(rows)


AGENT_TEXT = {
    "triage": dict(
        purpose="I read every alert MERIDIAN raises and decide what it actually is, so that a person only spends attention "
                "where attention changes the outcome. My verdict is a recommendation with evidence; policy decides what happens to it.",
        accountable=["A verdict, confidence, severity and evidence for every alert routed to me.",
                     "Saying clearly when I do not know (inconclusive), rather than guessing.",
                     "Evidence a responder can check: query ids and the facts that drove the verdict."],
        not_=["I do not close anything. Policy closes benign alerts only for rule severity <= 2, never on a crown-jewel asset, never when I ran degraded.",
              "I cannot see cases or request containment: the response and cases tools are not in my allow-list.",
              "I am not a detection engineer: I may not change rules."],
        escalate=["Rule severity >= 3 with any suspicious or malicious finding: the case opens for a human.",
                  "Anything in the telemetry that reads like an instruction to me: I treat it as evidence of an attack, never as a task."],
        judged="Analyst agreement on sampled verdicts (target >= 90%), auto-closure precision (weekly sample of 50), "
               "golden-set accuracy (`meridian eval`, gate >= 0.8 on your own labelled alerts)."),
    "investigate": dict(
        purpose="For serious cases I build the timeline, the scope and the most likely root cause, and I propose containment as "
                "separate, individually approvable actions.",
        accountable=["The accuracy of the scope I report: every host and identity I name has evidence behind it.",
                     "Containment requests that are specific, reversible and justified one by one.",
                     "A case record complete enough for a regulator notification without reconstruction."],
        not_=["I never execute anything. `request_containment` creates a pending approval; a different human decides.",
              "I cannot request containment of internal ranges or networks wider than /24 (refused by the validator).",
              "I hold no credential for any target system."],
        escalate=["Crown-jewel assets or privileged identities in scope: severity is raised and the on-call responder is notified.",
                  "Evidence that contradicts itself: I say so in the case note and leave the verdict inconclusive."],
        judged="Responder acceptance rate of proposed actions, rework rate of investigations, time from case open to approval request."),
    "hunt": dict(
        purpose="On an analyst's request I test a hypothesis or sweep indicators across up to 30 days per query and report findings "
                "with the query ids that support them.",
        accountable=["Findings that can be reproduced from the cited queries.", "Stating the coverage of what I searched, including what I could not."],
        not_=["I am read-only: lake and context tools only.", "I do not open cases or request containment; a person does."],
        escalate=["Confirmed malicious activity: I return it as a finding with severity; the analyst opens the case."],
        judged="Proportion of hunts producing actionable findings or new rules; analyst rating of hunt reports."),
    "tune": dict(
        purpose="For one noisy rule I review recent alerts and verdicts and propose keep, tune (with a filter) or disable, with an "
                "estimated noise reduction.",
        accountable=["Proposals that remove benign patterns without hiding attacks.", "An honest expected-reduction estimate."],
        not_=["My proposals are never applied automatically. A detection engineer changes the rule through a pull request and CI."],
        escalate=["A proposal that would suppress a rule with any malicious verdict in the window: I recommend keep and say why."],
        judged="Accepted proposals; alert volume change after merge; no missed detection traced to an accepted proposal."),
}


def agent_appendix() -> str:
    from meridian.agents.definitions import DEFAULT_AGENTS
    out = []
    for i, (k, d) in enumerate(DEFAULT_AGENTS.items(), 1):
        t = AGENT_TEXT[k]
        lim = d.definition()["limits"]
        out.append(f'<div class="agent" markdown="1">\n\n### A.{i} &middot; {k.upper()}\n\n'
                   f'<p class="hash">sha256:{d.fingerprint()}</p>\n\n'
                   f"| Field | Value |\n| --- | --- |\n| Designation | {k.upper()} &mdash; agent {i:02d} |\n"
                   f"| Model tier | {d.model_tier} (`model.{d.model_tier}`) |\n"
                   f"| Tools | `{'`, `'.join(d.tools)}` |\n"
                   f"| Limits | {lim['max_turns']} turns, {lim['max_tool_calls']} tool calls, {lim['max_tokens']} output tokens, "
                   f"{lim['timeout_s']} s wall clock, run budget `agents.run_budget_usd` |\n"
                   f"| Output contract | `{d.output.__name__}` (validated; invalid output never becomes a verdict) |\n"
                   f"| Kill switch | `meridian halt --agent {k}` or `POST /api/agents/{k}/halt` (any responder) |\n\n"
                   f"**Purpose.** {t['purpose']}\n\n**Accountable for**\n\n" + "\n".join(f"- {x}" for x in t["accountable"]) +
                   "\n\n**What I am explicitly not**\n\n" + "\n".join(f"- {x}" for x in t["not_"]) +
                   "\n\n**I stop and escalate when**\n\n" + "\n".join(f"- {x}" for x in t["escalate"]) +
                   f"\n\n**How I am judged.** {t['judged']}\n\n</div>\n")
    return "\n".join(out)


def generated(text: str) -> str:
    from meridian import __version__
    reps = {"{{AGENT_TABLE}}": agent_table, "{{AGENT_APPENDIX}}": agent_appendix,
            "{{VERSION}}": lambda: __version__, "{{DATE}}": lambda: date.today().strftime("%d %B %Y").lstrip("0")}
    for k, fn in reps.items():
        if k in text:
            text = text.replace(k, fn())
    return text


# ----------------------------------------------------------------------------------------------- markdown -> HTML
def preprocess(md: str) -> str:
    lines, out, depth = md.split("\n"), [], 0
    for ln in lines:
        m = re.match(r"^:::box\s+(\w+)\s*(.*)$", ln)
        if m:
            out.append(f'<div class="box box-{m.group(1)}" markdown="1">')
            if m.group(2).strip():
                out.append(f'<div class="bt">{html.escape(m.group(2).strip())}</div>\n')
            depth += 1
            continue
        if ln.strip() == ":::" and depth:
            out.append("\n</div>\n")
            depth -= 1
            continue
        f = re.match(r"^!fig\s+(\S+)\s+(\S+)\s+(.+)$", ln)
        if f:
            src = (DOCS / f.group(1)).resolve().as_uri()
            out.append(f'<figure><img src="{src}"><figcaption><b>Figure {f.group(2)}</b> {html.escape(f.group(3))}</figcaption></figure>')
            continue
        tc = re.match(r"^\{:\s*\.(\w+)\s*\}$", ln)
        if tc:                                     # table class marker on the line before a table
            out.append(f'<!--tableclass:{tc.group(1)}-->')
            continue
        out.append(ln)
    return "\n".join(out)


def to_html(md: str) -> tuple[str, list[tuple[str, str]]]:
    body = markdown.markdown(preprocess(md), extensions=["tables", "fenced_code", "md_in_html", "attr_list", "sane_lists"])
    body = re.sub(r"<!--tableclass:(\w+)-->\s*<table>", r'<table class="\1">', body)
    heads: list[tuple[str, str]] = []
    first = [True]

    def h2(m):
        txt = m.group(1)
        num = re.match(r"^([0-9A-Z]{1,2})\s+(.*)$", txt)
        hid = f"s{len(heads) + 1}"
        heads.append((hid, re.sub("<[^>]+>", "", txt)))
        cls = ' class="first"' if first[0] else ""
        first[0] = False
        inner = f'<span class="num">{num.group(1)}</span>{num.group(2)}' if num else txt
        return f'<h2 id="{hid}"{cls}>{inner}</h2>'
    body = re.sub(r"<h2>(.*?)</h2>", h2, body)
    return body, heads


def _css_str(t: str) -> str:
    return "".join(f"\\{ord(ch):x} " if ord(ch) > 126 or ch in '"\\' else ch for ch in t)


def page_html(meta: dict, body: str, heads: list[tuple[str, str]], pages: dict[str, int] | None) -> str:
    toc = "".join(f'<a href="#{hid}"><span class="t">{html.escape(t)}</span><span class="dots"></span>'
                  f'<span class="p">{(pages or {}).get(hid, "")}</span></a>' for hid, t in heads)
    m = meta
    metas = "".join(f"<div>{html.escape(k)}<b>{html.escape(str(v))}</b></div>" for k, v in m["cover_meta"].items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(m['title'])}</title>
<style>{CSS.replace('__RUNNING__', _css_str(m['running'])).replace('__FOOTER__', _css_str(m['footer']))}</style></head><body>
<div class="cover"><div class="bar"></div><div class="ticks"></div><div class="rings"></div>
<div class="kicker">{html.escape(m['kicker'])}</div><h1>{html.escape(m['cover_title'])}</h1><div class="rule"></div>
<div class="sub">{html.escape(m['subtitle'])}</div><div class="summary">{html.escape(m['summary'])}</div>
<div class="meta">{metas}</div></div>
<div class="toc"><h1 class="toc-title">Contents</h1>{toc}</div>
{body}</body></html>"""


async def render(html_path: Path, pdf_path: Path) -> None:
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page()
        await pg.goto(html_path.as_uri(), wait_until="networkidle")
        await pg.pdf(path=str(pdf_path), prefer_css_page_size=True, print_background=True)
        await b.close()


def heading_pages(pdf_path: Path, heads: list[tuple[str, str]]) -> dict[str, int]:
    import pdfplumber
    found: dict[str, int] = {}
    with pdfplumber.open(str(pdf_path)) as pdf:
        texts = [(i + 1, (pg.extract_text() or "")) for i, pg in enumerate(pdf.pages)]
    norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()  # noqa: E731
    start = 3                                         # after cover and contents
    for hid, title in heads:
        key = norm(title)[:40]
        for n, txt in texts:
            if n < start:
                continue
            if any(norm(ln).startswith(key[:30]) for ln in txt.split("\n")):
                found[hid] = n
                start = n
                break
    return found


def build(doc_id: str) -> Path:
    src = SOURCES[doc_id]
    raw = src.read_text(encoding="utf-8")
    _, fm, md = raw.split("---", 2)
    meta = yaml.safe_load(fm)
    meta.setdefault("title", meta["cover_title"])
    meta["footer"] = generated(meta["footer"])
    meta["cover_meta"] = {k: generated(str(v)) for k, v in meta["cover_meta"].items()}
    body, heads = to_html(generated(md))
    OUT.mkdir(parents=True, exist_ok=True)
    pdf = OUT / f"{meta['file']}.pdf"
    tmp = OUT / f".{meta['file']}.html"
    tmp.write_text(page_html(meta, body, heads, None), encoding="utf-8")
    asyncio.run(render(tmp, pdf))
    pages = heading_pages(pdf, heads)
    tmp.write_text(page_html(meta, body, heads, pages), encoding="utf-8")
    asyncio.run(render(tmp, pdf))
    tmp.unlink()
    missing = [t for h, t in heads if h not in pages]
    print(f"wrote {pdf.relative_to(ROOT)}  ({len(heads)} sections" + (f"; no page found for {missing}" if missing else "") + ")")
    return pdf


if __name__ == "__main__":
    for d in (sys.argv[1:] or list(SOURCES)):
        build(d)
