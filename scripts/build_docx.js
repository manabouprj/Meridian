// Build the Word editions of the design documents from the repository markdown (single source of truth).
//   NODE_PATH=$(npm root -g) node scripts/build_docx.js        (requires the `docx` npm package)
// Output: dist/docs/MERIDIAN-HLD.docx, MERIDIAN-LLD-Azure.docx, MERIDIAN-LLD-AWS.docx
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, ShadingType,
  ImageRun, AlignmentType, LevelFormat, PageBreak, Header, Footer, PageNumber, TableOfContents, BorderStyle,
  ExternalHyperlink,
} = require("docx");

const ROOT = path.resolve(__dirname, "..");
const DOCS = path.join(ROOT, "docs");
const OUT = path.join(ROOT, "dist", "docs");
const VERSION = "1.0.1";
const DATE = new Date().toISOString().slice(0, 10);

// A4 with 2 cm margins
const PAGE = { width: 11906, height: 16838 };
const MARGIN = 1134;
const CONTENT = PAGE.width - 2 * MARGIN;           // 9638 DXA
const CONTENT_PX = Math.round(CONTENT / 1440 * 96); // ~642 px at 96 dpi

const C = { ink: "1F2328", muted: "59636E", accent: "0969DA", line: "D0D7DE", head: "EAF1FB", code: "F6F8FA" };
const FONT = "Calibri";
const MONO = "Consolas";

// ------------------------------------------------------------------ inline markdown -> runs
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|(?<![\w*])\*[^*\s][^*]*?\*(?![\w*]))/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(new TextRun({ text: t.slice(2, -2), bold: true, ...base }));
    else if (t.startsWith("`")) out.push(new TextRun({ text: t.slice(1, -1), font: MONO, size: 19, ...base }));
    else if (t.startsWith("*")) out.push(new TextRun({ text: t.slice(1, -1), italics: true, ...base }));
    else {
      const [, label, url] = t.match(/\[([^\]]+)\]\(([^)]+)\)/);
      if (/^https?:/.test(url)) {
        out.push(new ExternalHyperlink({ link: url, children: [new TextRun({ text: label, style: "Hyperlink", ...base })] }));
      } else {
        out.push(new TextRun({ text: label, ...base }));       // repo-relative link: keep the text
      }
    }
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), ...base }));
  return out;
}

// ------------------------------------------------------------------ tables
function plain(s) { return s.replace(/\*\*|`/g, "").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1"); }

function table(rows) {
  const cells = rows.map(r => r.replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map(c => c.trim().replace(/\\\|/g, "|")));
  const header = cells[0];
  const body = cells.slice(2);
  const n = header.length;
  // Column widths: every column first gets room for its longest word (no mid-word breaks), then the rest of the
  // page width is shared in proportion to how much text each column holds. Sums exactly to CONTENT.
  const CHAR = 105;                                            // ~DXA per character at 9 pt
  const words = c => plain(c).split(/\s+/).reduce((m, w) => Math.max(m, w.length), 0);
  const minW = header.map((h, i) => Math.min(Math.max(words(h), ...body.map(r => words(r[i] || ""))), 28) * CHAR + 220);
  const text = header.map((h, i) => plain(h).length + body.reduce((s, r) => s + Math.min(plain(r[i] || "").length, 120), 0));
  let widths = minW.slice();
  const spare = CONTENT - widths.reduce((a, b) => a + b, 0);
  if (spare > 0) {
    const t = text.reduce((a, b) => a + b, 0) || 1;
    widths = widths.map((w, i) => w + Math.floor(spare * text[i] / t));
  } else {                                                     // too many long words: scale down proportionally
    const t = widths.reduce((a, b) => a + b, 0);
    widths = widths.map(w => Math.floor(w * CONTENT / t));
  }
  widths[n - 1] += CONTENT - widths.reduce((a, b) => a + b, 0);
  const border = { style: BorderStyle.SINGLE, size: 4, color: C.line };
  const borders = { top: border, bottom: border, left: border, right: border };
  const mk = (txt, i, head) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    borders,
    shading: head ? { type: ShadingType.CLEAR, color: "auto", fill: C.head } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: [new Paragraph({ spacing: { before: 0, after: 0 }, children: runs(txt || "", { size: 18, bold: head || undefined }) })],
  });
  return new Table({
    width: { size: CONTENT, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({ tableHeader: true, children: header.map((h, i) => mk(h, i, true)) }),
      ...body.map(r => new TableRow({ children: Array.from({ length: n }, (_, i) => mk(r[i] || "", i, false)) })),
    ],
  });
}

// ------------------------------------------------------------------ images
function pngSize(buf) { return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) }; }

function image(src, alt) {
  let p = path.join(DOCS, src);
  if (p.endsWith(".svg")) p = p.replace(/\.svg$/, ".png");
  if (!fs.existsSync(p)) return new Paragraph({ children: [new TextRun({ text: `[missing image ${src}]`, italics: true })] });
  const data = fs.readFileSync(p);
  const { w, h } = pngSize(data);
  const width = CONTENT_PX;
  const height = Math.round(h * width / w);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
      children: [new ImageRun({ type: "png", data, transformation: { width, height }, altText: { title: alt, description: alt, name: alt } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
      children: [new TextRun({ text: alt, italics: true, size: 18, color: C.muted })] }),
  ];
}

// ------------------------------------------------------------------ markdown -> blocks
function convert(md, { skipTitle = true, levels = null } = {}) {
  const lines = md.replace(/\r/g, "").split("\n");
  const out = [];
  let i = 0;
  let firstH1 = true;
  let numberedInstance = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    // fenced code
    if (line.startsWith("```")) {
      const code = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) code.push(lines[i++]);
      i++;
      code.forEach((c, k) => out.push(new Paragraph({
        shading: { type: ShadingType.CLEAR, color: "auto", fill: C.code },
        spacing: { before: k === 0 ? 80 : 0, after: k === code.length - 1 ? 160 : 0 },
        indent: { left: 120, right: 120 },
        children: [new TextRun({ text: c || " ", font: MONO, size: 17 })],
      })));
      continue;
    }
    // headings
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      if (level === 1 && firstH1 && skipTitle) { firstH1 = false; i++; continue; }
      firstH1 = false;
      const map = levels || { 1: HeadingLevel.HEADING_1, 2: HeadingLevel.HEADING_1, 3: HeadingLevel.HEADING_2, 4: HeadingLevel.HEADING_3 };
      out.push(new Paragraph({ heading: map[level], children: runs(h[2]) }));
      i++;
      continue;
    }
    // image
    const im = line.match(/^!\[([^\]]*)\]\(([^)]+)\)\s*$/);
    if (im) { out.push(...image(im[2], im[1])); i++; continue; }
    // table
    if (line.trim().startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(lines[i++].trim());
      out.push(table(rows));
      out.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
      continue;
    }
    // lists (bullets and numbers, nested by indentation, with indented continuation paragraphs)
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      numberedInstance++;
      while (i < lines.length) {
        const l = lines[i];
        if (!l.trim()) {
          // continue the list if the next non-blank line is indented or another item
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          if (j < lines.length && (/^\s+\S/.test(lines[j]) || /^\s*([-*]|\d+\.)\s+/.test(lines[j]))) { i = j; continue; }
          break;
        }
        const m = l.match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
        if (m) {
          const depth = Math.min(Math.floor(m[1].length / 2), 3);
          const numbered = /\d+\./.test(m[2]);
          let text = m[3];
          i++;
          while (i < lines.length && lines[i].trim() && !/^\s*([-*]|\d+\.)\s+/.test(lines[i]) && !lines[i].trim().startsWith("|")) {
            text += " " + lines[i].trim(); i++;
          }
          out.push(new Paragraph({
            numbering: numbered ? { reference: "numbers", level: depth, instance: numberedInstance } : { reference: "bullets", level: depth },
            spacing: { after: 60 },
            children: runs(text),
          }));
        } else if (/^\s+\S/.test(l)) {
          // indented continuation paragraph or code inside a list item
          if (l.trim().startsWith("```")) {
            const indent = l.match(/^\s*/)[0].length;
            const code = [];
            i++;
            while (i < lines.length && !lines[i].trim().startsWith("```")) code.push(lines[i++].slice(indent));
            i++;
            code.forEach(c => out.push(new Paragraph({ shading: { type: ShadingType.CLEAR, color: "auto", fill: C.code },
              indent: { left: 720 }, children: [new TextRun({ text: c || " ", font: MONO, size: 17 })] })));
            continue;
          }
          let text = l.trim();
          i++;
          while (i < lines.length && /^\s+\S/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s+/.test(lines[i])) { text += " " + lines[i].trim(); i++; }
          out.push(new Paragraph({ indent: { left: 720 }, spacing: { after: 80 }, children: runs(text) }));
        } else break;
      }
      out.push(new Paragraph({ spacing: { after: 60 }, children: [] }));
      continue;
    }
    // html (README <picture>) - skip
    if (line.trim().startsWith("<")) { i++; continue; }
    // paragraph
    let text = line.trim();
    i++;
    while (i < lines.length && lines[i].trim() && !/^(#|\||!\[|```|\s*([-*]|\d+\.)\s)/.test(lines[i])) { text += " " + lines[i].trim(); i++; }
    out.push(new Paragraph({ spacing: { after: 140 }, children: runs(text) }));
  }
  return out;
}

// ------------------------------------------------------------------ document shell
function titlePage(title, subtitle, cloud) {
  const control = [
    "| Field | Value |", "| --- | --- |",
    `| Product | MERIDIAN ${VERSION} - SIEM-less detection, investigation and response with AI agents over MCP |`,
    `| Document | ${title} |`,
    `| Deployment option | ${cloud} |`,
    `| Version / date | ${VERSION} / ${DATE} |`,
    "| Author | Peter Akinyele |",
    "| Classification | Internal |",
    "| Source | Generated from the repository markdown (docs/) by scripts/build_docx.js |",
  ];
  return [
    new Paragraph({ spacing: { before: 2400 }, children: [new TextRun({ text: "MERIDIAN", bold: true, size: 64, color: C.accent })] }),
    new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text: title, bold: true, size: 40, color: C.ink })] }),
    new Paragraph({ spacing: { after: 600 }, children: [new TextRun({ text: subtitle, size: 26, color: C.muted })] }),
    table(control),
    new Paragraph({ children: [new PageBreak()] }),
    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("Contents")] }),
    new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
    new Paragraph({ children: [new TextRun({ text: "Right-click the table and choose Update Field if page numbers are not shown.", italics: true, size: 16, color: C.muted })] }),
    new Paragraph({ children: [new PageBreak()] }),
  ];
}

function appendix(letter, title, file) {
  const md = fs.readFileSync(path.join(DOCS, file), "utf8");
  return [
    new Paragraph({ children: [new PageBreak()] }),
    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(`Appendix ${letter} - ${title}`)] }),
    ...convert(md.replace(/^#\s.*$/m, "").replace(/^## /gm, "### ").replace(/^### (?!#)/gm, "### ")),
  ];
}

// Chapter mode: each markdown file is one chapter; its H1 becomes Heading 1, H2 -> Heading 2, H3/H4 -> Heading 3
const CHAPTER_LEVELS = { 1: HeadingLevel.HEADING_1, 2: HeadingLevel.HEADING_2, 3: HeadingLevel.HEADING_3, 4: HeadingLevel.HEADING_3 };

function chapters(files) {
  const out = [];
  files.forEach((f, i) => {
    const md = fs.readFileSync(path.join(DOCS, f), "utf8").replace(/^<!--.*-->\s*$/gm, "");
    if (i > 0) out.push(new Paragraph({ children: [new PageBreak()] }));
    out.push(...convert(md, { skipTitle: false, levels: CHAPTER_LEVELS }));
  });
  return out;
}

function build(file, outName, title, subtitle, cloud, appendices) {
  let body;
  if (Array.isArray(file)) {
    body = chapters(file);
  } else {
    const md = fs.readFileSync(path.join(DOCS, file), "utf8");
    // drop the markdown front matter (subtitle + document table): it is on the title page. Keep from the first "## ".
    body = convert(md.slice(md.indexOf("\n## ") + 1));
  }
  const children = [...titlePage(title, subtitle, cloud), ...body];
  appendices.forEach(([l, t, f]) => children.push(...appendix(l, t, f)));
  const doc = new Document({
    creator: "Peter Akinyele", title: `MERIDIAN ${title}`, description: subtitle,
    features: { updateFields: true },
    styles: {
      default: { document: { run: { font: FONT, size: 21, color: C.ink } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 32, bold: true, color: C.accent, font: FONT }, paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 26, bold: true, color: C.ink, font: FONT }, paragraph: { spacing: { before: 280, after: 120 }, outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 22, bold: true, color: C.muted, font: FONT }, paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
      ],
    },
    numbering: {
      config: [
        { reference: "bullets", levels: [0, 1, 2, 3].map(l => ({ level: l, format: LevelFormat.BULLET, text: ["•", "–", "◦", "–"][l],
          alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360 + l * 360, hanging: 260 } } } })) },
        { reference: "numbers", levels: [0, 1, 2, 3].map(l => ({ level: l, format: l === 1 ? LevelFormat.LOWER_LETTER : LevelFormat.DECIMAL,
          text: `%${l + 1}.`, alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360 + l * 360, hanging: 300 } } } })) },
      ],
    },
    sections: [{
      properties: { page: { size: PAGE, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
        children: [new TextRun({ text: `MERIDIAN ${VERSION} - ${title}`, size: 16, color: C.muted })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ children: ["Page ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES], size: 16, color: C.muted })] })] }) },
      children,
    }],
  });
  return Packer.toBuffer(doc).then(buf => {
    fs.mkdirSync(OUT, { recursive: true });
    fs.writeFileSync(path.join(OUT, outName), buf);
    console.log("wrote", path.join("dist/docs", outName), buf.length, "bytes");
  });
}

(async () => {
  await build("EXECUTIVE_REVIEW.md", "MERIDIAN-Executive-Review.docx", "Executive Review",
    "Production readiness, phased implementation, monthly cost per cloud, 3-year TCO and ROI",
    "Both: Azure + Microsoft Foundry, AWS + Amazon Bedrock", []);
  await build(["design/README.md", "design/ARCHITECTURE-DECISIONS.md", "design/COMPONENT-DESIGN.md", "design/DATA-MODEL.md",
               "design/API-REFERENCE.md", "design/CONFIGURATION.md", "design/ENVIRONMENT.md", "design/DETECTION-ENGINEERING.md"],
    "MERIDIAN-Detailed-Design.docx", "Detailed Design",
    "Architecture decisions, component design, data model, API, configuration and detection engineering",
    "Both: Azure + Microsoft Foundry, AWS + Amazon Bedrock", []);
  await build(["deployment/README.md", "deployment/PREREQUISITES.md", "deployment/DEPLOY-LOCAL.md", "deployment/DEPLOY-AZURE.md",
               "deployment/DEPLOY-AWS.md", "deployment/ONBOARD-SOURCES.md", "deployment/GO-LIVE-CHECKLIST.md",
               "deployment/UPGRADE-ROLLBACK.md", "deployment/TROUBLESHOOTING.md"],
    "MERIDIAN-Deployment-Guide.docx", "Deployment Guide",
    "Step-by-step runbooks: prerequisites, local pilot, Azure, AWS, source onboarding, go-live, upgrade and DR, troubleshooting",
    "Both: Azure + Microsoft Foundry, AWS + Amazon Bedrock", []);
  await build("HLD.md", "MERIDIAN-HLD.docx", "High-Level Design",
    "Replacing the SIEM layer with a security data lake, deterministic detection and AI agents over MCP - Azure + Microsoft Foundry and AWS + Amazon Bedrock",
    "Both: Azure + Microsoft Foundry, AWS + Amazon Bedrock",
    [["A", "Security design and controls", "SECURITY.md"], ["B", "Pre-release peer review", "PEER_REVIEW.md"]]);
  await build("LLD-azure.md", "MERIDIAN-LLD-Azure.docx", "Low-Level Design - Azure + Microsoft Foundry",
    "Resources, network, identity, data flows, managed agents, operations and deployment on Microsoft Azure",
    "Microsoft Azure + Microsoft Foundry",
    [["A", "Operations guide and runbook", "OPERATIONS.md"], ["B", "MCP tool reference", "MCP-TOOLS.md"]]);
  await build("LLD-aws.md", "MERIDIAN-LLD-AWS.docx", "Low-Level Design - AWS + Amazon Bedrock",
    "Resources, network, identity, data flows, managed agents, operations and deployment on Amazon Web Services",
    "Amazon Web Services + Amazon Bedrock",
    [["A", "Operations guide and runbook", "OPERATIONS.md"], ["B", "MCP tool reference", "MCP-TOOLS.md"]]);
})();
