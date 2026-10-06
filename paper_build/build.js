// Builds the revised manuscript (clean and highlighted) from manuscript_*.md + values.json.
// Usage: node build.js <out_clean.docx> <out_highlighted.docx>
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, WidthType, AlignmentType,
  ShadingType, BorderStyle, LevelFormat, HeadingLevel, LineNumberRestartFormat, PageNumber, Footer,
} = require("docx");

const V = JSON.parse(fs.readFileSync("values.json", "utf8"));
const parts = fs.readdirSync(".").filter(f => /^manuscript_part\d+\.md$/.test(f)).sort();
let src = parts.map(f => fs.readFileSync(f, "utf8")).join("\n\n");

// ---------- values ----------
const missing = new Set();
src = src.replace(/\{\{(\w+)\}\}/g, (_, k) => {
  if (!(k in V.vals)) { missing.add(k); return `[[MISSING ${k}]]`; }
  return String(V.vals[k]);
});
if (missing.size) { console.error("Missing values:", [...missing].join(", ")); process.exit(1); }

// ---------- citations, numbered by first appearance ----------
const order = [];
src = src.replace(/\{@([\w,]+)\}/g, (_, keys) => {
  const nums = keys.split(",").map(k => {
    if (!(k in V.refs)) { console.error("Unknown reference", k); process.exit(1); }
    if (!order.includes(k)) order.push(k);
    return order.indexOf(k) + 1;
  }).sort((a, b) => a - b);
  return "(" + nums.join(", ") + ")";
});
const unused = Object.keys(V.refs).filter(k => !order.includes(k));
if (unused.length) console.warn("Unused references (omitted):", unused.join(", "));

const FONT = "Times New Roman";
const TEXT_W = 9026;

function runs(text, hl, base = {}) {
  // **bold**, *italic*
  const out = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*)/g;
  let last = 0, m;
  const push = (t, extra) => { if (t) out.push(new TextRun({ text: t, font: FONT, ...base, ...extra, ...(hl ? { highlight: "yellow" } : {}) })); };
  while ((m = re.exec(text))) {
    push(text.slice(last, m.index), {});
    if (m[0].startsWith("**")) push(m[0].slice(2, -2), { bold: true });
    else push(m[0].slice(1, -1), { italics: true });
    last = m.index + m[0].length;
  }
  push(text.slice(last), {});
  return out;
}

function pngSize(file) {
  const b = fs.readFileSync(file);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

function build(highlight) {
  const children = [];
  let fig = 0, tab = 0;
  const blocks = src.split(/\n\s*\n/).map(b => b.trim()).filter(Boolean);
  const P = (opts) => children.push(new Paragraph({ spacing: { after: 120, line: 300 }, ...opts }));
  for (let b of blocks) {
    let hl = highlight;
    if (b.startsWith("<<old>>")) { hl = false; b = b.slice(7).trim(); }
    if (b.startsWith("!title ")) {
      P({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: runs(b.slice(7), hl, { bold: true, size: 32 }) });
    } else if (b === "!authors") {
      for (const line of V.authors) P({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: runs(line, false, { size: 22 }) });
      P({ children: [] });
    } else if (b.startsWith("!keywords ")) {
      P({ children: runs(b.slice(10), hl, { size: 22 }) });
    } else if (b.startsWith("# ")) {
      P({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: runs(b.slice(2).toUpperCase(), hl && !V.unchangedHeadings.includes(b.slice(2)), { bold: true, size: 24 }) });
    } else if (b.startsWith("## ")) {
      P({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 100 }, children: runs(b.slice(3), hl, { bold: true, size: 24 }) });
    } else if (b.startsWith("### ")) {
      P({ heading: HeadingLevel.HEADING_3, spacing: { before: 160, after: 80 }, children: runs(b.slice(4), hl, { bold: true, italics: true, size: 24 }) });
    } else if (b.startsWith("!eq ")) {
      P({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 120 }, children: runs(b.slice(4), hl, { size: 22, italics: false }) });
    } else if (b.startsWith("!figure ")) {
      const [file, cap, wspec] = b.slice(8).split("|").map(s => s.trim());
      const fp = path.join("figures", file);
      const { w, h } = pngSize(fp);
      const wPx = wspec ? parseInt(wspec) : 600, hPx = Math.round(wPx * h / w);
      fig += 1;
      children.push(new Paragraph({ alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 60 }, children: [new ImageRun({ type: "png", data: fs.readFileSync(fp), transformation: { width: wPx, height: hPx }, altText: { title: `Figure ${fig}`, description: cap, name: file } })] }));
      P({ spacing: { after: 240 }, children: [...runs(`Figure ${fig}. `, hl, { bold: true, size: 20 }), ...runs(cap, hl, { size: 20 })] });
    } else if (b.startsWith("!table ")) {
      const t = V.tables[b.slice(7).trim()];
      if (!t) { console.error("Unknown table", b); process.exit(1); }
      tab += 1;
      P({ keepNext: true, spacing: { before: 120, after: 80 }, children: [...runs(`Table ${tab}. `, hl, { bold: true, size: 20 }), ...runs(t.caption, hl, { size: 20 })] });
      const tot = t.widths.reduce((a, c) => a + c, 0);
      const cw = t.widths.map(x => Math.floor(TEXT_W * x / tot));
      cw[cw.length - 1] += TEXT_W - cw.reduce((a, c) => a + c, 0);
      const border = { style: BorderStyle.SINGLE, size: 4, color: "808080" };
      const borders = { top: border, bottom: border, left: border, right: border };
      const mkRow = (cells, header) => new TableRow({
        tableHeader: header, cantSplit: true,
        children: cells.map((c, i) => new TableCell({
          width: { size: cw[i], type: WidthType.DXA }, borders,
          shading: header ? { type: ShadingType.CLEAR, fill: "E7ECF2", color: "auto" } : undefined,
          margins: { top: 40, bottom: 40, left: 80, right: 80 },
          children: String(c).split("\n").map(line => new Paragraph({ spacing: { after: 0 }, children: runs(line, hl, { size: 18, bold: header }) })),
        })),
      });
      children.push(new Table({ width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: cw,
        rows: [mkRow(t.header, true), ...t.rows.map(r => mkRow(r, false))] }));
      P({ spacing: { after: 240 }, children: t.note ? runs(t.note, hl, { size: 18, italics: true }) : [] });
    } else if (b.split("\n").every(l => l.startsWith("- "))) {
      for (const l of b.split("\n")) P({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 80, line: 300 }, children: runs(l.slice(2), hl, { size: 24 }) });
    } else if (b === "!references") {
      order.forEach((k, i) => P({ indent: { left: 567, hanging: 567 }, spacing: { after: 80 },
        children: runs(`${i + 1}. ${V.refs[k]}`, hl && !V.unchangedRefs.includes(k), { size: 20 }) }));
    } else {
      // a block may contain "- " lines after a lead sentence
      const lines = b.split("\n");
      if (lines.length > 1 && lines.slice(1).every(l => l.startsWith("- "))) {
        P({ children: runs(lines[0], hl, { size: 24 }) });
        for (const l of lines.slice(1)) P({ numbering: { reference: "bullets", level: 0 }, children: runs(l.slice(2), hl, { size: 24 }) });
      } else {
        P({ children: runs(b.replace(/\n/g, " "), hl, { size: 24 }) });
      }
    }
  }
  return new Document({
    creator: "Sharad Pratap Singh, Hanumat Sastry G",
    title: "Poisoning-Resistant Signature Sharing for Hybrid Intrusion Detection",
    styles: { default: { document: { run: { font: FONT, size: 24 } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 24, bold: true, color: "000000" }, paragraph: { outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 24, bold: true, color: "000000" }, paragraph: { outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 24, bold: true, italics: true, color: "000000" }, paragraph: { outlineLevel: 2 } },
      ] },
    numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 567, hanging: 283 } } } }] }] },
    sections: [{
      properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } },
        lineNumbers: { countBy: 1, restart: LineNumberRestartFormat.CONTINUOUS } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }) },
      children,
    }],
  });
}

(async () => {
  const [outClean, outHl] = process.argv.slice(2);
  fs.writeFileSync(outClean, await Packer.toBuffer(build(false)));
  fs.writeFileSync(outHl, await Packer.toBuffer(build(true)));
  fs.writeFileSync("citation_order.json", JSON.stringify(order, null, 1));
  console.log("built", outClean, outHl, "refs:", order.length);
})();
