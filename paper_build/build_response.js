// Builds the response-to-reviewers letter from response.md + values.json.
const fs = require("fs");
const { Document, Packer, Paragraph, TextRun, AlignmentType, LevelFormat, BorderStyle, ShadingType } = require("docx");
const V = JSON.parse(fs.readFileSync("values.json", "utf8"));
let src = fs.readFileSync("response.md", "utf8");
const missing = [];
src = src.replace(/\{\{(\w+)\}\}/g, (_, k) => (k in V.vals ? String(V.vals[k]) : (missing.push(k), `[[MISSING ${k}]]`)));
if (missing.length) { console.error("Missing:", missing.join(", ")); process.exit(1); }
const FONT = "Times New Roman";
function runs(text, base = {}) {
  const out = []; const re = /(\*\*[^*]+\*\*|\*[^*]+\*)/g; let last = 0, m;
  const push = (t, x) => t && out.push(new TextRun({ text: t, font: FONT, size: 22, ...base, ...x }));
  while ((m = re.exec(text))) {
    push(text.slice(last, m.index), {});
    m[0].startsWith("**") ? push(m[0].slice(2, -2), { bold: true }) : push(m[0].slice(1, -1), { italics: true });
    last = m.index + m[0].length;
  }
  push(text.slice(last), {}); return out;
}
const ch = [];
const P = (o) => ch.push(new Paragraph({ spacing: { after: 120, line: 288 }, ...o }));
for (let b of src.split(/\n\s*\n/).map(x => x.trim()).filter(Boolean)) {
  if (b.startsWith("!title ")) P({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: runs(b.slice(7), { bold: true, size: 30 }) });
  else if (b.startsWith("!para ")) P({ spacing: { after: 40 }, children: runs(b.slice(6)) });
  else if (b.startsWith("# ")) P({ spacing: { before: 300, after: 160 }, children: runs(b.slice(2), { bold: true, size: 26 }) });
  else if (b.startsWith("!comment ")) {
    const sp = b.indexOf(" ", 9); const id = b.slice(9, sp); const txt = b.slice(sp + 1);
    P({ spacing: { before: 200, after: 100 }, shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
        border: { left: { style: BorderStyle.SINGLE, size: 12, color: "808080", space: 6 } },
        children: [...runs(`Comment ${id}. `, { bold: true }), ...runs(txt, { italics: true })] });
  } else if (b.split("\n").every(l => l.startsWith("- "))) {
    for (const l of b.split("\n")) P({ numbering: { reference: "b", level: 0 }, children: runs(l.slice(2)) });
  } else P({ children: runs(b.replace(/\n/g, " ")) });
}
const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: 22 } } } },
  numbering: { config: [{ reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 567, hanging: 283 } } } }] }] },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } }, children: ch }],
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync(process.argv[2], b); console.log("built", process.argv[2]); });
