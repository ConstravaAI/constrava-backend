import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-messy-regex-syntax-fix-patch] server.js not found.");
  process.exit(0);
}

function replaceFunction(source, name, replacement) {
  const start = source.indexOf(name);
  if (start === -1) return { source, changed: false };
  const braceStart = source.indexOf("{", start);
  if (braceStart === -1) return { source, changed: false };
  let depth = 0;
  let end = -1;
  let inString = false;
  let stringChar = "";
  let escaped = false;
  let inTemplate = false;
  for (let i = braceStart; i < source.length; i++) {
    const ch = source[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (inString) { if (ch === stringChar) inString = false; continue; }
    if (inTemplate) { if (ch === "`") inTemplate = false; continue; }
    if (ch === "\"" || ch === "'") { inString = true; stringChar = ch; continue; }
    if (ch === "`") { inTemplate = true; continue; }
    if (ch === "{") depth++;
    if (ch === "}") {
      depth--;
      if (depth === 0) { end = i + 1; break; }
    }
  }
  if (end === -1) return { source, changed: false };
  const current = source.slice(start, end);
  if (current === replacement) return { source, changed: false };
  return { source: source.slice(0, start) + replacement + source.slice(end), changed: true };
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const safePhone = `function cxCrmAiExtractPhone(text) {
  const value = cxCrmAiClean(text);
  const phoneRe = new RegExp('(?:\\\\+?1[\\\\s.-]?)?(?:\\\\(?\\\\d{3}\\\\)?[\\\\s.-]?)\\\\d{3}[\\\\s.-]?\\\\d{4}');
  const m = value.match(phoneRe);
  return m ? m[0].trim() : "";
}`;

let result = replaceFunction(source, "function cxCrmAiExtractPhone", safePhone);
if (result.changed) { source = result.source; changed = true; }

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Messy CRM regex syntax repaired.");
} else {
  console.log("Messy CRM regex syntax already safe or anchor not found.");
}
