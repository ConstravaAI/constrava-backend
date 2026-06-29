import fs from "fs";

const target = "server.js";
if (!fs.existsSync(target)) {
  console.warn("[crm-syntax-fix] server.js not found; skipping.");
  process.exit(0);
}

let text = fs.readFileSync(target, "utf8");
const before = text;

// crm-real-upgrade.js can generate code like join("<actual newline>"),
// which is invalid JavaScript. Replace actual line-break join strings with "\\n".
text = text.replace(/\.filter\(Boolean\)\.join\("[\r\n]+"\)/g, '.filter(Boolean).join("\\n")');

if (text !== before) {
  fs.writeFileSync(target, text);
  console.log("Fixed CRM generated newline string syntax.");
} else {
  console.log("CRM newline syntax already clean.");
}
