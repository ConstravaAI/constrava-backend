import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

// crm-real-upgrade.js builds code with a template string. Without this cleanup,
// the generated server can contain join("<actual newline>") which is invalid JS.
const before = text;
text = text.replace(/\.filter\(Boolean\)\.join\("\r?\n"\)/g, '.filter(Boolean).join("\\n")');

if (text !== before) {
  fs.writeFileSync(target, text);
  console.log("Fixed CRM generated newline string syntax.");
} else {
  console.log("CRM newline syntax already clean.");
}
