import fs from "fs";

const files = ["server.js", "crm-multi-type-data-points-patch.js"];
let changedAny = false;

for (const file of files) {
  if (!fs.existsSync(file)) continue;
  let source = fs.readFileSync(file, "utf8");
  const before = source;

  source = source.replaceAll('follow-ups:"task"', '"follow-ups":"task"');
  source = source.replaceAll('crm-entry:"entry"', '"crm-entry":"entry"');
  source = source.replaceAll('follow-ups: "task"', '"follow-ups": "task"');
  source = source.replaceAll('crm-entry: "entry"', '"crm-entry": "entry"');

  if (source !== before) {
    fs.writeFileSync(file, source);
    console.log(`[crm-multi-type-syntax-fix-patch] Fixed dashed alias keys in ${file}.`);
    changedAny = true;
  }
}

if (!changedAny) {
  console.log("[crm-multi-type-syntax-fix-patch] Dashed alias keys already valid.");
}
