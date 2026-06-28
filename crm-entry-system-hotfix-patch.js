import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-entry-system-hotfix-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const before = source;

// Repair a bad generated string literal where a real newline was written inside quotes.
source = source.replace(
  /merged\.notes\s*=\s*existingNotes\s*\+\s*"\s*Update:\s*"\s*\+\s*newNotes;/g,
  'merged.notes = existingNotes + "\\n\\nUpdate: " + newNotes;'
);

// Also repair the exact two-line form if spacing differs.
source = source.replace(
  'merged.notes = existingNotes + "\n\nUpdate: " + newNotes;',
  'merged.notes = existingNotes + "\\n\\nUpdate: " + newNotes;'
);

if (source !== before) {
  fs.writeFileSync(file, source);
  console.log("CRM entry system newline syntax repaired.");
} else {
  console.log("CRM entry system newline syntax already valid.");
}

await import("./crm-layout-cleanup-patch.js");
