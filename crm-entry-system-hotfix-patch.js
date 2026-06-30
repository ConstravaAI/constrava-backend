import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-entry-system-hotfix-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const before = source;

source = source.replace(
  /merged\.notes\s*=\s*existingNotes\s*\+\s*"\s*Update:\s*"\s*\+\s*newNotes;/g,
  'merged.notes = existingNotes + "\\n\\nUpdate: " + newNotes;'
);

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

await import("./crm-ai-entry-normalizer-hotfix-patch.js");
await import("./crm-ai-entry-route-hard-replace-patch.js");
await import("./crm-openai-primary-intake-patch.js");
await import("./crm-plain-text-lead-intake-patch.js");
await import("./crm-ai-entry-save-compat-patch.js");
await import("./crm-layout-cleanup-patch.js");
await import("./crm-distinct-tabs-patch.js");
await import("./crm-distinct-tabs-stabilize-patch.js");
await import("./crm-distinct-tabs-nojump-patch.js");
await import("./crm-topbar-ai-tools-patch.js");
await import("./crm-simple-record-tabs-patch.js");
await import("./crm-hide-legacy-workflow-panels-patch.js");
await import("./crm-workflow-tools-cards-patch.js");
await import("./crm-collapsible-sidebar-groups-patch.js");
await import("./dashboard-menu-rebuild-inject-patch.js");
await import("./crm-titlebar-ai-add-patch.js");
await import("./crm-messy-ai-intake-pipeline-patch.js");
await import("./crm-messy-prompt-syntax-fix-patch.js");
