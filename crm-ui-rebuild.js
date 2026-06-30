import fs from "fs";

const target = "server.js";

try {
  if (!fs.existsSync(target)) {
    console.warn("[crm-ui-rebuild] server.js not found; skipping legacy rebuild.");
    process.exit(0);
  }

  // This legacy rebuild script is intentionally disabled.
  // The active CRM/dashboard interface is now produced by the newer patch chain:
  // crm-simple-record-tabs-patch.js, dashboard-menu-rebuild.js, dashboard-color-theme.js,
  // crm-titlebar-ai-add-patch.js, and the CRM workflow patches.
  // Keeping this file as a safe no-op prevents old generated UI code from breaking startup.
  console.log("Legacy CRM UI rebuild skipped; newer CRM UI patches are active.");
} catch (error) {
  console.warn("[crm-ui-rebuild] skipped after non-fatal error:", error && error.message ? error.message : error);
}
