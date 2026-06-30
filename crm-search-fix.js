import fs from "fs";

const target = "server.js";

try {
  if (!fs.existsSync(target)) {
    console.warn("[crm-search-fix] server.js not found; skipping legacy search fix.");
    process.exit(0);
  }

  // This legacy generated search patch is intentionally disabled.
  // The newer CRM pipeline now handles unified entries, multi-type records,
  // matching tabs, and AI/plain-text intake. Keeping this file as a safe no-op
  // prevents old regex patch code from breaking startup on Node 26.
  console.log("Legacy CRM search fix skipped; newer CRM search/intake pipeline is active.");
} catch (error) {
  console.warn("[crm-search-fix] skipped after non-fatal error:", error && error.message ? error.message : error);
}
