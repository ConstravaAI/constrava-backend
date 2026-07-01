import fs from "fs";

const file = "crm-distinct-tabs.js";

try {
  if (!fs.existsSync(file)) {
    console.warn("[crm-simple-record-tabs-patch] crm-distinct-tabs.js not found; skipping.");
    process.exit(0);
  }

  // The old generator rebuilt crm-distinct-tabs.js with logic that only trusted
  // the backend entries array. That caused AI-added records to say "saved" but
  // not appear when the backend response was empty or delayed.
  // crm-distinct-tabs.js is now maintained directly and merges backend entries,
  // dashboard records/leads, and session-saved AI records.
  console.log("[crm-simple-record-tabs-patch] skipped; direct reliable crm-distinct-tabs.js is active.");
} catch (error) {
  console.warn("[crm-simple-record-tabs-patch] skipped after non-fatal error:", error && error.message ? error.message : error);
}
