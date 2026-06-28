import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-entry-save-compat-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const helper = `async function saveCrmEntryCompat(siteId, token, entry) {
  if (typeof insertCrmLead === "function") return await insertCrmLead(siteId, entry);
  if (typeof insertCRMLead === "function") return await insertCRMLead(siteId, entry);
  if (typeof insertLead === "function") return await insertLead(siteId, entry);
  if (typeof addCrmLead === "function") return await addCrmLead(siteId, entry);
  if (typeof createCrmLead === "function") return await createCrmLead(siteId, entry);
  const saved = { ...entry, site_id: siteId, dashboard_token: token, created_at: entry.created_at || new Date().toISOString() };
  if (typeof memoryLeads !== "undefined" && Array.isArray(memoryLeads)) {
    memoryLeads.unshift(saved);
    return saved;
  }
  globalThis.__crmAiEntryFallbackLeads = globalThis.__crmAiEntryFallbackLeads || [];
  globalThis.__crmAiEntryFallbackLeads.unshift(saved);
  return saved;
}
`;

if (!source.includes("async function saveCrmEntryCompat")) {
  const anchor = "async function handleCrmAiEntry";
  if (source.includes(anchor)) {
    source = source.replace(anchor, helper + anchor);
    changed = true;
  } else {
    console.warn("[crm-ai-entry-save-compat-patch] handleCrmAiEntry anchor not found.");
  }
}

const beforeReplace = source;
source = source.replace(/await\s+insertCrmLead\(siteId,\s*finalEntry\);/g, "await saveCrmEntryCompat(siteId, token, finalEntry);");
source = source.replace(/await\s+insertCRMLead\(siteId,\s*finalEntry\);/g, "await saveCrmEntryCompat(siteId, token, finalEntry);");
if (source !== beforeReplace) changed = true;

if (changed) {
  fs.writeFileSync(file, source);
  console.log("AI CRM entry save compatibility patch applied.");
} else {
  console.log("AI CRM entry save compatibility patch already applied or no anchor found.");
}

await import("./crm-ai-fallback-list-merge-patch.js");
await import("./crm-entry-type-field-patch.js");
await import("./crm-distinct-tabs-resilient-loader-patch.js");
