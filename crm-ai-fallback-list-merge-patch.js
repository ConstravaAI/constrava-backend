import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-fallback-list-merge-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldBlock = `async function getUnifiedCrmLeadList(siteId, token) {
  const rawStored = await getCrmLeads(siteId);
  const storedLeads = (rawStored || []).map((lead, i) => mapLead(lead, i));
  return uniqueCrmLeads(storedLeads).sort(sortCrmLeadsNewestFirst);
}`;

const newBlock = `async function getUnifiedCrmLeadList(siteId, token) {
  const rawStored = await getCrmLeads(siteId);
  const aiFallback = Array.isArray(globalThis.__crmAiEntryFallbackLeads)
    ? globalThis.__crmAiEntryFallbackLeads.filter((lead) => String(lead.site_id || lead.site_slug || lead.dashboard_token || "") === String(siteId) || String(lead.dashboard_token || "") === String(token))
    : [];
  const memoryStored = (typeof memoryLeads !== "undefined" && Array.isArray(memoryLeads))
    ? memoryLeads.filter((lead) => String(lead.site_id || lead.site_slug || lead.dashboard_token || "") === String(siteId) || String(lead.dashboard_token || "") === String(token))
    : [];
  const mergedRaw = [...aiFallback, ...memoryStored, ...(rawStored || [])];
  const storedLeads = mergedRaw.map((lead, i) => mapLead(lead, i));
  return uniqueCrmLeads(storedLeads).sort(sortCrmLeadsNewestFirst);
}`;

if (source.includes(oldBlock)) {
  source = source.replace(oldBlock, newBlock);
  changed = true;
} else if (!source.includes("__crmAiFallbackListMerge_v1")) {
  console.warn("[crm-ai-fallback-list-merge-patch] getUnifiedCrmLeadList exact anchor not found.");
}

if (changed && !source.includes("__crmAiFallbackListMerge_v1")) {
  source = source.replace("// __crmUnifiedLeadListPatch_v2", "// __crmUnifiedLeadListPatch_v2\n// __crmAiFallbackListMerge_v1");
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("AI-created fallback leads are now merged into the unified CRM list.");
} else {
  console.log("AI fallback lead merge patch already applied or no anchor found.");
}
