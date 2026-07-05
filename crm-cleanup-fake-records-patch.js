import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-cleanup-fake-records-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const marker = "// __crmCleanupFakeRecords_v2";
const oldMarkers = ["// __crmCleanupFakeRecords_v1", "// __crmCleanupFakeRecords_v2"];
for (const oldMarker of oldMarkers) {
  const oldStart = source.indexOf(oldMarker);
  const oldEnd = oldStart >= 0 ? source.indexOf('app.all("/api/openai/diagnostic"', oldStart) : -1;
  if (oldStart >= 0 && oldEnd > oldStart) {
    source = source.slice(0, oldStart) + source.slice(oldEnd);
    changed = true;
  }
}

const route = [
  marker,
  'function crmCleanupFakeText(value) {',
  '  return String(value || "").toLowerCase();',
  '}',
  'function crmCleanupFakeRecordPredicate(record) {',
  '  const r = record || {};',
  '  const hay = [',
  '    r.name, r.full_name, r.lead_name, r.contact_name, r.company, r.organization,',
  '    r.account_name, r.deal_name, r.next_step, r.notes, r.message, r.body,',
  '    r.reason, r.source, r.provider, r.record_type, r.type, r.module,',
  '    Array.isArray(r.tags) ? r.tags.join(" ") : r.tags,',
  '    JSON.stringify(r.raw_submission || {}),',
  '    JSON.stringify(r.normalization || {})',
  '  ].map(crmCleanupFakeText).join(" | ");',
  '  const knownExample = /\\b(chris evans|acme roofing|green valley gym)\\b/i.test(hay) || /\\bsarah at acme roofing\\b/i.test(hay) || /\\bmike from green valley gym\\b/i.test(hay);',
  '  const ourGeneratedMarker = /person extracted from ai add text|task extracted from ai add text|hard semantic guard|semantic-extract|constravacrm demo adds|fake-record|test record/i.test(hay);',
  '  const oldExampleText = /chris evans wants me to call him at 9pm|wants a \\$?5000 website quote|new app project worth 12000/i.test(hay);',
  '  return Boolean(knownExample || ourGeneratedMarker || oldExampleText);',
  '}',
  'function crmCleanupRecordId(record) {',
  '  const r = record || {};',
  '  return String(r.lead_id || r.record_id || r.crm_id || r.id || "").trim();',
  '}',
  'async function crmCleanupDeleteFromDb(siteId, records) {',
  '  if (typeof hasDb !== "function" || !hasDb()) return { dbDeleted: 0, dbSkipped: "No database connection." };',
  '  const ids = Array.from(new Set((records || []).map(crmCleanupRecordId).filter(Boolean)));',
  '  if (!ids.length) return { dbDeleted: 0, dbSkipped: "No ids to delete." };',
  '  try {',
  '    const info = await tableInfo("crm_leads");',
  '    const c = cols(info);',
  '    const idCol = firstExisting(c, ["lead_id", "record_id", "crm_id", "id"]);',
  '    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id", "site_slug"]);',
  '    if (!idCol) return { dbDeleted: 0, dbSkipped: "No CRM id column found." };',
  '    const params = [ids];',
  '    let sql = "DELETE FROM crm_leads WHERE " + q(idCol) + " = ANY($1::text[])";',
  '    if (siteCol) { sql += " AND " + q(siteCol) + "=$2"; params.push(String(siteId)); }',
  '    const result = await db().query(sql, params);',
  '    return { dbDeleted: result.rowCount || 0 };',
  '  } catch (error) {',
  '    return { dbDeleted: 0, dbError: error && error.message ? error.message : String(error) };',
  '  }',
  '}',
  'function crmCleanupMemoryRecords() {',
  '  let removed = 0;',
  '  try {',
  '    if (typeof memoryLeads !== "undefined" && Array.isArray(memoryLeads)) {',
  '      for (let i = memoryLeads.length - 1; i >= 0; i--) {',
  '        if (crmCleanupFakeRecordPredicate(memoryLeads[i])) { memoryLeads.splice(i, 1); removed++; }',
  '      }',
  '    }',
  '  } catch {}',
  '  return removed;',
  '}',
  'app.all("/api/crm/cleanup-fake-records", async (req, res) => {',
  '  try {',
  '    const privateToken = "9f57ffbe-eba8-46ad-9573-c867aa4d1e66";',
  '    const token = String(req.query.token || req.body?.token || "").trim();',
  '    if (token !== privateToken) return res.status(403).json({ ok: false, error: "Invalid cleanup token." });',
  '    const site = await findSiteByToken(token);',
  '    const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token || "demo"));',
  '    const current = await getUnifiedCrmLeadList(siteId, token);',
  '    const matched = (current || []).filter(crmCleanupFakeRecordPredicate);',
  '    const memoryDeleted = crmCleanupMemoryRecords();',
  '    const dbResult = await crmCleanupDeleteFromDb(siteId, matched);',
  '    const refreshed = await getUnifiedCrmLeadList(siteId, token).catch(() => []);',
  '    res.json({ ok: true, matched: matched.length, matched_ids: matched.map(crmCleanupRecordId).filter(Boolean).slice(0, 100), memoryDeleted, ...dbResult, remaining: Array.isArray(refreshed) ? refreshed.length : null, message: "Removed obvious AI/test/fake CRM records only. Browser session demo records are also cleared by the dashboard on refresh." });',
  '  } catch (error) {',
  '    res.status(500).json({ ok: false, error: error && error.message ? error.message : "Cleanup failed." });',
  '  }',
  '});'
].join("\n");

if (!source.includes(marker)) {
  const anchor = 'app.all("/api/openai/diagnostic"';
  const fallbackAnchor = 'app.get("/api/crm/entries"';
  const insertAt = source.indexOf(anchor) >= 0 ? source.indexOf(anchor) : source.indexOf(fallbackAnchor);
  if (insertAt >= 0) {
    source = source.slice(0, insertAt) + route + "\n" + source.slice(insertAt);
    changed = true;
  } else {
    console.warn("[crm-cleanup-fake-records-patch] Could not find route anchor; skipping.");
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[crm-cleanup-fake-records-patch] Added fixed private fake CRM record cleanup endpoint.");
} else {
  console.log("[crm-cleanup-fake-records-patch] Cleanup endpoint already present or no changes needed.");
}
