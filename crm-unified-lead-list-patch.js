import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-unified-lead-list-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

if (!source.includes("__crmUnifiedLeadListPatch_v2")) {
  const start = source.indexOf("async function getDashboardPayload(token) {");
  const end = source.indexOf("function reportText(summary)", start);
  if (start === -1 || end === -1) {
    console.warn("[crm-unified-lead-list-patch] Could not find getDashboardPayload block.");
  } else {
    const block = `// __crmUnifiedLeadListPatch_v2
function leadIdentityKey(lead) {
  const email = String(lead.email || "").trim().toLowerCase();
  if (email) return "email:" + email;
  const phone = String(lead.phone || lead.mobile || "").replace(/\D/g, "");
  if (phone) return "phone:" + phone;
  const nameCompany = String((lead.name || "") + "::" + (lead.company || "")).trim().toLowerCase();
  if (nameCompany && nameCompany !== "::") return "name-company:" + nameCompany;
  return "lead:" + String(lead.lead_id || Math.random());
}
function sortCrmLeadsNewestFirst(a, b) {
  const ta = Date.parse(a.created_at || a.received_at || a.timestamp || 0) || 0;
  const tb = Date.parse(b.created_at || b.received_at || b.timestamp || 0) || 0;
  return tb - ta;
}
function uniqueCrmLeads(leads) {
  const seen = new Set();
  const list = [];
  for (const lead of leads || []) {
    const key = leadIdentityKey(lead);
    if (seen.has(key)) continue;
    seen.add(key);
    list.push(lead);
  }
  return list;
}
function crmLeadStatusCounts(leads) {
  const counts = {};
  for (const lead of leads || []) {
    const key = String(lead.status || "New");
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}
function crmLeadSourceCounts(leads) {
  const counts = {};
  for (const lead of leads || []) {
    const key = String(lead.source || "Form Submission");
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}
function crmListSummary(leads) {
  const list = leads || [];
  const pipelineValue = list.reduce((sum, lead) => sum + (Number(lead.value) || 0), 0);
  const expectedRevenue = list.reduce((sum, lead) => sum + (Number(lead.expected_revenue) || 0), 0);
  const openLeads = list.filter((lead) => !/closed won|closed lost/i.test(String(lead.status || ""))).length;
  return {
    total: list.length,
    open: openLeads,
    pipeline_value: pipelineValue,
    expected_revenue: expectedRevenue,
    statuses: crmLeadStatusCounts(list),
    sources: crmLeadSourceCounts(list)
  };
}
async function getUnifiedCrmLeadList(siteId, token) {
  const rawStored = await getCrmLeads(siteId);
  const storedLeads = (rawStored || []).map((lead, i) => mapLead(lead, i));
  return uniqueCrmLeads(storedLeads).sort(sortCrmLeadsNewestFirst);
}
async function getDashboardPayload(token) {
  const emptyBase = demoPayload();
  const site = await findSiteByToken(token);
  const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token || "demo"));
  const [events, reports, leads] = await Promise.all([getEvents(siteId), getReports(siteId), getUnifiedCrmLeadList(siteId, token)]);
  const summary = events.length ? summarize(events) : { total: 0, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0, sessions: 0, avgDurationSeconds: 0, bounceRate: 0, days: [], typeCounts: [], pageCounts: [], sources: [], devices: [] };
  summary.leads = leads.length;
  const crm = { leads, summary: crmListSummary(leads), source: "unified_crm_lead_list" };
  return {
    ...emptyBase,
    usingFallback: false,
    dbConnected: hasDb(),
    site: { ...emptyBase.site, site_id: siteId, token },
    summary,
    crm,
    leads,
    reports,
    recentEvents: events.slice(0, 80).map((event) => ({ type: eventType(event), path: cleanPath(eventPath(event)), time: eventTime(event) || new Date().toISOString(), amount: eventAmount(event), source: valueFrom(event, ["source"], "Direct"), device: valueFrom(event, ["device"], "Desktop") }))
  };
}
`;
    source = source.slice(0, start) + block + source.slice(end);
    changed = true;
  }
}

if (!source.includes('app.get("/api/crm/leads"')) {
  const anchor = 'app.get("/api/dashboard", async (req, res) => {';
  const route = 'app.get("/api/crm/leads", async (req, res) => { try { const token = String(req.query.token || "demo"); const payload = await getDashboardPayload(token); res.json({ ok: true, site: payload.site, source: "unified_crm_lead_list", summary: payload.crm?.summary || {}, leads: payload.leads || [] }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "CRM lead list failed." }); } });\n';
  if (source.includes(anchor)) {
    source = source.replace(anchor, route + anchor);
    changed = true;
  } else {
    console.warn("[crm-unified-lead-list-patch] Could not find API dashboard anchor.");
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Unified CRM lead list patch applied without demo data.");
} else {
  console.log("Unified CRM lead list patch already applied or no changes needed.");
}
