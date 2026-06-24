import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";
import { Pool } from "pg";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;
const TO_EMAIL = process.env.TO_EMAIL || "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "";
const resend = new Resend(process.env.RESEND_API_KEY || "missing-key");

app.use(express.json({ limit: "400kb" }));
app.use(express.urlencoded({ extended: true, limit: "400kb" }));
app.use(express.static(__dirname));

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false } })
  : null;
const columnCache = new Map();

function hasDb() { return Boolean(pool); }
function db() { if (!pool) throw new Error("DATABASE_URL is not set."); return pool; }
function q(name) { return `"${String(name).replaceAll('"', '""')}"`; }
function makeToken(prefix = "cx") { return `${prefix}_${randomBytes(12).toString("hex")}`; }
function esc(value) { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }
function money(num, digits = 0) { return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", minimumFractionDigits: digits, maximumFractionDigits: digits }).format(Number(num || 0)); }
function fmt(num) { return new Intl.NumberFormat("en-US").format(Math.round(Number(num || 0))); }
function pct(part, whole, digits = 2) { const w = Number(whole || 0); return w ? ((Number(part || 0) / w) * 100).toFixed(digits) : "0.00"; }
function firstExisting(cols, names) { return names.find((name) => cols.includes(name)); }
function cols(info) { return info.map((c) => c.column_name); }
function valueFrom(row, names, fallback = "") {
  for (const name of names) {
    if (row && row[name] !== undefined && row[name] !== null && row[name] !== "") return row[name];
    for (const key of ["payload", "metadata", "data", "properties"]) {
      if (row && row[key] && typeof row[key] === "object" && row[key][name] !== undefined && row[key][name] !== null && row[key][name] !== "") return row[key][name];
    }
  }
  return fallback;
}
async function tableInfo(tableName) {
  if (!hasDb()) return [];
  if (columnCache.has(tableName)) return columnCache.get(tableName);
  const result = await db().query(
    `SELECT column_name, data_type, udt_name, is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position`,
    [tableName]
  );
  columnCache.set(tableName, result.rows);
  return result.rows;
}
function isJsonColumn(info, name) { const c = info.find((x) => x.column_name === name); return c && ["json", "jsonb"].includes(c.udt_name); }
function virtualSite(token = "demo") { return { id: token, site_id: token, site_name: "Constrava Demo", name: "Constrava Demo", owner_email: "admin@constrava.com", plan: "demo", dashboard_token: token }; }
async function findSiteByToken(token) {
  const clean = String(token || "").trim();
  if (!clean) return null;
  if (!hasDb()) return virtualSite(clean);
  const info = await tableInfo("sites");
  const c = cols(info);
  if (!c.length) return virtualSite(clean);
  const tokenColumns = ["dashboard_token", "token", "demo_token", "access_token", "public_token", "site_token", "id", "site_id"].filter((name) => c.includes(name));
  if (!tokenColumns.length) return virtualSite(clean);
  const where = tokenColumns.map((col) => `${q(col)}::text = $1`).join(" OR ");
  const result = await db().query(`SELECT * FROM sites WHERE ${where} LIMIT 1`, [clean]);
  return result.rows[0] || null;
}
async function getSiteById(siteId) {
  if (!hasDb()) return virtualSite(siteId || "demo");
  const info = await tableInfo("sites");
  const c = cols(info);
  if (!c.length) return virtualSite(siteId || "demo");
  const idColumns = ["site_id", "id", "token", "dashboard_token", "site_token"].filter((name) => c.includes(name));
  if (!idColumns.length) return virtualSite(siteId || "demo");
  const where = idColumns.map((col) => `${q(col)}::text = $1`).join(" OR ");
  const result = await db().query(`SELECT * FROM sites WHERE ${where} LIMIT 1`, [String(siteId || "")]);
  return result.rows[0] || virtualSite(siteId || "demo");
}
function eventType(event) { return String(valueFrom(event, ["event_name", "event_type", "type", "name", "event", "action"], "event")); }
function eventPath(event) { return String(valueFrom(event, ["path", "url", "page", "pathname", "href", "route"], "/")); }
function eventTime(event) { return String(valueFrom(event, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"], "")); }
function eventAmount(event) { const n = Number(valueFrom(event, ["amount", "revenue", "value", "price", "total"], 0)); return Number.isFinite(n) ? n : 0; }
async function getEvents(siteId, limit = 750) {
  if (!hasDb()) return [];
  const info = await tableInfo("events_raw");
  const c = cols(info);
  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
  if (!siteCol) return [];
  const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
  const result = await db().query(`SELECT * FROM events_raw WHERE ${q(siteCol)}::text = $1 ${order} LIMIT $2`, [String(siteId), Number(limit)]);
  return result.rows;
}
async function getReports(siteId, limit = 10) {
  if (!hasDb()) return [];
  try {
    const info = await tableInfo("daily_reports");
    const c = cols(info);
    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    const timeCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);
    if (!siteCol) return [];
    const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
    const result = await db().query(`SELECT * FROM daily_reports WHERE ${q(siteCol)}::text = $1 ${order} LIMIT $2`, [String(siteId), Number(limit)]);
    return result.rows;
  } catch (err) { console.warn("Reports unavailable:", err.message); return []; }
}
async function getCrmLeads(siteId, limit = 80) {
  if (!hasDb()) return [];
  try {
    const info = await tableInfo("crm_leads");
    const c = cols(info);
    if (!c.length) return [];
    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "received_at", "inserted_at"]);
    const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
    if (siteCol) {
      const result = await db().query(`SELECT * FROM crm_leads WHERE ${q(siteCol)}::text = $1 ${order} LIMIT $2`, [String(siteId), Number(limit)]);
      return result.rows;
    }
    const result = await db().query(`SELECT * FROM crm_leads ${order} LIMIT $1`, [Number(limit)]);
    return result.rows;
  } catch (err) { console.warn("CRM leads unavailable:", err.message); return []; }
}
function fallbackSummary() {
  return {
    total: 24968, visits: 18426, leads: 1284, purchases: 392, clicks: 2781, revenue: 24680, sessions: 10942, avgDurationSeconds: 102, bounceRate: 31,
    days: [
      { day: "2025-05-10", visits: 1680, leads: 104, purchases: 29, clicks: 248, revenue: 1827 },
      { day: "2025-05-11", visits: 2410, leads: 162, purchases: 45, clicks: 362, revenue: 2835 },
      { day: "2025-05-12", visits: 2875, leads: 190, purchases: 58, clicks: 441, revenue: 3654 },
      { day: "2025-05-13", visits: 2180, leads: 146, purchases: 43, clicks: 337, revenue: 2709 },
      { day: "2025-05-14", visits: 3120, leads: 218, purchases: 68, clicks: 496, revenue: 4284 },
      { day: "2025-05-15", visits: 3456, leads: 253, purchases: 79, clicks: 531, revenue: 4977 },
      { day: "2025-05-16", visits: 2690, leads: 211, purchases: 70, clicks: 366, revenue: 4410 },
    ],
    typeCounts: [["page_view", 18426], ["cta_click", 2781], ["lead", 1284], ["purchase", 392], ["pricing_view", 1188], ["contact_open", 904]],
    pageCounts: [["/", 6820], ["/services", 4210], ["/contact", 1984], ["/work", 1432], ["/process", 1130], ["/dashboard", 914]],
    sources: [["Direct", 6580], ["Search", 5210], ["Social", 3842], ["Referral", 2794]],
    devices: [["Desktop", 59], ["Mobile", 34], ["Tablet", 7]],
  };
}
function fallbackLeads() {
  return [
    { name: "Avery Morgan", email: "avery@example.com", company: "Northstar Studio", status: "Qualified", source: "Contact form", created_at: "2025-05-16", value: 4800, notes: "Needs a client portal and analytics dashboard." },
    { name: "Jordan Lee", email: "jordan@example.com", company: "Lee Manufacturing", status: "New", source: "Pricing CTA", created_at: "2025-05-15", value: 3200, notes: "Interested in production tracking software." },
    { name: "Sam Patel", email: "sam@example.com", company: "Patel Labs", status: "Proposal", source: "Referral", created_at: "2025-05-14", value: 7400, notes: "Proposal sent for internal CRM." },
    { name: "Mia Carter", email: "mia@example.com", company: "Carter Design", status: "Negotiation", source: "Search", created_at: "2025-05-14", value: 6100, notes: "Asked for monthly support after launch." },
    { name: "Leo Brooks", email: "leo@example.com", company: "Brooks HVAC", status: "Closed Won", source: "Direct", created_at: "2025-05-13", value: 2500, notes: "Signed starter dashboard package." },
    { name: "Nora Kim", email: "nora@example.com", company: "Kim Fitness", status: "Needs Analysis", source: "Social", created_at: "2025-05-12", value: 3900, notes: "Needs booking and payment workflow." },
    { name: "Owen Clark", email: "owen@example.com", company: "Clark Electric", status: "Qualified", source: "Search", created_at: "2025-05-11", value: 5300, notes: "Wants job tracking and invoice exports." }
  ];
}
function summarize(events) {
  let visits = 0, leads = 0, purchases = 0, clicks = 0, revenue = 0;
  const sessions = new Set(), typeCounts = new Map(), pageCounts = new Map(), sourceCounts = new Map(), dayMetrics = new Map(), deviceCounts = new Map();
  for (const event of events) {
    const type = eventType(event).toLowerCase();
    const pathName = eventPath(event);
    const day = eventTime(event) ? String(eventTime(event)).slice(0, 10) : new Date().toISOString().slice(0, 10);
    const amount = eventAmount(event);
    const source = String(valueFrom(event, ["source", "utm_source", "referrer", "campaign"], "Direct") || "Direct");
    const device = String(valueFrom(event, ["device", "device_type", "platform"], "Desktop") || "Desktop");
    const session = String(valueFrom(event, ["session_id", "sid", "visitor", "visitor_id", "anonymous_id"], "") || "");
    if (session) sessions.add(session);
    if (!dayMetrics.has(day)) dayMetrics.set(day, { day, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0 });
    const bucket = dayMetrics.get(day);
    typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    pageCounts.set(pathName, (pageCounts.get(pathName) || 0) + 1);
    sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    deviceCounts.set(device, (deviceCounts.get(device) || 0) + 1);
    if (type.includes("page") || type.includes("visit") || type.includes("view")) { visits++; bucket.visits++; }
    if (type.includes("lead") || type.includes("form") || type.includes("contact")) { leads++; bucket.leads++; }
    if (type.includes("purchase") || type.includes("sale") || type.includes("checkout")) { purchases++; revenue += amount || 129; bucket.purchases++; bucket.revenue += amount || 129; }
    if (type.includes("cta") || type.includes("click")) { clicks++; bucket.clicks++; }
  }
  const totalDevices = [...deviceCounts.values()].reduce((a, b) => a + b, 0) || 1;
  return { total: events.length, visits, leads, purchases, clicks, revenue, sessions: sessions.size || Math.round(visits * 0.62), avgDurationSeconds: events.length ? 94 + Math.min(70, Math.round(events.length / 20)) : 0, bounceRate: events.length ? Math.max(18, 44 - Math.round((leads / Math.max(visits, 1)) * 100)) : 0, days: [...dayMetrics.values()].sort((a, b) => a.day.localeCompare(b.day)), typeCounts: [...typeCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), pageCounts: [...pageCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), sources: [...sourceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6), devices: [...deviceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([name, value]) => [name, Math.round((value / totalDevices) * 100)]) };
}
function dashboardJson(site, events, reports, leads) {
  const siteId = String(valueFrom(site, ["site_id", "id"], "demo"));
  const live = summarize(events);
  const usingFallback = !live.total;
  const summary = usingFallback ? fallbackSummary() : live;
  const recentEvents = events.slice(0, 40).map((event) => ({ type: eventType(event), path: eventPath(event), time: eventTime(event), amount: eventAmount(event) }));
  if (usingFallback && !recentEvents.length) recentEvents.push({ type: "page_view", path: "/", time: "2025-05-16T12:42:00Z", amount: 0 }, { type: "cta_click", path: "/services", time: "2025-05-16T12:37:00Z", amount: 0 }, { type: "lead", path: "/contact", time: "2025-05-16T12:31:00Z", amount: 0 }, { type: "purchase", path: "/checkout", time: "2025-05-16T12:12:00Z", amount: 129 });
  const mappedReports = reports.slice(0, 10).map((report) => ({ date: String(valueFrom(report, ["report_date", "date", "created_at", "generated_at"], "Latest report")), text: String(valueFrom(report, ["summary", "report", "content", "body", "insights", "ai_summary", "report_text"], "")) }));
  let mappedLeads = leads.slice(0, 80).map((lead, i) => ({ name: String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead")), email: String(valueFrom(lead, ["email", "lead_email", "contact_email"], "lead@example.com")), company: String(valueFrom(lead, ["company", "organization"], "—")), status: String(valueFrom(lead, ["status", "stage", "lead_status"], "New")), source: String(valueFrom(lead, ["source", "channel", "campaign"], "Website")), created_at: String(valueFrom(lead, ["created_at", "timestamp", "received_at"], "")), value: Number(valueFrom(lead, ["value", "deal_value", "amount", "budget"], 2200 + i * 700)) || 2200 + i * 700, notes: String(valueFrom(lead, ["notes", "message", "body"], "")) }));
  if (usingFallback && !mappedLeads.length) mappedLeads = fallbackLeads();
  return { ok: true, usingFallback, dbConnected: hasDb(), site: { site_id: siteId, site_name: String(valueFrom(site, ["site_name", "name", "business_name", "domain"], "Constrava Demo")), owner_email: String(valueFrom(site, ["owner_email", "email", "contact_email"], "admin@constrava.com")), plan: String(valueFrom(site, ["plan", "tier", "status"], "demo")), token: String(valueFrom(site, ["dashboard_token", "token", "demo_token", "access_token", "public_token", "site_token"], "")) }, summary, reports: mappedReports, leads: mappedLeads, recentEvents };
}
async function getDashboardPayload(token) {
  const site = await findSiteByToken(token);
  if (!site) return null;
  const siteId = String(valueFrom(site, ["site_id", "id"], token));
  const [events, reports, leads] = await Promise.all([getEvents(siteId), getReports(siteId), getCrmLeads(siteId)]);
  return dashboardJson(site, events, reports, leads);
}
async function insertEvent(siteId, type, options = {}) {
  if (!hasDb()) return false;
  const info = await tableInfo("events_raw");
  const c = cols(info);
  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  const typeCol = firstExisting(c, ["event_name", "event_type", "type", "name", "event", "action"]);
  const pathCol = firstExisting(c, ["path", "url", "page", "pathname", "href", "route"]);
  const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
  const payloadCol = firstExisting(c, ["payload", "metadata", "data", "properties"]);
  const amountCol = firstExisting(c, ["amount", "revenue", "value", "price", "total"]);
  if (!siteCol) return false;
  const pathName = options.path || (type === "lead" ? "/contact" : type === "purchase" ? "/checkout" : type === "cta_click" ? "/services" : "/");
  const payload = { demo: Boolean(options.demo ?? true), source: options.source || "dashboard", event_type: type, type, path: pathName, amount: type === "purchase" ? Number(options.amount || 129) : Number(options.amount || 0), campaign: options.campaign || "client-demo", visitor: options.visitor || `visitor_${Math.random().toString(16).slice(2, 8)}`, device: options.device || "Desktop", url: options.url || pathName };
  const insertCols = [];
  const values = [];
  function add(col, value) { if (col && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } }
  add(siteCol, String(siteId)); add(typeCol, type); add(pathCol, pathName); add(timeCol, options.time || new Date()); add(amountCol, payload.amount); if (payloadCol) add(payloadCol, isJsonColumn(info, payloadCol) ? payload : JSON.stringify(payload));
  if (!insertCols.length) return false;
  await db().query(`INSERT INTO events_raw (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values);
  return true;
}
async function insertLeadRecord(siteId, leadData) {
  if (!hasDb()) return false;
  try {
    const info = await tableInfo("crm_leads");
    const c = cols(info);
    if (!c.length) return false;
    const insertCols = [];
    const values = [];
    const add = (possible, value) => { const col = firstExisting(c, possible); if (col && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } };
    add(["site_id", "site", "client_site_id", "project_id"], String(siteId || "contact"));
    add(["name", "full_name", "lead_name", "contact_name"], leadData.name || "New Lead");
    add(["email", "lead_email", "contact_email"], leadData.email || "");
    add(["company", "organization"], leadData.company || "");
    add(["status", "stage", "lead_status"], leadData.status || "New");
    add(["source", "channel", "campaign"], leadData.source || "Website");
    add(["notes", "message", "body"], leadData.message || leadData.notes || "");
    add(["created_at", "timestamp", "received_at", "inserted_at"], new Date());
    const payloadCol = firstExisting(c, ["payload", "metadata", "data", "properties"]);
    if (payloadCol) add([payloadCol], isJsonColumn(info, payloadCol) ? leadData : JSON.stringify(leadData));
    if (!insertCols.length) return false;
    await db().query(`INSERT INTO crm_leads (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values);
    return true;
  } catch (err) { console.warn("CRM insert skipped:", err.message); return false; }
}
function reportText(summary) {
  const bestDay = [...(summary.days || [])].sort((a, b) => (b.visits || 0) - (a.visits || 0))[0];
  return ["Constrava AI Report", "", `Traffic is showing ${fmt(summary.visits)} visits, ${fmt(summary.leads)} leads, and ${fmt(summary.purchases)} purchases in the selected window.`, `Lead conversion is ${pct(summary.leads, summary.visits)}%. Purchase conversion is ${pct(summary.purchases, summary.visits)}%. Estimated revenue is ${money(summary.revenue)}.`, bestDay ? `Best traffic day: ${bestDay.day} with ${fmt(bestDay.visits)} visits.` : "", "", "Recommended next actions:", "1. Keep the highest-performing page or offer prominent above the fold.", "2. Improve the lead step because small gains there create large downstream impact.", "3. Use the CRM pipeline view to follow up with qualified/proposal leads first."].filter(Boolean).join("\n");
}
async function insertReport(siteId, text) {
  if (!hasDb()) return false;
  try {
    const info = await tableInfo("daily_reports");
    const c = cols(info);
    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    const textCol = firstExisting(c, ["summary", "report", "content", "body", "insights", "ai_summary", "report_text"]);
    const dateCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);
    if (!siteCol || !textCol) return false;
    const insertCols = [];
    const values = [];
    function add(col, value) { if (col && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } }
    add(siteCol, String(siteId)); add(textCol, text); add(dateCol, new Date());
    await db().query(`INSERT INTO daily_reports (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values);
    return true;
  } catch { return false; }
}
function servePage(fileName, fallbackHtml) { return (req, res) => res.sendFile(path.join(__dirname, fileName), (err) => { if (err) res.status(200).send(fallbackHtml); }); }

app.get("/health", (req, res) => res.status(200).send("ok"));
app.get("/db-test", async (req, res) => { try { if (!hasDb()) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set." }); const result = await db().query("SELECT NOW() AS now"); res.json({ ok: true, now: result.rows[0].now }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/dashboard", servePage("dashboard.html", "<h1>Constrava Dashboard</h1><p>dashboard.html is missing.</p>"));
app.get("/crm", servePage("crm.html", "<h1>Constrava CRM</h1><p>crm.html is missing.</p>"));
app.get("/api/dashboard", async (req, res) => { try { const token = String(req.query.token || "").trim(); if (!token) return res.status(400).json({ ok: false, error: "Missing token." }); const payload = await getDashboardPayload(token); if (!payload) return res.status(404).json({ ok: false, error: "No site found for that token." }); res.json(payload); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/dashboard/data", async (req, res) => { try { const token = String(req.query.token || "").trim(); if (!token) return res.status(400).json({ ok: false, error: "Missing token." }); const payload = await getDashboardPayload(token); if (!payload) return res.status(404).json({ ok: false, error: "Site not found." }); res.json(payload); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/simulate", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "").trim(); const type = String(req.query.type || req.body?.type || "page_view").trim(); if (!token) return res.status(400).json({ ok: false, error: "Missing token." }); const site = await findSiteByToken(token); if (!site) return res.status(404).json({ ok: false, error: "Site not found." }); const siteId = String(valueFrom(site, ["site_id", "id"], token)); await insertEvent(siteId, type, { source: "dashboard", demo: true }); res.json({ ok: true, type, site_id: siteId, stored: hasDb() }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/seed", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "").trim(); if (!token) return res.status(400).json({ ok: false, error: "Missing token." }); const site = await findSiteByToken(token); if (!site) return res.status(404).json({ ok: false, error: "Site not found." }); const siteId = String(valueFrom(site, ["site_id", "id"], token)); const now = Date.now(); const types = ["page_view", "page_view", "page_view", "page_view", "page_view", "cta_click", "cta_click", "lead", "purchase"]; let inserted = 0; for (let day = 0; day < 7; day++) { for (let i = 0; i < 9 + Math.floor(Math.random() * 10); i++) { const type = types[Math.floor(Math.random() * types.length)]; await insertEvent(siteId, type, { time: new Date(now - day * 86400000 - Math.floor(Math.random() * 80000000)), source: ["Direct", "Search", "Social", "Referral"][Math.floor(Math.random() * 4)], device: ["Desktop", "Desktop", "Mobile", "Tablet"][Math.floor(Math.random() * 4)], campaign: "seed-demo" }); inserted++; } } res.json({ ok: true, inserted, message: "Demo data seeded." }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/report", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "").trim(); if (!token) return res.status(400).json({ ok: false, error: "Missing token." }); const payload = await getDashboardPayload(token); if (!payload) return res.status(404).json({ ok: false, error: "Site not found." }); const text = reportText(payload.summary); await insertReport(payload.site.site_id, text); res.json({ ok: true, report: text, stored: hasDb() }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/dashboard/export.csv", async (req, res) => { try { const token = String(req.query.token || "").trim(); if (!token) return res.status(400).send("Missing token."); const payload = await getDashboardPayload(token); if (!payload) return res.status(404).send("Site not found."); const rows = [["type", "path", "time", "amount"]]; for (const event of payload.recentEvents || []) rows.push([event.type, event.path, event.time, String(event.amount || 0)]); const csv = rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n"); res.setHeader("Content-Type", "text/csv"); res.setHeader("Content-Disposition", "attachment; filename=constrava-dashboard-events.csv"); res.send(csv); } catch (err) { res.status(500).send(err.message); } });
app.post("/api/lead", async (req, res) => { try { const { name, email, company, role, type, timeline, budget, links, memberCode, message, website } = req.body || {}; if (website && String(website).trim() !== "") return res.json({ ok: true }); if (!name || !email || !message) return res.status(400).json({ ok: false, error: "Please include name, email, and message." }); await insertLeadRecord("contact", { name, email, company, role, type, timeline, budget, links, memberCode, message, source: "Website contact form", status: "New" }); if (!process.env.RESEND_API_KEY || !FROM_EMAIL) return res.json({ ok: true, warning: "Lead received. Email is not configured on this server." }); await resend.emails.send({ from: FROM_EMAIL, to: TO_EMAIL, replyTo: email, subject: `Constrava Request — ${esc(name)} (${esc(type || "Project")})`, html: `<div style="font-family:Arial,sans-serif;line-height:1.5"><h2>New Constrava Project Request</h2><p><b>Name:</b> ${esc(name)}</p><p><b>Email:</b> ${esc(email)}</p><p><b>Company:</b> ${esc(company || "")}</p><p><b>Message:</b></p><pre>${esc(message || "")}</pre></div>` }); res.json({ ok: true }); } catch (err) { res.status(500).json({ ok: false, error: "Lead send failed. Check Render logs." }); } });
app.post("/sites", async (req, res) => { try { if (!hasDb()) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set." }); const info = await tableInfo("sites"); const c = cols(info); const dashboardToken = String(req.body?.dashboard_token || req.body?.token || makeToken("dash")); const siteIdValue = String(req.body?.site_id || makeToken("site")); const name = String(req.body?.site_name || req.body?.name || "Client Demo"); const domain = String(req.body?.domain || ""); const ownerEmail = String(req.body?.owner_email || req.body?.email || "admin@constrava.com"); const insertCols = []; const values = []; const add = (possible, value) => { const col = firstExisting(c, possible); if (col && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } }; add(["site_id", "id"], siteIdValue); add(["site_name", "name", "business_name"], name); add(["domain"], domain); add(["owner_email", "email", "contact_email"], ownerEmail); add(["dashboard_token", "token", "demo_token", "access_token", "public_token", "site_token"], dashboardToken); add(["plan", "tier", "status"], "demo"); add(["created_at", "inserted_at"], new Date()); if (!insertCols.length) return res.status(500).json({ ok: false, error: "No compatible sites columns were found." }); await db().query(`INSERT INTO sites (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values); res.json({ ok: true, site_id: siteIdValue, dashboard_token: dashboardToken, dashboard_url: `/dashboard?token=${encodeURIComponent(dashboardToken)}` }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.options("/events", (req, res) => { res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS"); res.setHeader("Access-Control-Allow-Headers", "Content-Type"); res.status(204).end(); });
app.post("/events", async (req, res) => { res.setHeader("Access-Control-Allow-Origin", "*"); try { const body = req.body || {}; const token = String(body.token || body.dashboard_token || body.site_token || req.query.token || "").trim(); const siteIdInput = String(body.site_id || body.siteId || req.query.site_id || req.query.siteId || "").trim(); let site = null; if (token) site = await findSiteByToken(token); if (!site && siteIdInput) site = await getSiteById(siteIdInput); const siteId = site ? String(valueFrom(site, ["site_id", "id"], siteIdInput || token || "demo")) : siteIdInput || token || "demo"; const type = String(body.event_type || body.type || body.name || "page_view"); await insertEvent(siteId, type, { path: String(body.path || body.pathname || body.url || "/"), url: String(body.url || body.href || ""), amount: Number(body.amount || body.revenue || body.value || 0), source: String(body.source || body.utm_source || "tracker"), visitor: String(body.visitor || body.visitor_id || body.anonymous_id || ""), demo: false, device: String(body.device || "") }); res.status(204).end(); } catch (err) { res.status(200).json({ ok: false, error: err.message }); } });
app.get("/tracker.js", (req, res) => { res.type("application/javascript"); res.send("window.ConstravaTrack=function(type,payload){payload=payload||{};fetch('/events',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({type:type,event_type:type,path:location.pathname,url:location.href,source:'tracker'},payload))}).catch(function(){})};window.ConstravaTrack('page_view',{});"); });
app.get("/reports/latest", async (req, res) => { try { const payload = await getDashboardPayload(String(req.query.token || "")); if (!payload) return res.status(404).json({ ok: false, error: "Site not found." }); res.json({ ok: true, report: payload.reports[0] || { date: new Date().toISOString(), text: reportText(payload.summary) } }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/live", async (req, res) => { try { const payload = await getDashboardPayload(String(req.query.token || "")); if (!payload) return res.status(404).json({ ok: false, error: "Site not found." }); res.json({ ok: true, events: payload.recentEvents, summary: payload.summary }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/", servePage("index.html", `<!doctype html><html><head><title>Constrava</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fffc;color:#0f172a}main{max-width:900px;margin:0 auto;padding:80px 24px}a{color:#047857;font-weight:800}</style></head><body><main><h1>Constrava</h1><p>Rapid custom app development, analytics, and AI-assisted business tools.</p><p><a href="/dashboard?token=demo">Open dashboard demo</a></p></main></body></html>`));
app.get("/services", servePage("services.html", "<h1>Constrava Services</h1>"));
app.get("/process", servePage("process.html", "<h1>Constrava Process</h1>"));
app.get("/work", servePage("work.html", "<h1>Constrava Work</h1>"));
app.get("/contact", servePage("contact.html", "<h1>Contact Constrava</h1>"));
app.use((req, res) => res.status(404).send(`<h1>404</h1><p>Route not found.</p><p><a href="/">Back to Constrava</a></p>`));
app.listen(PORT, () => console.log("Constrava running on port", PORT));
