import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";
import { Pool } from "pg";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
app.set("trust proxy", true);
const PORT = process.env.PORT || 3000;
const TO_EMAIL = process.env.TO_EMAIL || "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "";
const resend = new Resend(process.env.RESEND_API_KEY || "missing-key");

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.static(__dirname));

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false } })
  : null;
const columnCache = new Map();
const intakeLeads = [];
const googleConnections = new Map();
const GOOGLE_FORM_SCOPES = [
  "openid",
  "email",
  "profile",
  "https://www.googleapis.com/auth/drive.metadata.readonly",
  "https://www.googleapis.com/auth/forms.body.readonly",
  "https://www.googleapis.com/auth/forms.responses.readonly"
];

function hasDb() { return Boolean(pool); }
function db() { if (!pool) throw new Error("DATABASE_URL is not set."); return pool; }
function q(name) { return `"${String(name).replaceAll('"', '""')}"`; }
function makeToken(prefix = "cx") { return `${prefix}_${randomBytes(12).toString("hex")}`; }
function esc(value) { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }
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
  } catch { return []; }
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
    if (siteCol) return (await db().query(`SELECT * FROM crm_leads WHERE ${q(siteCol)}::text = $1 ${order} LIMIT $2`, [String(siteId), Number(limit)])).rows;
    return (await db().query(`SELECT * FROM crm_leads ${order} LIMIT $1`, [Number(limit)])).rows;
  } catch { return []; }
}
function demoPayload() {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, "dashboard/data"), "utf8")); }
  catch {
    return { ok: true, usingFallback: true, dbConnected: false, site: { site_id: "demo", site_name: "Constrava Demo", owner_email: "admin@constrava.com", plan: "demo", token: "demo" }, summary: { total: 0, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0, sessions: 0, avgDurationSeconds: 0, bounceRate: 0, days: [], typeCounts: [], pageCounts: [], sources: [], devices: [] }, reports: [], recentEvents: [], leads: [] };
  }
}
function summarize(events) {
  let visits = 0, leads = 0, purchases = 0, clicks = 0, revenue = 0;
  const typeCounts = new Map(), pageCounts = new Map(), sourceCounts = new Map(), dayMetrics = new Map(), deviceCounts = new Map(), sessions = new Set();
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
    typeCounts.set(type, (typeCounts.get(type) || 0) + 1); pageCounts.set(pathName, (pageCounts.get(pathName) || 0) + 1); sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1); deviceCounts.set(device, (deviceCounts.get(device) || 0) + 1);
    if (type.includes("page") || type.includes("visit") || type.includes("view")) { visits++; bucket.visits++; }
    if (type.includes("lead") || type.includes("form") || type.includes("contact")) { leads++; bucket.leads++; }
    if (type.includes("purchase") || type.includes("sale") || type.includes("checkout")) { purchases++; revenue += amount || 129; bucket.purchases++; bucket.revenue += amount || 129; }
    if (type.includes("cta") || type.includes("click")) { clicks++; bucket.clicks++; }
  }
  const totalDevices = [...deviceCounts.values()].reduce((a, b) => a + b, 0) || 1;
  return { total: events.length, visits, leads, purchases, clicks, revenue, sessions: sessions.size || Math.round(visits * 0.62), avgDurationSeconds: events.length ? 110 : 0, bounceRate: events.length ? 24 : 0, days: [...dayMetrics.values()].sort((a, b) => a.day.localeCompare(b.day)), typeCounts: [...typeCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), pageCounts: [...pageCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), sources: [...sourceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6), devices: [...deviceCounts.entries()].map(([name, value]) => [name, Math.round((value / totalDevices) * 100)]) };
}
function mapLead(lead, i) {
  return { name: String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead")), email: String(valueFrom(lead, ["email", "lead_email", "contact_email"], "lead@example.com")), company: String(valueFrom(lead, ["company", "organization"], "—")), status: String(valueFrom(lead, ["status", "stage", "lead_status"], "New")), source: String(valueFrom(lead, ["source", "channel", "campaign"], "Website")), created_at: String(valueFrom(lead, ["created_at", "timestamp", "received_at"], "")), value: Number(valueFrom(lead, ["value", "deal_value", "amount", "budget"], 2200 + i * 700)) || 2200 + i * 700, notes: String(valueFrom(lead, ["notes", "message", "body"], "")) };
}
function memoryLeadsFor(siteId) {
  return intakeLeads.filter((lead) => !siteId || lead.site_id === siteId || lead.site_slug === siteId || lead.dashboard_token === siteId).slice(0, 60);
}
async function getDashboardPayload(token) {
  const demo = demoPayload();
  if (!hasDb()) {
    const memory = memoryLeadsFor(String(token || "demo"));
    return { ...demo, leads: [...memory, ...(demo.leads || [])], recentEvents: [...memory.map((lead) => ({ type: "form_lead", path: `/forms/${lead.form_slug || "intake"}`, time: lead.created_at, amount: lead.value || 0 })), ...(demo.recentEvents || [])] };
  }
  const site = await findSiteByToken(token);
  if (!site) return demo;
  const siteId = String(valueFrom(site, ["site_id", "id"], token));
  const memory = memoryLeadsFor(siteId);
  const [events, reports, rawLeads] = await Promise.all([getEvents(siteId), getReports(siteId), getCrmLeads(siteId)]);
  if (!events.length && !rawLeads.length && !memory.length) return demo;
  const summary = events.length ? summarize(events) : demo.summary;
  const leads = [...memory, ...(rawLeads.length ? rawLeads.map(mapLead) : demo.leads)];
  return { ...demo, usingFallback: !events.length, dbConnected: hasDb(), site: { ...demo.site, site_id: siteId }, summary, leads, reports: reports.length ? reports : demo.reports, recentEvents: [...memory.map((lead) => ({ type: "form_lead", path: `/forms/${lead.form_slug || "intake"}`, time: lead.created_at, amount: lead.value || 0 })), ...events.slice(0, 40).map((event) => ({ type: eventType(event), path: eventPath(event), time: eventTime(event), amount: eventAmount(event) }))] };
}
async function insertEvent(siteId, type, options = {}) {
  if (!hasDb()) return false;
  const info = await tableInfo("events_raw");
  const c = cols(info);
  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  if (!siteCol) return false;
  const typeCol = firstExisting(c, ["event_name", "event_type", "type", "name", "event", "action"]);
  const pathCol = firstExisting(c, ["path", "url", "page", "pathname", "href", "route"]);
  const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
  const payloadCol = firstExisting(c, ["payload", "metadata", "data", "properties"]);
  const amountCol = firstExisting(c, ["amount", "revenue", "value", "price", "total"]);
  const pathName = options.path || (type === "lead" ? "/contact" : type === "purchase" ? "/checkout" : type === "cta_click" ? "/services" : "/");
  const payload = { demo: true, source: options.source || "dashboard", event_type: type, type, path: pathName, amount: Number(options.amount || (type === "purchase" ? 129 : 0)), lead: options.lead || null };
  const insertCols = [], values = [];
  const add = (col, value) => { if (col && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } };
  add(siteCol, String(siteId)); add(typeCol, type); add(pathCol, pathName); add(timeCol, options.time || new Date()); add(amountCol, payload.amount); if (payloadCol) add(payloadCol, isJsonColumn(info, payloadCol) ? payload : JSON.stringify(payload));
  await db().query(`INSERT INTO events_raw (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values);
  return true;
}
function normalizeFormLead(body, siteSlug, formSlug, req) {
  const payload = body && typeof body === "object" ? body : {};
  const nested = payload.form_response || payload.response || payload.data || payload.submission || payload.answers || payload.fields || {};
  const pick = (...names) => {
    for (const name of names) {
      if (payload[name] !== undefined && payload[name] !== null && payload[name] !== "") return payload[name];
      if (nested[name] !== undefined && nested[name] !== null && nested[name] !== "") return nested[name];
    }
    return "";
  };
  const firstName = pick("first_name", "firstName", "firstname", "First Name");
  const lastName = pick("last_name", "lastName", "lastname", "Last Name");
  const combinedName = pick("name", "full_name", "fullName", "lead_name", "contact_name", "Name") || [firstName, lastName].filter(Boolean).join(" ");
  const email = pick("email", "Email", "email_address", "emailAddress", "contact_email");
  const company = pick("company", "Company", "organization", "business", "business_name") || "External Form Lead";
  const message = pick("message", "Message", "notes", "Notes", "body", "comments", "description");
  const value = Number(pick("value", "budget", "deal_value", "amount", "estimated_value") || 0);
  const now = new Date().toISOString();
  return {
    lead_id: "FORM-" + randomBytes(5).toString("hex").toUpperCase(), record_type: "external_form_lead", module: "leads", site_id: siteSlug, site_slug: siteSlug, form_slug: formSlug, dashboard_token: String(pick("dashboard_token", "token") || siteSlug), name: String(combinedName || email || "External Form Lead"), email: String(email || ""), phone: String(pick("phone", "Phone", "phone_number", "mobile") || ""), company: String(company), title: String(pick("title", "role", "job_title") || "External Form Lead"), source: String(pick("source", "platform", "provider", "utm_source") || req.get("x-form-provider") || "External Form"), owner: String(pick("owner") || "Constrava Demo Team"), status: String(pick("status", "stage") || "New"), priority: String(pick("priority") || "High"), deal_name: String(pick("deal_name", "project", "service") || `${company} form inquiry`), value: Number.isFinite(value) ? value : 0, probability: 35, expected_revenue: Number.isFinite(value) ? Math.round(value * 0.35) : 0, close_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10), created_at: now, last_contacted: now.slice(0, 10), tags: ["external-form", String(siteSlug), String(formSlug)], notes: String(message || "Submitted through external form intake."), raw_submission: payload
  };
}
async function insertCrmLead(siteId, lead) {
  if (!hasDb()) return false;
  const info = await tableInfo("crm_leads");
  const c = cols(info);
  if (!c.length) return false;
  const insertCols = [], values = [];
  const add = (col, value) => { if (col && c.includes(col) && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } };
  add(firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]), siteId);
  add(firstExisting(c, ["lead_id", "id"]), lead.lead_id);
  add(firstExisting(c, ["name", "full_name", "lead_name", "contact_name"]), lead.name);
  add(firstExisting(c, ["email", "lead_email", "contact_email"]), lead.email);
  add(firstExisting(c, ["phone", "phone_number", "mobile"]), lead.phone);
  add(firstExisting(c, ["company", "organization"]), lead.company);
  add(firstExisting(c, ["status", "stage", "lead_status"]), lead.status);
  add(firstExisting(c, ["source", "channel", "campaign"]), lead.source);
  add(firstExisting(c, ["notes", "message", "body"]), lead.notes);
  add(firstExisting(c, ["value", "deal_value", "amount", "budget"]), lead.value);
  add(firstExisting(c, ["created_at", "timestamp", "received_at", "inserted_at"]), new Date(lead.created_at));
  const payloadCol = firstExisting(c, ["payload", "metadata", "data", "properties", "raw_submission"]);
  if (payloadCol) add(payloadCol, isJsonColumn(info, payloadCol) ? lead : JSON.stringify(lead));
  if (!insertCols.length) return false;
  await db().query(`INSERT INTO crm_leads (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values);
  return true;
}
function reportText(summary) { return `Constrava AI Report\n\nTraffic: ${summary.visits} visits, ${summary.leads} leads, ${summary.purchases} purchases.\nLead conversion: ${summary.visits ? ((summary.leads / summary.visits) * 100).toFixed(2) : "0.00"}%.\nRecommendation: follow up with qualified and proposal-stage CRM leads first.`; }
function servePage(fileName, fallbackHtml) { return (req, res) => res.sendFile(path.join(__dirname, fileName), (err) => { if (err) res.status(200).send(fallbackHtml); }); }
function removeVendorReferences(html) { return String(html || "").replace(/Zoho[-\s]*style\s*/gi, "custom ").replace(/\bZoho\b/gi, "CRM"); }
function cors(res) { res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-constrava-key, x-form-provider"); }
function isPrivateRequest(req) { return String(req.query.private || "") === "1" || String(req.get("x-constrava-private") || "") === "1"; }
function requirePrivate(req, res) { if (!isPrivateRequest(req)) { res.status(403).json({ ok: false, error: "This Google Forms connector is blocked on the public demo. Open the private site." }); return false; } return true; }
function appBase(req) { return `${req.protocol}://${req.get("host")}`; }
function safeReturnTo(value) { const clean = String(value || "/app/"); return clean.startsWith("/") ? clean : "/app/"; }
function encodeState(obj) { return Buffer.from(JSON.stringify(obj)).toString("base64url"); }
function decodeState(value) { try { return JSON.parse(Buffer.from(String(value || ""), "base64url").toString("utf8")); } catch { return {}; } }
function googleRedirectUri(req) { return `${appBase(req)}/auth/google/forms/callback`; }
async function refreshGoogleConnection(conn) {
  if (!conn) throw new Error("Google Forms connection not found.");
  if (conn.expires_at && Date.now() < conn.expires_at - 60000) return conn.access_token;
  if (!conn.refresh_token) return conn.access_token;
  const result = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID || "", client_secret: process.env.GOOGLE_CLIENT_SECRET || "", refresh_token: conn.refresh_token, grant_type: "refresh_token" }) });
  const json = await result.json();
  if (!result.ok) throw new Error(json.error_description || json.error || "Google token refresh failed.");
  conn.access_token = json.access_token || conn.access_token;
  conn.expires_at = Date.now() + Number(json.expires_in || 3600) * 1000;
  return conn.access_token;
}
function googleAppsScript(siteSlug, formSlug, endpoint, key) {
  return `const CONSTRAVA_ENDPOINT = "${endpoint}";
const CONSTRAVA_KEY = "${key}";

function onFormSubmit(e) {
  const data = {};
  if (e && e.namedValues) {
    Object.keys(e.namedValues).forEach(function(fieldName) {
      const value = e.namedValues[fieldName];
      data[fieldName] = Array.isArray(value) ? value.join(", ") : value;
    });
  }
  data.provider = "Google Forms";
  data.source = "Google Forms";
  data.site_slug = "${siteSlug}";
  data.form_slug = "${formSlug}";

  UrlFetchApp.fetch(CONSTRAVA_ENDPOINT, {
    method: "post",
    contentType: "application/json",
    muteHttpExceptions: true,
    headers: {
      "x-constrava-key": CONSTRAVA_KEY,
      "x-form-provider": "Google Forms"
    },
    payload: JSON.stringify(data)
  });
}

// In Apps Script: Triggers → Add Trigger → choose onFormSubmit → event type: On form submit.`;
}

app.get("/health", (req, res) => res.status(200).send("ok"));
app.get("/db-test", async (req, res) => { try { if (!hasDb()) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set." }); const result = await db().query("SELECT NOW() AS now"); res.json({ ok: true, now: result.rows[0].now }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/dashboard", (req, res) => { try { const filePath = path.join(__dirname, "dashboard.html"); let html = fs.readFileSync(filePath, "utf8"); const injection = '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>'; if (!html.includes('/crm-demo-form.js')) html = html.replace("</body>", `${injection}\n</body>`); if (html.includes('/crm-demo-form.js') && !html.includes('/crm-full-workflows.js')) html = html.replace('<script src="/crm-demo-form.js"></script>', injection); if (html.includes('/crm-full-workflows.js') && !html.includes('/crm-form-integrations.js')) html = html.replace('<script src="/crm-full-workflows.js"></script>', '<script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>'); html = removeVendorReferences(html); res.type("html").send(html); } catch (err) { res.status(200).send("<h1>Constrava Dashboard</h1><p>dashboard.html is missing.</p>"); } });
app.get("/crm", (req, res) => { const filePath = path.join(__dirname, "crm.html"); fs.readFile(filePath, "utf8", (err, html) => { if (err) return res.status(200).send("<h1>Constrava CRM</h1><p>crm.html is missing.</p>"); res.type("html").send(removeVendorReferences(html)); }); });
app.get("/dashboard/data", async (req, res) => { try { const payload = await getDashboardPayload(String(req.query.token || "demo")); res.json(payload); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/api/dashboard", async (req, res) => { try { res.json(await getDashboardPayload(String(req.query.token || "demo"))); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/auth/google/forms/start", (req, res) => {
  if (!requirePrivate(req, res)) return;
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return res.status(501).type("html").send("<h1>Google Forms OAuth is not configured</h1><p>Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render, then add this callback URL in Google Cloud:</p><pre>" + esc(googleRedirectUri(req)) + "</pre>");
  const state = encodeState({ siteSlug: req.query.siteSlug || "google-forms-site", formSlug: req.query.formSlug || "google-form", token: req.query.token || "demo", returnTo: safeReturnTo(req.query.returnTo), nonce: makeToken("state") });
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", process.env.GOOGLE_CLIENT_ID);
  url.searchParams.set("redirect_uri", googleRedirectUri(req));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("scope", GOOGLE_FORM_SCOPES.join(" "));
  url.searchParams.set("state", state);
  res.redirect(url.toString());
});
app.get("/auth/google/forms/callback", async (req, res) => {
  try {
    const state = decodeState(req.query.state);
    const code = String(req.query.code || "");
    if (!code) return res.status(400).send("Missing Google authorization code.");
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: process.env.GOOGLE_CLIENT_ID || "", client_secret: process.env.GOOGLE_CLIENT_SECRET || "", redirect_uri: googleRedirectUri(req), grant_type: "authorization_code" }) });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok) return res.status(400).json({ ok: false, error: tokens.error_description || tokens.error || "Google OAuth token exchange failed." });
    let account = "Google account";
    try { const me = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", { headers: { Authorization: `Bearer ${tokens.access_token}` } }); const user = await me.json(); account = user.email || user.name || account; } catch {}
    const connectionId = makeToken("gforms");
    googleConnections.set(connectionId, { connection_id: connectionId, site_slug: String(state.siteSlug || "google-forms-site"), form_slug: String(state.formSlug || "google-form"), dashboard_token: String(state.token || "demo"), account, access_token: tokens.access_token, refresh_token: tokens.refresh_token, expires_at: Date.now() + Number(tokens.expires_in || 3600) * 1000, scope: tokens.scope || GOOGLE_FORM_SCOPES.join(" "), connected_at: new Date().toISOString() });
    const returnTo = safeReturnTo(state.returnTo);
    const sep = returnTo.includes("?") ? "&" : "?";
    res.redirect(`${returnTo}${sep}googleFormsConnected=1&connectionId=${encodeURIComponent(connectionId)}`);
  } catch (err) { res.status(500).json({ ok: false, error: err.message || "Google Forms OAuth failed." }); }
});
app.get("/api/google/forms/status", (req, res) => { if (!requirePrivate(req, res)) return; const conn = googleConnections.get(String(req.query.connectionId || "")); if (!conn) return res.status(404).json({ ok: false, error: "Google Forms connection not found." }); res.json({ ok: true, connection: { connection_id: conn.connection_id, account: conn.account, site_slug: conn.site_slug, form_slug: conn.form_slug, connected_at: conn.connected_at } }); });
app.get("/api/google/forms/list", async (req, res) => {
  if (!requirePrivate(req, res)) return;
  try {
    const conn = googleConnections.get(String(req.query.connectionId || ""));
    if (!conn) return res.status(404).json({ ok: false, error: "Google Forms connection not found. Sign in with Google first." });
    const accessToken = await refreshGoogleConnection(conn);
    const qValue = "mimeType='application/vnd.google-apps.form' and trashed=false";
    const url = "https://www.googleapis.com/drive/v3/files?q=" + encodeURIComponent(qValue) + "&spaces=drive&pageSize=50&fields=" + encodeURIComponent("files(id,name,webViewLink,createdTime,modifiedTime)");
    const response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
    const json = await response.json();
    if (!response.ok) return res.status(response.status).json({ ok: false, error: json.error?.message || "Could not list Google Forms." });
    res.json({ ok: true, forms: json.files || [], connection: { connection_id: conn.connection_id, account: conn.account } });
  } catch (err) { res.status(500).json({ ok: false, error: err.message || "Google Forms list failed." }); }
});
app.get("/api/google/forms/apps-script", (req, res) => { if (!requirePrivate(req, res)) return; const siteSlug = String(req.query.siteSlug || "google-forms-site"); const formSlug = String(req.query.formSlug || "google-form"); const endpoint = `${appBase(req)}/api/forms/intake/${encodeURIComponent(siteSlug)}/${encodeURIComponent(formSlug)}`; const key = String(req.query.key || `cx_${siteSlug.replace(/[^a-z0-9]+/gi, "_")}_${formSlug.replace(/[^a-z0-9]+/gi, "_")}_google`); res.type("text/plain").send(googleAppsScript(siteSlug, formSlug, endpoint, key)); });
app.options("/api/forms/intake/:siteSlug/:formSlug", (req, res) => { cors(res); res.status(204).end(); });
app.post("/api/forms/intake/:siteSlug/:formSlug", async (req, res) => { cors(res); try { const siteSlug = String(req.params.siteSlug || "external-site"); const formSlug = String(req.params.formSlug || "external-form"); const lead = normalizeFormLead(req.body || {}, siteSlug, formSlug, req); intakeLeads.unshift(lead); while (intakeLeads.length > 250) intakeLeads.pop(); let crmStored = false, eventStored = false; try { crmStored = await insertCrmLead(siteSlug, lead); } catch { crmStored = false; } try { eventStored = await insertEvent(siteSlug, "form_lead", { source: lead.source, path: `/forms/${formSlug}`, amount: lead.value, lead }); } catch { eventStored = false; } res.json({ ok: true, message: "Form submission received and converted into a CRM lead.", lead_id: lead.lead_id, crm_stored: crmStored, event_stored: eventStored, session_stored: true, lead }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Form intake failed." }); } });
app.post("/dashboard/simulate", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "demo"); const type = String(req.query.type || req.body?.type || "page_view"); const site = await findSiteByToken(token); const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token)); if (hasDb()) await insertEvent(siteId, type, { source: "dashboard" }); res.json({ ok: true, type, site_id: siteId, stored: hasDb() }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/seed", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "demo"); const site = await findSiteByToken(token); const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token)); let inserted = 0; if (hasDb()) { for (const type of ["page_view", "cta_click", "lead", "purchase", "page_view", "lead"]) { await insertEvent(siteId, type, { source: "seed" }); inserted++; } } res.json({ ok: true, inserted, message: hasDb() ? "Demo data seeded." : "Demo preview already includes sample data." }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/report", async (req, res) => { try { const payload = await getDashboardPayload(String(req.query.token || req.body?.token || "demo")); res.json({ ok: true, report: reportText(payload.summary), stored: false }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/dashboard/export.csv", async (req, res) => { const payload = await getDashboardPayload(String(req.query.token || "demo")); const rows = [["type", "path", "time", "amount"], ...(payload.recentEvents || []).map((e) => [e.type, e.path, e.time, String(e.amount || 0)])]; const csv = rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n"); res.setHeader("Content-Type", "text/csv"); res.setHeader("Content-Disposition", "attachment; filename=constrava-dashboard-events.csv"); res.send(csv); });
app.post("/api/lead", async (req, res) => { try { const { name, email, message, website } = req.body || {}; if (website && String(website).trim() !== "") return res.json({ ok: true }); if (!name || !email || !message) return res.status(400).json({ ok: false, error: "Please include name, email, and message." }); if (!process.env.RESEND_API_KEY || !FROM_EMAIL) return res.json({ ok: true, warning: "Lead received. Email is not configured." }); await resend.emails.send({ from: FROM_EMAIL, to: TO_EMAIL, replyTo: email, subject: `Constrava Request — ${esc(name)}`, html: `<p><b>Name:</b> ${esc(name)}</p><p><b>Email:</b> ${esc(email)}</p><pre>${esc(message)}</pre>` }); res.json({ ok: true }); } catch { res.status(500).json({ ok: false, error: "Lead send failed." }); } });
app.post("/sites", async (req, res) => { const dashboardToken = String(req.body?.dashboard_token || req.body?.token || makeToken("dash")); res.json({ ok: true, site_id: String(req.body?.site_id || makeToken("site")), dashboard_token: dashboardToken, dashboard_url: `/dashboard?token=${encodeURIComponent(dashboardToken)}` }); });
app.options("/events", (req, res) => { res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS"); res.setHeader("Access-Control-Allow-Headers", "Content-Type"); res.status(204).end(); });
app.post("/events", async (req, res) => { res.setHeader("Access-Control-Allow-Origin", "*"); res.status(204).end(); });
app.get("/tracker.js", (req, res) => { res.type("application/javascript"); res.send("window.ConstravaTrack=function(){};"); });
app.get("/reports/latest", async (req, res) => { const payload = await getDashboardPayload(String(req.query.token || "demo")); res.json({ ok: true, report: payload.reports[0] || { date: new Date().toISOString(), text: reportText(payload.summary) } }); });
app.get("/live", async (req, res) => { const payload = await getDashboardPayload(String(req.query.token || "demo")); res.json({ ok: true, events: payload.recentEvents, summary: payload.summary }); });
app.get("/", servePage("index.html", "<h1>Constrava</h1><p><a href='/dashboard?token=demo'>Open dashboard demo</a></p>"));
app.get("/services", servePage("services.html", "<h1>Constrava Services</h1>"));
app.get("/process", servePage("process.html", "<h1>Constrava Process</h1>"));
app.get("/work", servePage("work.html", "<h1>Constrava Work</h1>"));
app.get("/contact", servePage("contact.html", "<h1>Contact Constrava</h1>"));
app.use((req, res) => res.status(404).send("<h1>404</h1><p>Route not found.</p>"));
app.listen(PORT, () => console.log("Constrava running on port", PORT));
