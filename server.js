import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { randomBytes, pbkdf2Sync, timingSafeEqual, createHmac, createHash } from "crypto";
import { Pool } from "pg";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
app.set("trust proxy", true);

const PORT = process.env.PORT || 3000;
const TO_EMAIL = process.env.TO_EMAIL || "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "";
const CANONICAL_ORIGIN = process.env.PUBLIC_ORIGIN || "https://constravaai.com";
const SESSION_COOKIE = "constrava_session";
const AUTH_SECRET = process.env.AUTH_SECRET || process.env.SESSION_SECRET || "dev-constrava-change-this-secret";
const resend = new Resend(process.env.RESEND_API_KEY || "missing-key");

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.static(__dirname));

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false } })
  : null;

const columnCache = new Map();
const memoryEvents = [];
const memoryLeads = [];
const memoryUsers = new Map();
const memoryCrmRecords = new Map();
const googleConnections = new Map();
const GOOGLE_FORM_SCOPES = ["openid", "email", "profile"];

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
    for (const key of ["payload", "metadata", "data", "properties", "raw_submission"]) {
      if (row && row[key] && typeof row[key] === "object" && row[key][name] !== undefined && row[key][name] !== null && row[key][name] !== "") return row[key][name];
    }
  }
  return fallback;
}
function isJsonColumn(info, name) { const c = info.find((x) => x.column_name === name); return c && ["json", "jsonb"].includes(c.udt_name); }
function virtualSite(token = "demo") { return { id: token, site_id: token, site_name: "Constrava Demo", name: "Constrava Demo", owner_email: "admin@constravaai.com", plan: "demo", dashboard_token: token }; }
function cleanPath(value = "/") { try { return new URL(String(value), CANONICAL_ORIGIN).pathname || "/"; } catch { return String(value || "/"); } }
function sourceFrom(referrer = "") {
  const ref = String(referrer || "");
  if (!ref) return "Direct";
  try {
    const host = new URL(ref).hostname.replace(/^www\./, "");
    if (host.includes("google")) return "Google";
    if (host.includes("bing")) return "Bing";
    if (host.includes("facebook") || host.includes("instagram") || host.includes("tiktok") || host.includes("x.com") || host.includes("twitter")) return "Social";
    if (host.includes("constravaai.com")) return "Internal";
    return host;
  } catch { return "Referral"; }
}
function deviceFrom(userAgent = "") {
  const ua = String(userAgent || "").toLowerCase();
  if (/ipad|tablet/.test(ua)) return "Tablet";
  if (/mobile|iphone|android/.test(ua)) return "Mobile";
  return "Desktop";
}
function eventType(event) { return String(valueFrom(event, ["event_name", "event_type", "type", "name", "event", "action"], "event")); }
function eventPath(event) { return String(valueFrom(event, ["path", "url", "page", "pathname", "href", "route"], "/")); }
function eventTime(event) { return String(valueFrom(event, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"], "")); }
function eventAmount(event) { const n = Number(valueFrom(event, ["amount", "revenue", "value", "price", "total"], 0)); return Number.isFinite(n) ? n : 0; }

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

let authReadyPromise = null;
function authReady() {
  if (!authReadyPromise) authReadyPromise = ensureAuthTables();
  return authReadyPromise;
}
async function ensureAuthTables() {
  if (!hasDb()) return;
  await db().query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db().query(`
    CREATE TABLE IF NOT EXISTS app_crm_records (
      user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
      record_id TEXT NOT NULL,
      record JSONB NOT NULL,
      deleted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, record_id)
    )
  `);
  await db().query(`CREATE INDEX IF NOT EXISTS app_crm_records_user_updated_idx ON app_crm_records(user_id, updated_at DESC)`);
}
function normalizeEmail(email = "") { return String(email || "").trim().toLowerCase(); }
function userIdFor(email) { return "usr_" + createHash("sha256").update(normalizeEmail(email)).digest("hex").slice(0, 24); }
function hashPassword(password, salt = randomBytes(16).toString("hex"), iterations = 120000) {
  const hash = pbkdf2Sync(String(password), salt, iterations, 32, "sha256").toString("hex");
  return `pbkdf2_sha256$${iterations}$${salt}$${hash}`;
}
function verifyPassword(password, stored = "") {
  const parts = String(stored).split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
  const [, iterText, salt, expectedHex] = parts;
  const actual = pbkdf2Sync(String(password), salt, Number(iterText), 32, "sha256");
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const eq = part.indexOf("=");
    return [decodeURIComponent(part.slice(0, eq)), decodeURIComponent(part.slice(eq + 1))];
  }));
}
function sign(value) { return createHmac("sha256", AUTH_SECRET).update(value).digest("base64url"); }
function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({ id: user.id, email: user.email, name: user.name || user.email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}
function readSession(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token || !token.includes(".")) return null;
  const [payload, signature] = token.split(".");
  if (signature !== sign(payload)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || Date.now() > data.exp) return null;
    return { id: data.id, email: data.email, name: data.name || data.email };
  } catch { return null; }
}
function setSessionCookie(req, res, user) {
  res.cookie(SESSION_COOKIE, makeSession(user), { httpOnly: true, secure: req.secure || req.get("x-forwarded-proto") === "https", sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000, path: "/" });
}
function clearSessionCookie(res) { res.clearCookie(SESSION_COOKIE, { path: "/" }); }
function safeReturnTo(value) { const clean = String(value || "/dashboard"); return clean.startsWith("/") ? clean : "/dashboard"; }
function requireAuth(req, res, next) {
  const user = readSession(req);
  if (!user) {
    if (req.path.startsWith("/api/")) return res.status(401).json({ ok: false, error: "Sign in required." });
    return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl || "/dashboard")}`);
  }
  req.user = user;
  next();
}
async function findUserByEmail(email) {
  const clean = normalizeEmail(email);
  if (!clean) return null;
  await authReady();
  if (hasDb()) {
    const result = await db().query("SELECT id, email, name, password_hash FROM app_users WHERE email = $1 LIMIT 1", [clean]);
    return result.rows[0] || null;
  }
  return memoryUsers.get(clean) || null;
}
async function createUser({ email, name, password }) {
  const clean = normalizeEmail(email);
  if (!clean || !clean.includes("@")) throw new Error("Please enter a valid email address.");
  if (String(password || "").length < 8) throw new Error("Password must be at least 8 characters.");
  await authReady();
  const existing = await findUserByEmail(clean);
  if (existing) throw new Error("An account already exists for that email. Sign in instead.");
  const user = { id: userIdFor(clean), email: clean, name: String(name || clean.split("@")[0] || "User"), password_hash: hashPassword(password) };
  if (hasDb()) await db().query("INSERT INTO app_users (id, email, name, password_hash) VALUES ($1, $2, $3, $4)", [user.id, user.email, user.name, user.password_hash]);
  else memoryUsers.set(clean, user);
  return { id: user.id, email: user.email, name: user.name };
}
async function authenticateUser(email, password) {
  const user = await findUserByEmail(email);
  if (!user || !verifyPassword(password, user.password_hash)) throw new Error("Invalid email or password.");
  return { id: user.id, email: user.email, name: user.name || user.email };
}

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
  return result.rows[0] || virtualSite(clean);
}
async function getEvents(siteId, limit = 750) {
  const memory = memoryEvents.filter((e) => !siteId || e.site_id === siteId || e.dashboard_token === siteId).slice(0, limit);
  if (!hasDb()) return memory;
  try {
    const info = await tableInfo("events_raw");
    const c = cols(info);
    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
    if (!siteCol) return memory;
    const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
    const result = await db().query(`SELECT * FROM events_raw WHERE ${q(siteCol)}::text = $1 ${order} LIMIT $2`, [String(siteId), Number(limit)]);
    return [...memory, ...result.rows];
  } catch { return memory; }
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
  const memory = memoryLeads.filter((lead) => !siteId || lead.site_id === siteId || lead.site_slug === siteId || lead.dashboard_token === siteId).slice(0, limit);
  if (!hasDb()) return memory;
  try {
    const info = await tableInfo("crm_leads");
    const c = cols(info);
    if (!c.length) return memory;
    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "received_at", "inserted_at"]);
    const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
    let rows = [];
    if (siteCol) rows = (await db().query(`SELECT * FROM crm_leads WHERE ${q(siteCol)}::text = $1 ${order} LIMIT $2`, [String(siteId), Number(limit)])).rows;
    else rows = (await db().query(`SELECT * FROM crm_leads ${order} LIMIT $1`, [Number(limit)])).rows;
    return [...memory, ...rows];
  } catch { return memory; }
}
function demoPayload() {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, "dashboard/data"), "utf8")); }
  catch {
    return { ok: true, usingFallback: true, dbConnected: hasDb(), site: { site_id: "demo", site_name: "Constrava Demo", owner_email: "admin@constravaai.com", plan: "demo", token: "demo" }, summary: { total: 0, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0, sessions: 0, avgDurationSeconds: 0, bounceRate: 0, days: [], typeCounts: [], pageCounts: [], sources: [], devices: [] }, reports: [], recentEvents: [], leads: [] };
  }
}
function summarize(events) {
  let visits = 0, leads = 0, purchases = 0, clicks = 0, revenue = 0, engagementSeconds = 0;
  const typeCounts = new Map(), pageCounts = new Map(), sourceCounts = new Map(), dayMetrics = new Map(), deviceCounts = new Map(), sessions = new Set(), bouncedSessions = new Set(), sessionViews = new Map();
  for (const event of events) {
    const type = eventType(event).toLowerCase();
    const pathName = cleanPath(eventPath(event));
    const day = eventTime(event) ? String(eventTime(event)).slice(0, 10) : new Date().toISOString().slice(0, 10);
    const amount = eventAmount(event);
    const source = String(valueFrom(event, ["source", "utm_source", "referrer", "campaign"], "Direct") || "Direct");
    const device = String(valueFrom(event, ["device", "device_type", "platform"], "Desktop") || "Desktop");
    const session = String(valueFrom(event, ["session_id", "sid", "visitor", "visitor_id", "anonymous_id"], "") || "");
    if (session) { sessions.add(session); sessionViews.set(session, (sessionViews.get(session) || 0) + (type.includes("page") || type.includes("view") ? 1 : 0)); }
    if (!dayMetrics.has(day)) dayMetrics.set(day, { day, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0 });
    const bucket = dayMetrics.get(day);
    typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    pageCounts.set(pathName, (pageCounts.get(pathName) || 0) + 1);
    sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    deviceCounts.set(device, (deviceCounts.get(device) || 0) + 1);
    if (type.includes("page") || type.includes("visit") || type.includes("view")) { visits++; bucket.visits++; }
    if (type.includes("lead") || type.includes("form") || type.includes("contact") || type.includes("conversion")) { leads++; bucket.leads++; }
    if (type.includes("purchase") || type.includes("sale") || type.includes("checkout")) { purchases++; revenue += amount || 129; bucket.purchases++; bucket.revenue += amount || 129; }
    if (type.includes("cta") || type.includes("click")) { clicks++; bucket.clicks++; }
    if (type.includes("engagement")) engagementSeconds += Number(valueFrom(event, ["duration", "duration_seconds", "seconds"], 0)) || 0;
  }
  for (const [session, views] of sessionViews.entries()) if (views <= 1) bouncedSessions.add(session);
  const totalDevices = [...deviceCounts.values()].reduce((a, b) => a + b, 0) || 1;
  const sessionCount = sessions.size || Math.max(1, Math.round(visits * 0.62));
  return { total: events.length, visits, leads, purchases, clicks, revenue, sessions: sessionCount, avgDurationSeconds: engagementSeconds ? Math.round(engagementSeconds / sessionCount) : events.length ? 110 : 0, bounceRate: sessions.size ? Math.round((bouncedSessions.size / sessions.size) * 100) : events.length ? 24 : 0, days: [...dayMetrics.values()].sort((a, b) => a.day.localeCompare(b.day)), typeCounts: [...typeCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), pageCounts: [...pageCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), sources: [...sourceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8), devices: [...deviceCounts.entries()].map(([name, value]) => [name, Math.round((value / totalDevices) * 100)]) };
}
function mapLead(lead) {
  return { name: String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead")), email: String(valueFrom(lead, ["email", "lead_email", "contact_email"], "lead@example.com")), company: String(valueFrom(lead, ["company", "organization", "business"], "Demo Company")), status: String(valueFrom(lead, ["status", "stage", "lead_status"], "New")), source: String(valueFrom(lead, ["source", "channel", "campaign"], "CRM")), value: Number(valueFrom(lead, ["value", "deal_value", "amount", "budget"], 0)) || 0, notes: String(valueFrom(lead, ["notes", "message", "body", "description"], "")), created_at: String(valueFrom(lead, ["created_at", "timestamp", "received_at", "inserted_at"], new Date().toISOString())) };
}
async function getDashboardPayload(token) {
  const demo = demoPayload();
  const site = await findSiteByToken(token);
  const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token || "demo"));
  const [events, reports, rawLeads] = await Promise.all([getEvents(siteId), getReports(siteId), getCrmLeads(siteId)]);
  if (!events.length && !rawLeads.length) return { ...demo, dbConnected: hasDb(), site: { ...demo.site, site_id: siteId, token } };
  const summary = summarize(events);
  const leads = rawLeads.length ? rawLeads.map(mapLead) : demo.leads;
  return { ...demo, usingFallback: false, dbConnected: hasDb(), site: { ...demo.site, site_id: siteId, token }, summary, leads, reports: reports.length ? reports : demo.reports, recentEvents: events.slice(0, 80).map((event) => ({ type: eventType(event), path: cleanPath(eventPath(event)), time: eventTime(event) || new Date().toISOString(), amount: eventAmount(event), source: valueFrom(event, ["source"], "Direct"), device: valueFrom(event, ["device"], "Desktop") })) };
}
async function insertEvent(siteId, type, options = {}) {
  const payload = { ...options, site_id: siteId, type, event_type: type, path: cleanPath(options.path || options.url || "/"), source: options.source || sourceFrom(options.referrer), device: options.device || deviceFrom(options.user_agent), amount: Number(options.amount || options.value || 0), created_at: options.created_at || new Date().toISOString() };
  memoryEvents.unshift(payload);
  while (memoryEvents.length > 1000) memoryEvents.pop();
  if (!hasDb()) return false;
  try {
    const info = await tableInfo("events_raw");
    const c = cols(info);
    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    if (!siteCol) return false;
    const typeCol = firstExisting(c, ["event_name", "event_type", "type", "name", "event", "action"]);
    const pathCol = firstExisting(c, ["path", "url", "page", "pathname", "href", "route"]);
    const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
    const payloadCol = firstExisting(c, ["payload", "metadata", "data", "properties"]);
    const amountCol = firstExisting(c, ["amount", "revenue", "value", "price", "total"]);
    const sourceCol = firstExisting(c, ["source", "utm_source", "referrer", "campaign"]);
    const sessionCol = firstExisting(c, ["session_id", "sid", "visitor", "visitor_id", "anonymous_id"]);
    const insertCols = [], values = [];
    const add = (col, value) => { if (col && c.includes(col) && !insertCols.includes(col)) { insertCols.push(col); values.push(value); } };
    add(siteCol, String(siteId)); add(typeCol, type); add(pathCol, payload.path); add(timeCol, new Date(payload.created_at)); add(amountCol, payload.amount); add(sourceCol, payload.source); add(sessionCol, payload.session_id || payload.visitor_id || "");
    if (payloadCol) add(payloadCol, isJsonColumn(info, payloadCol) ? payload : JSON.stringify(payload));
    await db().query(`INSERT INTO events_raw (${insertCols.map(q).join(", ")}) VALUES (${values.map((_, i) => `$${i + 1}`).join(", ")})`, values);
    return true;
  } catch { return false; }
}
function normalizeAnalyticsEvent(body, req) {
  const payload = body && typeof body === "object" ? body : {};
  const type = String(payload.type || payload.event_type || payload.event || "page_view");
  const dashboardToken = String(payload.dashboard_token || payload.token || req.query.token || "demo");
  return { dashboard_token: dashboardToken, type, path: cleanPath(payload.path || payload.url || req.get("referer") || "/"), title: String(payload.title || ""), referrer: String(payload.referrer || req.get("referer") || ""), source: String(payload.source || sourceFrom(payload.referrer || req.get("referer") || "")), device: String(payload.device || deviceFrom(req.get("user-agent") || "")), user_agent: String(req.get("user-agent") || ""), session_id: String(payload.session_id || ""), visitor_id: String(payload.visitor_id || ""), amount: Number(payload.amount || payload.value || 0), duration: Number(payload.duration || payload.duration_seconds || 0), metadata: payload.metadata || {}, created_at: new Date().toISOString() };
}
function normalizeFormLead(body, siteSlug, formSlug, req) {
  const payload = body && typeof body === "object" ? body : {};
  const nested = payload.form_response || payload.response || payload.data || payload.submission || payload.answers || payload.fields || {};
  const pick = (...names) => { for (const name of names) { if (payload[name] !== undefined && payload[name] !== null && payload[name] !== "") return payload[name]; if (nested[name] !== undefined && nested[name] !== null && nested[name] !== "") return nested[name]; } return ""; };
  const firstName = pick("first_name", "firstName", "firstname", "First Name");
  const lastName = pick("last_name", "lastName", "lastname", "Last Name");
  const combinedName = pick("name", "full_name", "fullName", "lead_name", "contact_name", "Name") || [firstName, lastName].filter(Boolean).join(" ");
  const email = pick("email", "Email", "email_address", "emailAddress", "contact_email");
  const company = pick("company", "Company", "organization", "business", "business_name") || "External Form Lead";
  const message = pick("message", "Message", "notes", "Notes", "body", "comments", "description");
  const value = Number(pick("value", "budget", "deal_value", "amount", "estimated_value") || 0);
  const now = new Date().toISOString();
  return { lead_id: "FORM-" + randomBytes(5).toString("hex").toUpperCase(), record_type: "external_form_lead", module: "leads", site_id: siteSlug, site_slug: siteSlug, form_slug: formSlug, dashboard_token: String(pick("dashboard_token", "token") || siteSlug), name: String(combinedName || email || "External Form Lead"), email: String(email || ""), phone: String(pick("phone", "Phone", "phone_number", "mobile") || ""), company: String(company), title: String(pick("title", "role", "job_title") || "External Form Lead"), source: String(pick("source", "platform", "provider", "utm_source") || req.get("x-form-provider") || "External Form"), owner: String(pick("owner") || "Constrava Demo Team"), status: String(pick("status", "stage") || "New"), priority: String(pick("priority") || "High"), deal_name: String(pick("deal_name", "project", "service") || `${company} form inquiry`), value: Number.isFinite(value) ? value : 0, probability: 35, expected_revenue: Number.isFinite(value) ? Math.round(value * 0.35) : 0, close_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10), created_at: now, last_contacted: now.slice(0, 10), tags: ["external-form", String(siteSlug), String(formSlug)], notes: String(message || "Submitted through external form intake."), raw_submission: payload };
}
async function insertCrmLead(siteId, lead) {
  memoryLeads.unshift(lead);
  while (memoryLeads.length > 250) memoryLeads.pop();
  if (!hasDb()) return false;
  try {
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
  } catch { return false; }
}
function reportText(summary) { return `Constrava AI Report\n\nTraffic: ${summary.visits} visits, ${summary.leads} leads, ${summary.purchases} purchases.\nLead conversion: ${summary.visits ? ((summary.leads / summary.visits) * 100).toFixed(2) : "0.00"}%.\nRecommendation: follow up with qualified and proposal-stage CRM leads first.`; }
function servePage(fileName, fallbackHtml) { return (req, res) => res.sendFile(path.join(__dirname, fileName), (err) => { if (err) res.status(200).send(fallbackHtml); }); }
function removeVendorReferences(html) { return String(html || "").replace(/Zoho[-\s]*style\s*/gi, "custom ").replace(/\bZoho\b/gi, "CRM"); }
function cors(res) { res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-constrava-key, x-form-provider"); }
function isPrivateRequest(req) { return Boolean(readSession(req)) || String(req.query.private || "") === "1" || String(req.get("x-constrava-private") || "") === "1"; }
function requirePrivate(req, res) { if (!isPrivateRequest(req)) { res.status(403).json({ ok: false, error: "Sign in required for this connector." }); return false; } return true; }
function appBase(req) { return `${req.protocol}://${req.get("host")}`; }
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
    headers: { "x-constrava-key": CONSTRAVA_KEY, "x-form-provider": "Google Forms" },
    payload: JSON.stringify(data)
  });
}

// In Apps Script: Triggers → Add Trigger → choose onFormSubmit → event type: On form submit.`;
}
function trackerScript(req) {
  const defaultToken = esc(req.query.token || "demo");
  return `(function(){
  if(window.ConstravaAnalyticsLoaded)return;window.ConstravaAnalyticsLoaded=true;
  var s=document.currentScript||{};
  var token=(s.getAttribute&&s.getAttribute('data-token'))||new URLSearchParams(location.search).get('token')||'${defaultToken}';
  var endpoint=(s.src?new URL('/events',s.src).href:location.origin+'/events');
  var vid=localStorage.getItem('cx_visitor_id')||('v_'+Math.random().toString(16).slice(2)+Date.now().toString(16));
  localStorage.setItem('cx_visitor_id',vid);
  var sid=sessionStorage.getItem('cx_session_id')||('s_'+Math.random().toString(16).slice(2)+Date.now().toString(16));
  sessionStorage.setItem('cx_session_id',sid);
  var started=Date.now();
  function device(){return /Mobi|Android|iPhone/i.test(navigator.userAgent)?'Mobile':(/iPad|Tablet/i.test(navigator.userAgent)?'Tablet':'Desktop');}
  function send(type,data){
    var body=JSON.stringify(Object.assign({dashboard_token:token,type:type,path:location.pathname,url:location.href,title:document.title,referrer:document.referrer,visitor_id:vid,session_id:sid,device:device(),created_at:new Date().toISOString()},data||{}));
    if(navigator.sendBeacon){try{navigator.sendBeacon(endpoint,new Blob([body],{type:'application/json'}));return;}catch(e){}}
    fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:body,keepalive:true}).catch(function(){});
  }
  window.ConstravaTrack=send;
  window.ConstravaConversion=function(name,value,data){send(name||'conversion',Object.assign({amount:value||0},data||{}));};
  send('page_view');
  document.addEventListener('click',function(e){var el=e.target.closest('a,button,[data-track],[data-cx-track]');if(!el)return;send('cta_click',{metadata:{text:(el.innerText||el.getAttribute('aria-label')||el.href||'').slice(0,120),href:el.href||'',id:el.id||'',className:el.className||''}});},true);
  document.addEventListener('submit',function(e){send('form_submit',{metadata:{id:e.target.id||'',action:e.target.action||'',name:e.target.getAttribute('name')||''}});},true);
  window.addEventListener('beforeunload',function(){send('engagement',{duration:Math.round((Date.now()-started)/1000)});});
})();`;
}
async function userRecords(userId) {
  await authReady();
  if (hasDb()) {
    const result = await db().query("SELECT record FROM app_crm_records WHERE user_id = $1 AND deleted_at IS NULL ORDER BY updated_at DESC", [userId]);
    return result.rows.map((row) => row.record);
  }
  return Array.from((memoryCrmRecords.get(userId) || new Map()).values());
}
async function saveUserRecord(userId, record) {
  const clean = record && typeof record === "object" ? record : {};
  const recordId = String(clean.record_id || clean.id || makeToken("rec"));
  const saved = { ...clean, record_id: recordId, id: clean.id || recordId, updated_at: new Date().toISOString() };
  await authReady();
  if (hasDb()) {
    await db().query("INSERT INTO app_crm_records (user_id, record_id, record, deleted_at, updated_at) VALUES ($1, $2, $3::jsonb, NULL, NOW()) ON CONFLICT (user_id, record_id) DO UPDATE SET record = EXCLUDED.record, deleted_at = NULL, updated_at = NOW()", [userId, recordId, JSON.stringify(saved)]);
  } else {
    if (!memoryCrmRecords.has(userId)) memoryCrmRecords.set(userId, new Map());
    memoryCrmRecords.get(userId).set(recordId, saved);
  }
  return saved;
}
async function deleteUserRecord(userId, recordId) {
  await authReady();
  if (hasDb()) await db().query("UPDATE app_crm_records SET deleted_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND record_id = $2", [userId, String(recordId)]);
  else if (memoryCrmRecords.has(userId)) memoryCrmRecords.get(userId).delete(String(recordId));
}

app.get("/health", (req, res) => res.status(200).send("ok"));
app.get("/db-test", async (req, res) => { try { if (!hasDb()) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set." }); const result = await db().query("SELECT NOW() AS now"); res.json({ ok: true, now: result.rows[0].now }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });

app.get("/login", servePage("login.html", "<h1>Constrava Sign In</h1>"));
app.post("/auth/signup", async (req, res) => { try { const user = await createUser(req.body || {}); setSessionCookie(req, res, user); res.json({ ok: true, user, redirect: safeReturnTo(req.body?.returnTo || "/dashboard") }); } catch (err) { res.status(400).json({ ok: false, error: err.message || "Could not create account." }); } });
app.post("/auth/login", async (req, res) => { try { const user = await authenticateUser(req.body?.email, req.body?.password); setSessionCookie(req, res, user); res.json({ ok: true, user, redirect: safeReturnTo(req.body?.returnTo || "/dashboard") }); } catch (err) { res.status(401).json({ ok: false, error: err.message || "Sign in failed." }); } });
app.get("/logout", (req, res) => { clearSessionCookie(res); res.redirect("/"); });
app.get("/api/auth/me", (req, res) => { const user = readSession(req); if (!user) return res.status(401).json({ ok: false, user: null }); res.json({ ok: true, user }); });
app.get("/api/crm/records", requireAuth, async (req, res) => { try { res.json({ ok: true, records: await userRecords(req.user.id) }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/api/crm/records", requireAuth, async (req, res) => { try { const record = await saveUserRecord(req.user.id, req.body?.record || req.body || {}); res.json({ ok: true, record }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.delete("/api/crm/records/:recordId", requireAuth, async (req, res) => { try { await deleteUserRecord(req.user.id, req.params.recordId); res.json({ ok: true }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });

app.get("/analytics/install", (req, res) => { const token = esc(req.query.token || "demo"); res.type("html").send(`<h1>Constrava Analytics Install</h1><p>Paste this before the closing body tag of a tracked site:</p><pre>&lt;script async src="${CANONICAL_ORIGIN}/tracker.js" data-token="${token}"&gt;&lt;/script&gt;</pre>`); });
app.get("/tracker.js", (req, res) => { res.type("application/javascript"); res.setHeader("Cache-Control", "public, max-age=60"); res.send(trackerScript(req)); });
app.options("/events", (req, res) => { cors(res); res.status(204).end(); });
app.post("/events", async (req, res) => { cors(res); try { const event = normalizeAnalyticsEvent(req.body || {}, req); const site = await findSiteByToken(event.dashboard_token); const siteId = String(valueFrom(site || virtualSite(event.dashboard_token), ["site_id", "id"], event.dashboard_token)); const stored = await insertEvent(siteId, event.type, event); res.json({ ok: true, stored, site_id: siteId, received: event.type }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Event ingestion failed." }); } });
app.post("/dashboard/simulate", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "demo"); const type = String(req.query.type || req.body?.type || "page_view"); const site = await findSiteByToken(token); const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token)); const stored = await insertEvent(siteId, type, { source: "dashboard", path: req.body?.path || "/dashboard", dashboard_token: token }); res.json({ ok: true, type, site_id: siteId, stored }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/seed", async (req, res) => { try { const token = String(req.query.token || req.body?.token || "demo"); const site = await findSiteByToken(token); const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token)); let inserted = 0; for (const type of ["page_view", "cta_click", "lead", "purchase", "page_view", "lead"]) { await insertEvent(siteId, type, { source: "seed", path: type === "purchase" ? "/checkout" : type === "lead" ? "/contact" : "/", dashboard_token: token }); inserted++; } res.json({ ok: true, inserted, message: "Demo analytics data seeded." }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.post("/dashboard/report", async (req, res) => { try { const payload = await getDashboardPayload(String(req.query.token || req.body?.token || "demo")); res.json({ ok: true, report: reportText(payload.summary), stored: false }); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/dashboard/export.csv", async (req, res) => { const payload = await getDashboardPayload(String(req.query.token || "demo")); const rows = [["type", "path", "time", "amount", "source", "device"], ...(payload.recentEvents || []).map((e) => [e.type, e.path, e.time, String(e.amount || 0), e.source || "", e.device || ""] )]; const csv = rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n"); res.setHeader("Content-Type", "text/csv"); res.setHeader("Content-Disposition", "attachment; filename=constrava-dashboard-events.csv"); res.send(csv); });
app.get("/dashboard", requireAuth, (req, res) => { try { const filePath = path.join(__dirname, "dashboard.html"); const html = removeVendorReferences(fs.readFileSync(filePath, "utf8")); res.type("html").send(html); } catch { res.status(200).send("<h1>Constrava Dashboard</h1><p>dashboard.html is missing.</p>"); } });
app.get("/crm", (req, res) => res.redirect("/dashboard"));
app.get("/dashboard/data", requireAuth, async (req, res) => { try { const payload = await getDashboardPayload(String(req.query.token || "demo")); res.json(payload); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/api/dashboard", requireAuth, async (req, res) => { try { res.json(await getDashboardPayload(String(req.query.token || "demo"))); } catch (err) { res.status(500).json({ ok: false, error: err.message }); } });
app.get("/reports/latest", requireAuth, async (req, res) => { const payload = await getDashboardPayload(String(req.query.token || "demo")); res.json({ ok: true, report: payload.reports[0] || { date: new Date().toISOString(), text: reportText(payload.summary) } }); });
app.get("/live", requireAuth, async (req, res) => { const payload = await getDashboardPayload(String(req.query.token || "demo")); res.json({ ok: true, events: payload.recentEvents, summary: payload.summary }); });

app.get("/auth/google/forms/start", (req, res) => {
  if (!requirePrivate(req, res)) return;
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return res.status(501).type("html").send("<h1>Google Forms OAuth is not configured</h1><p>Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render, then add this callback URL in Google Cloud:</p><pre>" + esc(googleRedirectUri(req)) + "</pre>");
  const state = encodeState({ siteSlug: req.query.siteSlug || "google-forms-site", formSlug: req.query.formSlug || "google-form", token: req.query.token || "demo", returnTo: safeReturnTo(req.query.returnTo), nonce: makeToken("state") });
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", process.env.GOOGLE_CLIENT_ID || "");
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
app.get("/api/google/forms/list", async (req, res) => { if (!requirePrivate(req, res)) return; res.json({ ok: true, forms: [], connection: { connection_id: String(req.query.connectionId || ""), account: "Google account" }, note: "Google OAuth form listing is temporarily disabled. Generate Apps Script manually." }); });
app.get("/api/google/forms/apps-script", (req, res) => { if (!requirePrivate(req, res)) return; const siteSlug = String(req.query.siteSlug || "google-forms-site"); const formSlug = String(req.query.formSlug || "google-form"); const endpoint = `${CANONICAL_ORIGIN}/api/forms/intake/${encodeURIComponent(siteSlug)}/${encodeURIComponent(formSlug)}`; const key = String(req.query.key || `cx_${siteSlug.replace(/[^a-z0-9]+/gi, "_")}_${formSlug.replace(/[^a-z0-9]+/gi, "_")}_google`); res.type("text/plain").send(googleAppsScript(siteSlug, formSlug, endpoint, key)); });
app.options("/api/forms/intake/:siteSlug/:formSlug", (req, res) => { cors(res); res.status(204).end(); });
app.post("/api/forms/intake/:siteSlug/:formSlug", async (req, res) => { cors(res); try { const siteSlug = String(req.params.siteSlug || "external-site"); const formSlug = String(req.params.formSlug || "external-form"); const lead = normalizeFormLead(req.body || {}, siteSlug, formSlug, req); const crmStored = await insertCrmLead(siteSlug, lead); const eventStored = await insertEvent(siteSlug, "form_lead", { source: lead.source, path: `/forms/${formSlug}`, amount: lead.value, lead, dashboard_token: lead.dashboard_token }); res.json({ ok: true, message: "Form submission received and converted into a CRM lead.", lead_id: lead.lead_id, crm_stored: crmStored, event_stored: eventStored, session_stored: true, lead }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Form intake failed." }); } });
app.post("/api/lead", async (req, res) => { try { const { name, email, message, website } = req.body || {}; if (website && String(website).trim() !== "") return res.json({ ok: true }); if (!name || !email || !message) return res.status(400).json({ ok: false, error: "Please include name, email, and message." }); await insertEvent("demo", "lead", { source: "contact_form", path: "/contact", metadata: { name, email }, dashboard_token: "demo" }); if (!process.env.RESEND_API_KEY || !FROM_EMAIL) return res.json({ ok: true, warning: "Lead received. Email is not configured." }); await resend.emails.send({ from: FROM_EMAIL, to: TO_EMAIL, replyTo: email, subject: `Constrava Request — ${esc(name)}`, html: `<p><b>Name:</b> ${esc(name)}</p><p><b>Email:</b> ${esc(email)}</p><pre>${esc(message)}</pre>` }); res.json({ ok: true }); } catch { res.status(500).json({ ok: false, error: "Lead send failed." }); } });
app.post("/sites", async (req, res) => { const dashboardToken = String(req.body?.dashboard_token || req.body?.token || makeToken("dash")); res.json({ ok: true, site_id: String(req.body?.site_id || makeToken("site")), dashboard_token: dashboardToken, dashboard_url: `/dashboard`, tracker_script: `<script async src="${CANONICAL_ORIGIN}/tracker.js" data-token="${esc(dashboardToken)}"></script>` }); });

app.get("/", servePage("index.html", "<h1>Constrava</h1><p><a href='/login'>Sign in</a></p>"));
app.get("/services", servePage("services.html", "<h1>Constrava Services</h1>"));
app.get("/process", servePage("process.html", "<h1>Constrava Process</h1>"));
app.get("/work", servePage("work.html", "<h1>Constrava Work</h1>"));
app.get("/contact", servePage("contact.html", "<h1>Contact Constrava</h1>"));
app.use((req, res) => res.status(404).send("<h1>404</h1><p>Route not found.</p>"));
app.listen(PORT, () => console.log("Constrava running on port", PORT));
