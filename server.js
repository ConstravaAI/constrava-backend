import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";
import { Resend } from "resend";
import { Pool } from "pg";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(express.json({ limit: "400kb" }));
app.use(express.urlencoded({ extended: true, limit: "400kb" }));
app.use(express.static(__dirname));

const resend = new Resend(process.env.RESEND_API_KEY || "missing-key");
const TO_EMAIL = process.env.TO_EMAIL || "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "";
const PORT = process.env.PORT || 3000;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.PGSSLMODE === "disable"
          ? false
          : { rejectUnauthorized: false },
    })
  : null;

const columnCache = new Map();

function db() {
  if (!pool) {
    throw new Error("Missing DATABASE_URL. Add your Neon connection string in Render Environment Variables.");
  }
  return pool;
}

function hasDb() {
  return Boolean(pool);
}

function q(name) {
  return `"${String(name).replaceAll('"', '""')}"`;
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fmt(num) {
  return new Intl.NumberFormat("en-US").format(Math.round(Number(num || 0)));
}

function money(num, digits = 0) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(Number(num || 0));
}

function pct(part, whole, digits = 2) {
  const p = Number(part || 0);
  const w = Number(whole || 0);
  if (!w) return "0.00";
  return ((p / w) * 100).toFixed(digits);
}

function safeJson(value) {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function firstExisting(cols, names) {
  return names.find((name) => cols.includes(name));
}

async function tableInfo(tableName) {
  if (!hasDb()) return [];
  if (columnCache.has(tableName)) return columnCache.get(tableName);

  const result = await db().query(
    `SELECT column_name, data_type, udt_name, is_nullable, column_default
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1
     ORDER BY ordinal_position`,
    [tableName]
  );

  const info = result.rows;
  columnCache.set(tableName, info);
  return info;
}

function cols(info) {
  return info.map((c) => c.column_name);
}

function column(info, name) {
  return info.find((c) => c.column_name === name);
}

function isJsonColumn(info, name) {
  const c = column(info, name);
  return c && ["json", "jsonb"].includes(c.udt_name);
}

function isTextLikeColumn(info, name) {
  const c = column(info, name);
  return !c || ["text", "varchar", "bpchar", "uuid"].includes(c.udt_name);
}

function valueFrom(row, names, fallback = "") {
  for (const name of names) {
    if (row && row[name] !== undefined && row[name] !== null && row[name] !== "") {
      return row[name];
    }

    for (const key of ["payload", "metadata", "data", "properties"]) {
      if (
        row &&
        row[key] &&
        typeof row[key] === "object" &&
        row[key][name] !== undefined &&
        row[key][name] !== null &&
        row[key][name] !== ""
      ) {
        return row[key][name];
      }
    }
  }

  return fallback;
}

function eventType(event) {
  return String(valueFrom(event, ["event_type", "type", "name", "event", "action"], "event"));
}

function eventPath(event) {
  return String(valueFrom(event, ["path", "url", "page", "pathname", "href", "route"], "/"));
}

function eventTime(event) {
  return String(valueFrom(event, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"], ""));
}

function eventAmount(event) {
  const n = Number(valueFrom(event, ["amount", "revenue", "value", "price", "total"], 0));
  return Number.isFinite(n) ? n : 0;
}

function makeToken(prefix = "cx") {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}

function virtualSite(token = "demo") {
  return {
    id: token,
    site_id: token,
    site_name: "Constrava Demo",
    name: "Constrava Demo",
    owner_email: "admin@constrava.com",
    plan: "demo",
    dashboard_token: token,
  };
}

async function findSiteByToken(token) {
  const cleanToken = String(token || "").trim();
  if (!cleanToken) return null;

  if (!hasDb()) return virtualSite(cleanToken);

  const info = await tableInfo("sites");
  const c = cols(info);

  if (!c.length) return virtualSite(cleanToken);

  const tokenColumns = [
    "dashboard_token",
    "token",
    "demo_token",
    "access_token",
    "public_token",
    "site_token",
    "id",
    "site_id",
  ].filter((name) => c.includes(name));

  if (!tokenColumns.length) return virtualSite(cleanToken);

  const where = tokenColumns.map((col) => `${q(col)}::text = $1`).join(" OR ");
  const result = await db().query(`SELECT * FROM sites WHERE ${where} LIMIT 1`, [cleanToken]);

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

async function getEvents(siteId, limit = 750) {
  if (!hasDb()) return [];

  const info = await tableInfo("events_raw");
  const c = cols(info);
  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);

  if (!siteCol) return [];

  const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
  const result = await db().query(
    `SELECT * FROM events_raw
     WHERE ${q(siteCol)}::text = $1
     ${order}
     LIMIT $2`,
    [String(siteId), Number(limit)]
  );

  return result.rows;
}

async function getReports(siteId, limit = 10) {
  if (!hasDb()) return [];

  const info = await tableInfo("daily_reports");
  const c = cols(info);
  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  const timeCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);

  if (!siteCol) return [];

  const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";
  const result = await db().query(
    `SELECT * FROM daily_reports
     WHERE ${q(siteCol)}::text = $1
     ${order}
     LIMIT $2`,
    [String(siteId), Number(limit)]
  );

  return result.rows;
}

async function getCrmLeads(siteId, limit = 50) {
  if (!hasDb()) return [];

  try {
    const info = await tableInfo("crm_leads");
    const c = cols(info);
    if (!c.length) return [];

    const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
    const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "received_at", "inserted_at"]);
    const order = timeCol ? `ORDER BY ${q(timeCol)} DESC` : "";

    if (siteCol) {
      const result = await db().query(
        `SELECT * FROM crm_leads
         WHERE ${q(siteCol)}::text = $1
         ${order}
         LIMIT $2`,
        [String(siteId), Number(limit)]
      );
      return result.rows;
    }

    const result = await db().query(`SELECT * FROM crm_leads ${order} LIMIT $1`, [Number(limit)]);
    return result.rows;
  } catch (err) {
    console.warn("CRM leads unavailable:", err.message);
    return [];
  }
}

function fallbackSummary() {
  return {
    total: 24968,
    visits: 18426,
    leads: 1284,
    purchases: 392,
    clicks: 2781,
    revenue: 24680,
    sessions: 10942,
    avgDurationSeconds: 102,
    bounceRate: 31,
    days: [
      { day: "2025-05-10", visits: 1680, leads: 104, purchases: 29, clicks: 248, revenue: 1827 },
      { day: "2025-05-11", visits: 2410, leads: 162, purchases: 45, clicks: 362, revenue: 2835 },
      { day: "2025-05-12", visits: 2875, leads: 190, purchases: 58, clicks: 441, revenue: 3654 },
      { day: "2025-05-13", visits: 2180, leads: 146, purchases: 43, clicks: 337, revenue: 2709 },
      { day: "2025-05-14", visits: 3120, leads: 218, purchases: 68, clicks: 496, revenue: 4284 },
      { day: "2025-05-15", visits: 3456, leads: 253, purchases: 79, clicks: 531, revenue: 4977 },
      { day: "2025-05-16", visits: 2690, leads: 211, purchases: 70, clicks: 366, revenue: 4410 },
    ],
    typeCounts: [
      ["page_view", 18426],
      ["cta_click", 2781],
      ["lead", 1284],
      ["purchase", 392],
      ["pricing_view", 1188],
      ["contact_open", 904],
    ],
    pageCounts: [
      ["/", 6820],
      ["/services", 4210],
      ["/contact", 1984],
      ["/work", 1432],
      ["/process", 1130],
      ["/dashboard", 914],
    ],
    sources: [
      ["Direct", 6580],
      ["Search", 5210],
      ["Social", 3842],
      ["Referral", 2794],
    ],
    devices: [
      ["Desktop", 59],
      ["Mobile", 34],
      ["Tablet", 7],
    ],
  };
}

function summarize(events) {
  let visits = 0;
  let leads = 0;
  let purchases = 0;
  let clicks = 0;
  let revenue = 0;
  let sessions = new Set();

  const typeCounts = new Map();
  const pageCounts = new Map();
  const sourceCounts = new Map();
  const dayMetrics = new Map();
  const deviceCounts = new Map();

  for (const event of events) {
    const type = eventType(event).toLowerCase();
    const pathName = eventPath(event);
    const time = eventTime(event);
    const day = time ? String(time).slice(0, 10) : new Date().toISOString().slice(0, 10);
    const amount = eventAmount(event);
    const source = String(valueFrom(event, ["source", "utm_source", "referrer", "campaign"], "Direct") || "Direct");
    const device = String(valueFrom(event, ["device", "device_type", "platform"], "Desktop") || "Desktop");
    const session = String(valueFrom(event, ["session_id", "sid", "visitor", "visitor_id", "anonymous_id"], "") || "");

    if (session) sessions.add(session);

    if (!dayMetrics.has(day)) {
      dayMetrics.set(day, { day, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0 });
    }

    const bucket = dayMetrics.get(day);

    typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    pageCounts.set(pathName, (pageCounts.get(pathName) || 0) + 1);
    sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
    deviceCounts.set(device, (deviceCounts.get(device) || 0) + 1);

    if (type.includes("page") || type.includes("visit") || type.includes("view")) {
      visits++;
      bucket.visits++;
    }

    if (type.includes("lead") || type.includes("form") || type.includes("contact")) {
      leads++;
      bucket.leads++;
    }

    if (type.includes("purchase") || type.includes("sale") || type.includes("checkout")) {
      purchases++;
      revenue += amount || 129;
      bucket.purchases++;
      bucket.revenue += amount || 129;
    }

    if (type.includes("cta") || type.includes("click")) {
      clicks++;
      bucket.clicks++;
    }
  }

  const totalDevices = [...deviceCounts.values()].reduce((a, b) => a + b, 0) || 1;

  return {
    total: events.length,
    visits,
    leads,
    purchases,
    clicks,
    revenue,
    sessions: sessions.size || Math.round(visits * 0.62),
    avgDurationSeconds: events.length ? 94 + Math.min(70, Math.round(events.length / 20)) : 0,
    bounceRate: events.length ? Math.max(18, 44 - Math.round(leads / Math.max(visits, 1) * 100)) : 0,
    days: [...dayMetrics.values()].sort((a, b) => a.day.localeCompare(b.day)),
    typeCounts: [...typeCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    pageCounts: [...pageCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    sources: [...sourceCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6),
    devices: [...deviceCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([name, value]) => [name, Math.round((value / totalDevices) * 100)]),
  };
}

function prepareSummary(events) {
  const live = summarize(events);
  if (!live.total) {
    return { summary: fallbackSummary(), usingFallback: true };
  }

  return { summary: live, usingFallback: false };
}

function reportText(summary) {
  const leadRate = pct(summary.leads, summary.visits);
  const purchaseRate = pct(summary.purchases, summary.visits);
  const bestDay = [...(summary.days || [])].sort((a, b) => (b.visits || 0) - (a.visits || 0))[0];

  return [
    "Constrava AI Report",
    "",
    `Traffic is showing ${fmt(summary.visits)} visits, ${fmt(summary.leads)} leads, and ${fmt(summary.purchases)} purchases in the selected window.`,
    `Lead conversion is ${leadRate}%. Purchase conversion is ${purchaseRate}%. Estimated revenue is ${money(summary.revenue)}.`,
    bestDay ? `Best traffic day: ${bestDay.day} with ${fmt(bestDay.visits)} visits.` : "",
    "",
    "Recommended next actions:",
    "1. Keep the highest-performing page or offer prominent above the fold.",
    "2. Improve the contact/lead step because small gains there create large downstream impact.",
    "3. Use CTA click behavior to identify which service package should be emphasized in the client pitch.",
  ].filter(Boolean).join("\n");
}

async function insertEvent(siteId, type, options = {}) {
  if (!hasDb()) return false;

  const info = await tableInfo("events_raw");
  const c = cols(info);

  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  const typeCol = firstExisting(c, ["event_type", "type", "name", "event", "action"]);
  const pathCol = firstExisting(c, ["path", "url", "page", "pathname", "href", "route"]);
  const timeCol = firstExisting(c, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
  const payloadCol = firstExisting(c, ["payload", "metadata", "data", "properties"]);
  const amountCol = firstExisting(c, ["amount", "revenue", "value", "price", "total"]);
  const userAgentCol = firstExisting(c, ["user_agent", "ua"]);
  const ipCol = firstExisting(c, ["ip", "ip_address", "ip_hash"]);
  const referrerCol = firstExisting(c, ["referrer", "referer"]);

  if (!siteCol) throw new Error("events_raw needs a site_id-like column.");

  const pathName =
    options.path ||
    (type === "lead"
      ? "/contact"
      : type === "purchase"
      ? "/checkout"
      : type === "cta_click"
      ? "/services"
      : "/");

  const amount = type === "purchase" ? Number(options.amount || 129) : Number(options.amount || 0);
  const eventDate = options.time || new Date();
  const payload = {
    demo: Boolean(options.demo ?? true),
    source: options.source || "dashboard",
    event_type: type,
    type,
    path: pathName,
    amount,
    campaign: options.campaign || "client-demo",
    visitor: options.visitor || `visitor_${Math.random().toString(16).slice(2, 8)}`,
    device: options.device || "Desktop",
    url: options.url || pathName,
  };

  const insertCols = [];
  const values = [];

  function add(col, value) {
    if (!col || insertCols.includes(col)) return;
    insertCols.push(col);
    values.push(value);
  }

  add(siteCol, String(siteId));
  add(typeCol, type);
  add(pathCol, pathName);
  add(timeCol, eventDate);
  add(amountCol, amount);
  add(userAgentCol, options.userAgent || "");
  add(ipCol, options.ip || "");
  add(referrerCol, options.referrer || "");
  if (payloadCol) {
    add(payloadCol, isJsonColumn(info, payloadCol) ? payload : JSON.stringify(payload));
  }

  const sqlCols = insertCols.map(q).join(", ");
  const placeholders = values.map((_, i) => `$${i + 1}`).join(", ");

  await db().query(`INSERT INTO events_raw (${sqlCols}) VALUES (${placeholders})`, values);
  return true;
}

async function insertReport(siteId, text) {
  if (!hasDb()) return false;

  const info = await tableInfo("daily_reports");
  const c = cols(info);

  const siteCol = firstExisting(c, ["site_id", "site", "client_site_id", "project_id"]);
  const textCol = firstExisting(c, ["summary", "report", "content", "body", "insights", "ai_summary", "report_text"]);
  const dateCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);

  if (!siteCol || !textCol) return false;

  const insertCols = [];
  const values = [];

  function add(col, value) {
    if (!col || insertCols.includes(col)) return;
    insertCols.push(col);
    values.push(value);
  }

  add(siteCol, String(siteId));
  add(textCol, text);
  add(dateCol, new Date());

  const sqlCols = insertCols.map(q).join(", ");
  const placeholders = values.map((_, i) => `$${i + 1}`).join(", ");
  await db().query(`INSERT INTO daily_reports (${sqlCols}) VALUES (${placeholders})`, values);
  return true;
}

async function insertLeadRecord(siteId, leadData) {
  if (!hasDb()) return false;

  try {
    const info = await tableInfo("crm_leads");
    const c = cols(info);
    if (!c.length) return false;

    const map = {
      site_id: ["site_id", "site", "client_site_id", "project_id"],
      name: ["name", "full_name", "lead_name", "contact_name"],
      email: ["email", "lead_email", "contact_email"],
      company: ["company", "organization"],
      status: ["status", "stage", "lead_status"],
      source: ["source", "channel", "campaign"],
      notes: ["notes", "message", "body"],
      created_at: ["created_at", "timestamp", "received_at", "inserted_at"],
      payload: ["payload", "metadata", "data", "properties"],
    };

    const insertCols = [];
    const values = [];

    function add(possible, value) {
      const col = firstExisting(c, possible);
      if (!col || insertCols.includes(col)) return;
      insertCols.push(col);
      values.push(value);
    }

    add(map.site_id, String(siteId || "contact"));
    add(map.name, leadData.name || "New Lead");
    add(map.email, leadData.email || "");
    add(map.company, leadData.company || "");
    add(map.status, leadData.status || "New");
    add(map.source, leadData.source || "Website");
    add(map.notes, leadData.message || "");
    add(map.created_at, new Date());

    const payloadCol = firstExisting(c, map.payload);
    if (payloadCol) {
      add([payloadCol], isJsonColumn(info, payloadCol) ? leadData : JSON.stringify(leadData));
    }

    if (!insertCols.length) return false;

    const sqlCols = insertCols.map(q).join(", ");
    const placeholders = values.map((_, i) => `$${i + 1}`).join(", ");
    await db().query(`INSERT INTO crm_leads (${sqlCols}) VALUES (${placeholders})`, values);
    return true;
  } catch (err) {
    console.warn("CRM insert skipped:", err.message);
    return false;
  }
}

function dashboardJson(site, events, reports, leads) {
  const siteId = String(valueFrom(site, ["site_id", "id"], "demo"));
  const { summary, usingFallback } = prepareSummary(events);

  const recentEvents = events.slice(0, 40).map((event) => ({
    type: eventType(event),
    path: eventPath(event),
    time: eventTime(event),
    amount: eventAmount(event),
  }));

  const mappedReports = reports.slice(0, 10).map((report) => ({
    date: String(valueFrom(report, ["report_date", "date", "created_at", "generated_at"], "Latest report")),
    text: String(valueFrom(report, ["summary", "report", "content", "body", "insights", "ai_summary", "report_text"], "")),
  }));

  const mappedLeads = leads.slice(0, 60).map((lead) => ({
    name: String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead")),
    email: String(valueFrom(lead, ["email", "lead_email", "contact_email"], "lead@example.com")),
    company: String(valueFrom(lead, ["company", "organization"], "—")),
    status: String(valueFrom(lead, ["status", "stage", "lead_status"], "New")),
    source: String(valueFrom(lead, ["source", "channel", "campaign"], "Website")),
    created_at: String(valueFrom(lead, ["created_at", "timestamp", "received_at"], "")),
  }));

  if (usingFallback && !recentEvents.length) {
    recentEvents.push(
      { type: "page_view", path: "/", time: "2025-05-16T12:42:00Z", amount: 0 },
      { type: "cta_click", path: "/services", time: "2025-05-16T12:37:00Z", amount: 0 },
      { type: "lead", path: "/contact", time: "2025-05-16T12:31:00Z", amount: 0 },
      { type: "purchase", path: "/checkout", time: "2025-05-16T12:12:00Z", amount: 129 }
    );
  }

  if (usingFallback && !mappedLeads.length) {
    mappedLeads.push(
      { name: "Avery Morgan", email: "avery@example.com", company: "Northstar Studio", status: "Qualified", source: "Contact form", created_at: "2025-05-16" },
      { name: "Jordan Lee", email: "jordan@example.com", company: "Lee Manufacturing", status: "New", source: "Pricing CTA", created_at: "2025-05-15" },
      { name: "Sam Patel", email: "sam@example.com", company: "Patel Labs", status: "Proposal", source: "Referral", created_at: "2025-05-14" }
    );
  }

  return {
    ok: true,
    usingFallback,
    dbConnected: hasDb(),
    site: {
      site_id: siteId,
      site_name: String(valueFrom(site, ["site_name", "name", "business_name", "domain"], "Constrava Demo")),
      owner_email: String(valueFrom(site, ["owner_email", "email", "contact_email"], "admin@constrava.com")),
      plan: String(valueFrom(site, ["plan", "tier", "status"], "demo")),
      token: String(valueFrom(site, ["dashboard_token", "token", "demo_token", "access_token", "public_token", "site_token"], "")),
    },
    summary,
    reports: mappedReports,
    leads: mappedLeads,
    recentEvents,
  };
}

async function getDashboardPayload(token) {
  const site = await findSiteByToken(token);
  if (!site) return null;

  const siteId = String(valueFrom(site, ["site_id", "id"], token));
  const [events, reports, leads] = await Promise.all([
    getEvents(siteId),
    getReports(siteId),
    getCrmLeads(siteId),
  ]);

  return dashboardJson(site, events, reports, leads);
}

function servePage(fileName, fallbackHtml) {
  return (req, res) => {
    const fullPath = path.join(__dirname, fileName);
    res.sendFile(fullPath, (err) => {
      if (err) res.status(200).send(fallbackHtml);
    });
  };
}

app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

app.get("/db-test", async (req, res) => {
  try {
    if (!hasDb()) {
      return res.status(500).json({ ok: false, error: "DATABASE_URL is not set." });
    }

    const result = await db().query("SELECT NOW() AS now");
    res.json({ ok: true, now: result.rows[0].now });
  } catch (err) {
    console.error("DB TEST ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/lead", async (req, res) => {
  try {
    const {
      name,
      email,
      company,
      role,
      type,
      timeline,
      budget,
      links,
      memberCode,
      message,
      website,
    } = req.body || {};

    if (website && String(website).trim() !== "") {
      return res.json({ ok: true });
    }

    if (!name || !email || !message) {
      return res.status(400).json({ ok: false, error: "Please include name, email, and message." });
    }

    await insertLeadRecord("contact", {
      name,
      email,
      company,
      role,
      type,
      timeline,
      budget,
      links,
      memberCode,
      message,
      source: "Website contact form",
      status: "New",
    });

    if (!process.env.RESEND_API_KEY || !FROM_EMAIL) {
      console.warn("Lead stored/skipped email because RESEND_API_KEY or FROM_EMAIL is missing.");
      return res.json({ ok: true, warning: "Lead received. Email is not configured on this server." });
    }

    const subject = `Constrava Request — ${esc(name)} (${esc(type || "Project")})`;
    const html = `
      <div style="font-family:Arial,sans-serif;line-height:1.5">
        <h2>New Constrava Project Request</h2>
        <p><b>Name:</b> ${esc(name)}</p>
        <p><b>Email:</b> ${esc(email)}</p>
        <p><b>Company:</b> ${esc(company || "")}</p>
        <p><b>Role:</b> ${esc(role || "")}</p>
        <p><b>Type:</b> ${esc(type || "")}</p>
        <p><b>Timeline:</b> ${esc(timeline || "")}</p>
        <p><b>Budget:</b> ${esc(budget || "")}</p>
        <p><b>Links:</b> ${esc(links || "")}</p>
        <p><b>Member Code:</b> ${esc(memberCode || "None")}</p>
        <p><b>Message:</b></p>
        <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:10px">${esc(message || "")}</pre>
      </div>
    `;

    await resend.emails.send({
      from: FROM_EMAIL,
      to: TO_EMAIL,
      replyTo: email,
      subject,
      html,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("LEAD ERROR:", err);
    return res.status(500).json({ ok: false, error: "Lead send failed. Check Render logs." });
  }
});

app.post("/sites", async (req, res) => {
  try {
    if (!hasDb()) {
      return res.status(500).json({ ok: false, error: "DATABASE_URL is not set." });
    }

    const info = await tableInfo("sites");
    const c = cols(info);
    if (!c.length) return res.status(500).json({ ok: false, error: "sites table was not found." });

    const dashboardToken = String(req.body?.dashboard_token || req.body?.token || makeToken("dash"));
    const siteIdValue = String(req.body?.site_id || makeToken("site"));
    const name = String(req.body?.site_name || req.body?.name || "Client Demo");
    const domain = String(req.body?.domain || "");
    const ownerEmail = String(req.body?.owner_email || req.body?.email || "admin@constrava.com");

    const insertCols = [];
    const values = [];

    function add(possible, value) {
      const col = firstExisting(c, possible);
      if (!col || insertCols.includes(col)) return;
      insertCols.push(col);
      values.push(value);
    }

    add(["site_id", "id"], siteIdValue);
    add(["site_name", "name", "business_name"], name);
    add(["domain"], domain);
    add(["owner_email", "email", "contact_email"], ownerEmail);
    add(["dashboard_token", "token", "demo_token", "access_token", "public_token", "site_token"], dashboardToken);
    add(["plan", "tier", "status"], "demo");
    add(["created_at", "inserted_at"], new Date());

    if (!insertCols.length) return res.status(500).json({ ok: false, error: "No compatible sites columns were found." });

    const sqlCols = insertCols.map(q).join(", ");
    const placeholders = values.map((_, i) => `$${i + 1}`).join(", ");
    await db().query(`INSERT INTO sites (${sqlCols}) VALUES (${placeholders})`, values);

    res.json({
      ok: true,
      site_id: siteIdValue,
      dashboard_token: dashboardToken,
      dashboard_url: `/dashboard?token=${encodeURIComponent(dashboardToken)}`,
    });
  } catch (err) {
    console.error("CREATE SITE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/dashboard", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) {
      return res.status(400).json({ ok: false, error: "Missing token. Use /api/dashboard?token=YOUR_TOKEN" });
    }

    const payload = await getDashboardPayload(token);
    if (!payload) return res.status(404).json({ ok: false, error: "No site found for that token." });

    res.json(payload);
  } catch (err) {
    console.error("API DASHBOARD ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/dashboard/data", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const payload = await getDashboardPayload(token);
    if (!payload) return res.status(404).json({ ok: false, error: "Site not found." });

    res.json(payload);
  } catch (err) {
    console.error("DASHBOARD DATA ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/dashboard/simulate", async (req, res) => {
  try {
    const token = String(req.query.token || req.body?.token || "").trim();
    const type = String(req.query.type || req.body?.type || "page_view").trim();

    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const site = await findSiteByToken(token);
    if (!site) return res.status(404).json({ ok: false, error: "Site not found." });

    const siteId = String(valueFrom(site, ["site_id", "id"], token));
    await insertEvent(siteId, type, { source: "dashboard", demo: true });

    res.json({ ok: true, type, site_id: siteId, stored: hasDb() });
  } catch (err) {
    console.error("SIMULATE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/dashboard/seed", async (req, res) => {
  try {
    const token = String(req.query.token || req.body?.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const site = await findSiteByToken(token);
    if (!site) return res.status(404).json({ ok: false, error: "Site not found." });

    const siteId = String(valueFrom(site, ["site_id", "id"], token));
    const now = Date.now();
    const types = [
      "page_view",
      "page_view",
      "page_view",
      "page_view",
      "page_view",
      "cta_click",
      "cta_click",
      "lead",
      "purchase",
    ];

    let inserted = 0;

    for (let day = 0; day < 7; day++) {
      const count = 9 + Math.floor(Math.random() * 10);

      for (let i = 0; i < count; i++) {
        const type = types[Math.floor(Math.random() * types.length)];
        const time = new Date(now - day * 86400000 - Math.floor(Math.random() * 80000000));
        await insertEvent(siteId, type, {
          time,
          source: ["Direct", "Search", "Social", "Referral"][Math.floor(Math.random() * 4)],
          device: ["Desktop", "Desktop", "Mobile", "Tablet"][Math.floor(Math.random() * 4)],
          campaign: "seed-demo",
        });
        inserted++;
      }
    }

    res.json({ ok: true, inserted, message: "Demo data seeded." });
  } catch (err) {
    console.error("SEED ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/dashboard/report", async (req, res) => {
  try {
    const token = String(req.query.token || req.body?.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const payload = await getDashboardPayload(token);
    if (!payload) return res.status(404).json({ ok: false, error: "Site not found." });

    const text = reportText(payload.summary);
    await insertReport(payload.site.site_id, text);

    res.json({ ok: true, report: text, stored: hasDb() });
  } catch (err) {
    console.error("REPORT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/dashboard/export.csv", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).send("Missing token.");

    const site = await findSiteByToken(token);
    if (!site) return res.status(404).send("Site not found.");

    const siteId = String(valueFrom(site, ["site_id", "id"], token));
    const events = await getEvents(siteId, 1000);

    const rows = [["type", "path", "time", "amount"]];

    for (const event of events) {
      rows.push([eventType(event), eventPath(event), eventTime(event), String(eventAmount(event))]);
    }

    if (!events.length) {
      for (const day of fallbackSummary().days) {
        rows.push(["page_view", "/", day.day, "0"]);
        rows.push(["lead", "/contact", day.day, "0"]);
        rows.push(["purchase", "/checkout", day.day, "129"]);
      }
    }

    const csv = rows
      .map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(","))
      .join("\n");

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=constrava-dashboard-events.csv");
    res.send(csv);
  } catch (err) {
    console.error("EXPORT ERROR:", err);
    res.status(500).send(err.message);
  }
});

app.options("/events", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.status(204).end();
});

app.post("/events", async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  try {
    const body = req.body || {};
    const token = String(body.token || body.dashboard_token || body.site_token || req.query.token || "").trim();
    const siteIdInput = String(body.site_id || body.siteId || req.query.site_id || req.query.siteId || "").trim();

    let site = null;

    if (token) site = await findSiteByToken(token);
    if (!site && siteIdInput) site = await getSiteById(siteIdInput);

    const siteId = site
      ? String(valueFrom(site, ["site_id", "id"], siteIdInput || token || "demo"))
      : siteIdInput || token || "demo";

    const type = String(body.event_type || body.type || body.name || "page_view");
    await insertEvent(siteId, type, {
      path: String(body.path || body.pathname || body.url || "/"),
      url: String(body.url || body.href || ""),
      referrer: String(body.referrer || body.referer || ""),
      userAgent: String(req.get("user-agent") || body.user_agent || ""),
      ip: String(req.ip || ""),
      amount: Number(body.amount || body.revenue || body.value || 0),
      source: String(body.source || body.utm_source || "tracker"),
      visitor: String(body.visitor || body.visitor_id || body.anonymous_id || ""),
      demo: false,
      device: String(body.device || ""),
    });

    res.status(204).end();
  } catch (err) {
    console.error("TRACK EVENT ERROR:", err);
    res.status(200).json({ ok: false, error: err.message });
  }
});

app.get("/tracker.js", (req, res) => {
  res.type("application/javascript");
  res.send(String.raw`(function(){
  if (window.__constravaTrackerLoaded) return;
  window.__constravaTrackerLoaded = true;

  var script = document.currentScript || (function(){
    var scripts = document.getElementsByTagName("script");
    return scripts[scripts.length - 1];
  })();

  var siteId = script && (script.getAttribute("data-site-id") || script.getAttribute("data-siteid") || script.getAttribute("data-site"));
  var token = script && (script.getAttribute("data-token") || script.getAttribute("data-dashboard-token"));
  var endpoint = script && script.getAttribute("data-endpoint");
  endpoint = endpoint || (new URL("/events", window.location.origin)).toString();

  function cleanText(value) {
    return String(value || "").replace(/\s+/g, " ").trim().slice(0, 160);
  }

  function guessDevice() {
    var w = window.innerWidth || 1200;
    if (w < 700) return "Mobile";
    if (w < 1050) return "Tablet";
    return "Desktop";
  }

  function send(type, payload) {
    payload = payload || {};
    var data = {
      type: type,
      event_type: type,
      site_id: siteId || "",
      token: token || "",
      path: window.location.pathname,
      url: window.location.href,
      referrer: document.referrer || "",
      title: document.title || "",
      device: guessDevice(),
      source: payload.source || "",
      amount: payload.amount || payload.revenue || 0,
      visitor: localStorage.getItem("cx_visitor") || "",
      payload: payload
    };

    if (!data.visitor) {
      data.visitor = "v_" + Math.random().toString(16).slice(2) + Date.now().toString(16);
      try { localStorage.setItem("cx_visitor", data.visitor); } catch (err) {}
    }

    var json = JSON.stringify(data);

    if (navigator.sendBeacon) {
      try {
        var blob = new Blob([json], { type: "application/json" });
        if (navigator.sendBeacon(endpoint, blob)) return;
      } catch (err) {}
    }

    try {
      fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: json,
        keepalive: true,
        mode: "cors"
      }).catch(function(){});
    } catch (err) {}
  }

  window.ConstravaTrack = send;

  send("page_view", { source: "tracker" });

  document.addEventListener("click", function(event){
    var node = event.target;
    while (node && node !== document.body) {
      var tag = String(node.tagName || "").toLowerCase();
      if (tag === "a" || tag === "button" || node.getAttribute("data-track")) {
        send("cta_click", {
          text: cleanText(node.innerText || node.getAttribute("aria-label") || node.getAttribute("href")),
          href: node.getAttribute("href") || "",
          source: "tracker-click"
        });
        break;
      }
      node = node.parentElement;
    }
  }, true);
})();`);
});

app.get("/reports/latest", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const payload = await getDashboardPayload(token);
    if (!payload) return res.status(404).json({ ok: false, error: "Site not found." });

    res.json({ ok: true, report: payload.reports[0] || { date: new Date().toISOString(), text: reportText(payload.summary) } });
  } catch (err) {
    console.error("LATEST REPORT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/live", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const payload = await getDashboardPayload(token);
    if (!payload) return res.status(404).json({ ok: false, error: "Site not found." });

    res.json({ ok: true, events: payload.recentEvents, summary: payload.summary });
  } catch (err) {
    console.error("LIVE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

function dashboardHtml(token, initialData) {
  const initial = safeJson(initialData);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Constrava Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@450;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    :root {
      --green-950: #022c22;
      --green-900: #064e3b;
      --green-800: #065f46;
      --green-700: #047857;
      --green-600: #059669;
      --green-500: #10b981;
      --green-400: #34d399;
      --green-200: #a7f3d0;
      --green-100: #d1fae5;
      --green-50: #ecfdf5;
      --ink: #0f172a;
      --muted: #64748b;
      --soft: #f8fafc;
      --line: #dbe8e4;
      --card: rgba(255,255,255,.88);
      --shadow: 0 18px 45px rgba(15, 23, 42, .08);
      --shadow-strong: 0 28px 80px rgba(2, 44, 34, .18);
      --radius: 24px;
    }

    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 20% 0%, rgba(16,185,129,.20), transparent 36%),
        radial-gradient(circle at 90% 12%, rgba(52,211,153,.16), transparent 28%),
        linear-gradient(135deg, #f8fffc 0%, #eefaf5 42%, #ffffff 100%);
      overflow-x: hidden;
    }

    body:before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(4,120,87,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(4,120,87,.035) 1px, transparent 1px);
      background-size: 42px 42px;
      mask-image: linear-gradient(90deg, transparent, black 18%, black 80%, transparent);
    }

    button, select, a, textarea, input { font: inherit; }
    button { cursor: pointer; }

    .layout {
      display: grid;
      grid-template-columns: 298px 1fr;
      min-height: 100vh;
    }

    .sidebar {
      position: sticky;
      top: 0;
      height: 100vh;
      padding: 28px 22px;
      overflow-y: auto;
      color: #eafff7;
      background:
        radial-gradient(circle at 0% 0%, rgba(52,211,153,.24), transparent 28%),
        radial-gradient(circle at 110% 45%, rgba(16,185,129,.18), transparent 32%),
        linear-gradient(180deg, #063f31 0%, #03271f 62%, #021813 100%);
      border-right: 1px solid rgba(255,255,255,.12);
      box-shadow: 20px 0 70px rgba(2, 44, 34, .22);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
      margin: 4px 0 34px;
      letter-spacing: .28em;
      text-transform: uppercase;
      font-weight: 900;
      font-size: 21px;
    }

    .brand-mark {
      width: 42px;
      height: 42px;
      border-radius: 13px;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #00f59b, #10b981);
      box-shadow: 0 16px 36px rgba(16,185,129,.36);
      color: #022c22;
      letter-spacing: -.06em;
      font-weight: 1000;
      font-size: 24px;
      transform: skew(-10deg);
    }

    .top-switch {
      display: grid;
      gap: 12px;
      margin-bottom: 24px;
    }

    .side-section-title {
      margin: 28px 14px 12px;
      color: rgba(236,253,245,.62);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: .13em;
      text-transform: uppercase;
    }

    .side-link {
      width: 100%;
      border: 0;
      color: rgba(236,253,245,.88);
      background: transparent;
      border-radius: 15px;
      padding: 14px 14px;
      display: flex;
      align-items: center;
      gap: 14px;
      transition: .18s ease;
      text-align: left;
      position: relative;
    }

    .side-link .ico {
      width: 26px;
      height: 26px;
      display: grid;
      place-items: center;
      color: var(--green-200);
    }

    .side-link span.label {
      flex: 1;
      font-size: 15px;
      font-weight: 650;
    }

    .side-link small {
      padding: 3px 8px;
      border: 1px solid rgba(167,243,208,.24);
      border-radius: 9px;
      color: #d1fae5;
      background: rgba(16,185,129,.20);
      font-weight: 900;
    }

    .side-link:hover {
      background: rgba(255,255,255,.08);
      transform: translateX(2px);
    }

    .side-link.active {
      background: linear-gradient(90deg, rgba(16,185,129,.38), rgba(255,255,255,.10));
      box-shadow: inset 3px 0 0 #12f7a3, 0 18px 40px rgba(0,0,0,.12);
      color: white;
    }

    .insight-card {
      margin-top: 30px;
      border: 1px solid rgba(167,243,208,.18);
      border-radius: 20px;
      padding: 20px;
      background: linear-gradient(135deg, rgba(16,185,129,.28), rgba(6,78,59,.55));
      box-shadow: 0 18px 45px rgba(0,0,0,.16);
    }

    .insight-card h3 {
      margin: 0 0 10px;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 16px;
    }

    .insight-card p {
      margin: 0 0 18px;
      color: rgba(236,253,245,.88);
      line-height: 1.5;
      font-size: 14px;
    }

    .insight-card button {
      border: 0;
      background: transparent;
      color: #a7f3d0;
      font-weight: 900;
      padding: 0;
    }

    .admin-card {
      margin-top: 24px;
      padding-top: 22px;
      border-top: 1px solid rgba(255,255,255,.10);
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .avatar {
      width: 48px;
      height: 48px;
      border-radius: 16px;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, rgba(52,211,153,.9), rgba(255,255,255,.16));
      color: white;
      font-weight: 900;
    }

    .admin-card strong { display: block; font-size: 14px; }
    .admin-card span { display: block; color: rgba(236,253,245,.62); font-size: 12px; margin-top: 3px; }

    .main {
      padding: 36px 26px 42px;
    }

    .shell {
      max-width: 1560px;
      margin: 0 auto;
    }

    .hero {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 24px;
    }

    h1 {
      margin: 0;
      font-size: clamp(32px, 3vw, 44px);
      letter-spacing: -.05em;
      color: #073d32;
      line-height: 1;
    }

    .subtitle {
      margin: 9px 0 0;
      color: var(--muted);
      font-size: 15px;
    }

    .status-pill {
      min-width: max-content;
      border: 1px solid rgba(16,185,129,.26);
      border-radius: 14px;
      padding: 12px 16px;
      display: flex;
      align-items: center;
      gap: 10px;
      background: rgba(236,253,245,.68);
      color: #064e3b;
      box-shadow: 0 10px 28px rgba(16,185,129,.10);
      font-weight: 900;
      font-size: 14px;
    }

    .dot {
      width: 12px;
      height: 12px;
      border-radius: 999px;
      background: var(--green-500);
      box-shadow: 0 0 0 6px rgba(16,185,129,.12);
    }

    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-bottom: 22px;
    }

    .btn, .select-wrap {
      border: 1px solid var(--line);
      border-radius: 13px;
      min-height: 50px;
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 0 16px;
      background: rgba(255,255,255,.83);
      box-shadow: 0 12px 25px rgba(15,23,42,.05);
      color: #073d32;
      font-weight: 900;
      text-decoration: none;
      transition: .18s ease;
    }

    .btn:hover, .select-wrap:hover {
      transform: translateY(-1px);
      border-color: rgba(16,185,129,.45);
      box-shadow: 0 18px 38px rgba(2,44,34,.10);
    }

    .btn svg, .select-wrap svg { color: var(--green-700); }
    .btn .new {
      color: #047857;
      background: #d1fae5;
      border-radius: 8px;
      padding: 3px 7px;
      font-size: 11px;
    }

    select {
      border: 0;
      outline: 0;
      background: transparent;
      color: #073d32;
      font-weight: 900;
      appearance: none;
      padding-right: 8px;
    }

    .tip {
      flex: 1;
      justify-content: space-between;
      min-width: 330px;
      color: var(--muted);
      font-weight: 700;
    }

    .top-tabs {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 10px;
      background: rgba(255,255,255,.72);
      box-shadow: var(--shadow);
      margin-bottom: 24px;
    }

    .tab-btn {
      border: 0;
      border-radius: 13px;
      padding: 13px 20px;
      background: transparent;
      color: #334155;
      font-weight: 900;
    }

    .tab-btn.active {
      background: white;
      color: #047857;
      box-shadow: inset 0 -2px 0 var(--green-500), 0 10px 24px rgba(16,185,129,.10);
    }

    .grid { display: grid; gap: 18px; }
    .kpi-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 22px; }
    .panel-grid { grid-template-columns: minmax(0, 1.65fr) minmax(390px, .95fr); margin-bottom: 22px; }
    .three-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); margin-bottom: 22px; }
    .two-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-bottom: 22px; }

    .card {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--card);
      backdrop-filter: blur(20px);
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }

    .card:before {
      content: "";
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 85% 0%, rgba(16,185,129,.12), transparent 30%);
      pointer-events: none;
    }

    .card-inner { position: relative; padding: 22px; }

    .kpi {
      min-height: 150px;
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 16px;
      align-items: center;
    }

    .kpi-icon {
      width: 58px;
      height: 58px;
      border-radius: 17px;
      display: grid;
      place-items: center;
      color: #047857;
      background: linear-gradient(135deg, #dcfce7, #bbf7d0);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.75);
    }

    .kpi h3 { margin: 0 0 8px; font-size: 15px; }
    .kpi .value {
      font-size: 30px;
      font-weight: 950;
      letter-spacing: -.04em;
      color: #0f172a;
    }

    .trend-up {
      margin-top: 8px;
      color: #059669;
      font-size: 13px;
      font-weight: 900;
    }

    .trend-up span { color: var(--muted); font-weight: 700; }

    .spark {
      width: 82px;
      height: 42px;
      overflow: visible;
    }

    .spark polyline {
      fill: none;
      stroke: #059669;
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .card-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 14px;
    }

    .card-title h2, .card-title h3 {
      margin: 0;
      letter-spacing: -.03em;
    }

    .card-title h2 { font-size: 20px; }
    .card-title h3 { font-size: 18px; }
    .card-title p {
      margin: 3px 0 0;
      color: var(--muted);
      font-size: 13px;
      font-weight: 650;
    }

    .panel-actions { display: flex; align-items: center; gap: 8px; }

    .mini-btn {
      border: 1px solid var(--line);
      border-radius: 12px;
      min-height: 42px;
      padding: 0 14px;
      background: rgba(255,255,255,.72);
      color: #064e3b;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      font-weight: 900;
    }

    .mini-btn:hover { border-color: rgba(16,185,129,.5); }

    .chart-wrap {
      position: relative;
      min-height: 335px;
      overflow: hidden;
      border-radius: 18px;
      background:
        linear-gradient(180deg, rgba(255,255,255,.65), rgba(255,255,255,.20)),
        radial-gradient(circle at 50% 100%, rgba(16,185,129,.12), transparent 55%);
    }

    .traffic-svg {
      width: 100%;
      height: 335px;
      display: block;
    }

    .grid-line { stroke: rgba(148,163,184,.24); stroke-width: 1; }
    .axis-label { fill: #64748b; font-size: 13px; font-weight: 700; }
    .chart-line { fill: none; stroke: #047857; stroke-width: 4; stroke-linecap: round; stroke-linejoin: round; }
    .chart-dot { fill: #047857; stroke: white; stroke-width: 3; cursor: pointer; }
    .chart-dot:hover { r: 8; }
    .chart-tooltip rect { fill: rgba(255,255,255,.94); stroke: rgba(16,185,129,.22); filter: drop-shadow(0 14px 22px rgba(15,23,42,.14)); }
    .tip-small { fill: #64748b; font-size: 12px; font-weight: 800; }
    .tip-big { fill: #0f172a; font-size: 18px; font-weight: 950; }
    .tip-green { fill: #059669; font-size: 12px; font-weight: 900; }

    .metric-strip {
      display: grid;
      grid-template-columns: repeat(4, minmax(0,1fr));
      gap: 0;
      margin-top: 16px;
      border: 1px solid #e5eee9;
      border-radius: 16px;
      overflow: hidden;
      background: rgba(255,255,255,.70);
    }

    .metric-strip div {
      padding: 16px;
      text-align: center;
      border-right: 1px solid #e5eee9;
    }

    .metric-strip div:last-child { border-right: 0; }
    .metric-strip strong { display: block; font-size: 19px; letter-spacing: -.03em; }
    .metric-strip span { color: var(--muted); font-size: 12px; font-weight: 650; }

    .funnel {
      display: grid;
      gap: 10px;
      margin: 12px 0 20px;
    }

    .funnel-row {
      position: relative;
      display: grid;
      grid-template-columns: 1fr 1.2fr 1fr;
      align-items: center;
      min-height: 70px;
      border-radius: 13px;
      background: rgba(241,245,249,.65);
      overflow: hidden;
      padding: 0 16px;
    }

    .funnel-row strong { display: block; }
    .funnel-row span { font-weight: 950; color: #0f172a; }
    .funnel-shape {
      height: 52px;
      margin: 0 auto;
      background: linear-gradient(135deg, #2f9966, #66c892);
      clip-path: polygon(0 0,100% 0,84% 100%,16% 100%);
      box-shadow: inset 0 16px 24px rgba(255,255,255,.20);
    }

    .funnel-stat { text-align: right; color: #064e3b; font-weight: 950; }
    .funnel-stat small { display: block; color: var(--muted); font-weight: 650; margin-top: 5px; }

    .revenue-box {
      display: grid;
      grid-template-columns: 1fr 1fr;
      border: 1px solid #e5eee9;
      border-radius: 16px;
      overflow: hidden;
      background: rgba(255,255,255,.62);
    }

    .revenue-box div { padding: 16px; text-align: center; border-right: 1px solid #e5eee9; }
    .revenue-box div:last-child { border-right: 0; }
    .revenue-box small { display: block; color: var(--muted); font-weight: 800; }
    .revenue-box strong { display: block; color: #047857; font-size: 22px; margin-top: 6px; letter-spacing: -.03em; }

    .simulate-card {
      min-height: 170px;
      background:
        linear-gradient(90deg, rgba(255,255,255,.92), rgba(255,255,255,.75) 62%, rgba(236,253,245,.72)),
        radial-gradient(circle at 90% 20%, rgba(16,185,129,.18), transparent 30%);
    }

    .simulate-row {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }

    .sim-visual {
      position: absolute;
      right: 18px;
      bottom: 14px;
      width: 310px;
      height: 118px;
      opacity: .95;
      pointer-events: none;
    }

    .bar-list { display: grid; gap: 12px; }
    .bar-row {
      display: grid;
      grid-template-columns: minmax(100px, 1fr) 2fr auto;
      align-items: center;
      gap: 12px;
    }

    .bar-track {
      height: 12px;
      border-radius: 999px;
      background: #e8f4ef;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      width: 0;
      border-radius: 999px;
      background: linear-gradient(90deg, #059669, #34d399);
    }

    .mini-table, table {
      width: 100%;
      border-collapse: collapse;
    }

    th {
      color: #64748b;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
      text-align: left;
      padding: 10px 10px;
    }

    td {
      padding: 13px 10px;
      border-top: 1px solid #edf3f1;
      font-size: 14px;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 5px 9px;
      background: #dcfce7;
      color: #047857;
      font-weight: 900;
      font-size: 12px;
    }

    .activity-list { display: grid; gap: 10px; max-height: 430px; overflow: auto; padding-right: 4px; }
    .activity-row {
      display: grid;
      grid-template-columns: 42px 1fr auto;
      gap: 12px;
      align-items: center;
      padding: 12px;
      border: 1px solid #edf3f1;
      border-radius: 16px;
      background: rgba(255,255,255,.66);
    }

    .activity-icon {
      width: 42px;
      height: 42px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      background: #dcfce7;
      color: #047857;
      font-weight: 950;
    }

    .activity-row strong { display: block; }
    .activity-row span { display: block; color: var(--muted); font-size: 12px; margin-top: 3px; }
    .activity-row em { color: var(--muted); font-size: 12px; font-style: normal; font-weight: 700; text-align: right; }

    .report-box {
      white-space: pre-wrap;
      color: #334155;
      line-height: 1.55;
      margin: 0;
      padding: 16px;
      border-radius: 16px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      max-height: 320px;
      overflow: auto;
    }

    .code-box {
      display: flex;
      gap: 10px;
      align-items: center;
      padding: 12px;
      border: 1px solid #dbe8e4;
      border-radius: 14px;
      background: #022c22;
      color: #d1fae5;
      overflow: auto;
    }

    .code-box code {
      flex: 1;
      white-space: nowrap;
      font-size: 13px;
    }

    .empty {
      color: var(--muted);
      padding: 14px;
      border: 1px dashed #cbd5e1;
      border-radius: 14px;
      background: rgba(248,250,252,.65);
    }

    .section-page { display: none; }
    .section-page.active { display: block; animation: pageIn .22s ease both; }

    @keyframes pageIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .toast {
      position: fixed;
      right: 22px;
      bottom: 22px;
      z-index: 30;
      border: 1px solid rgba(16,185,129,.24);
      border-radius: 16px;
      padding: 14px 16px;
      background: rgba(255,255,255,.95);
      box-shadow: var(--shadow-strong);
      color: #064e3b;
      font-weight: 900;
      opacity: 0;
      transform: translateY(12px);
      pointer-events: none;
      transition: .2s ease;
    }

    .toast.show { opacity: 1; transform: translateY(0); }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      display: none;
      place-items: center;
      z-index: 40;
      padding: 20px;
      background: rgba(2, 18, 14, .52);
      backdrop-filter: blur(10px);
    }

    .modal-backdrop.open { display: grid; }

    .modal {
      width: min(720px, 100%);
      max-height: 88vh;
      overflow: auto;
      border: 1px solid rgba(167,243,208,.25);
      border-radius: 26px;
      background: white;
      box-shadow: 0 36px 120px rgba(0,0,0,.28);
      padding: 24px;
    }

    .modal-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 14px;
    }

    .modal h2 { margin: 0; letter-spacing: -.04em; color: #073d32; }
    .modal p { color: #475569; line-height: 1.6; }
    .close {
      border: 0;
      width: 38px;
      height: 38px;
      border-radius: 12px;
      background: #f1f5f9;
      color: #0f172a;
      font-weight: 900;
    }

    .plan-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0,1fr));
      gap: 12px;
      margin-top: 16px;
    }

    .plan {
      border: 1px solid #dbe8e4;
      border-radius: 18px;
      padding: 16px;
      background: #f8fffc;
    }

    .plan strong { display: block; font-size: 18px; }
    .plan span { display: block; color: #047857; font-weight: 950; margin: 8px 0; }
    .plan small { color: #64748b; line-height: 1.5; display: block; }

    @media (max-width: 1180px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar { position: relative; height: auto; }
      .kpi-grid, .panel-grid, .three-grid, .two-grid { grid-template-columns: 1fr; }
      .sim-visual { display: none; }
    }

    @media (max-width: 680px) {
      .main { padding: 24px 14px; }
      .hero { flex-direction: column; }
      .toolbar .btn, .toolbar .select-wrap, .tip { width: 100%; justify-content: center; }
      .kpi { grid-template-columns: auto 1fr; }
      .kpi .spark { display: none; }
      .metric-strip, .revenue-box, .plan-grid { grid-template-columns: 1fr; }
      .metric-strip div, .revenue-box div { border-right: 0; border-bottom: 1px solid #e5eee9; }
      .funnel-row { grid-template-columns: 1fr; gap: 8px; padding: 14px; }
      .funnel-stat { text-align: left; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">∕∕</div>
        <div>CONSTRAVA</div>
      </div>

      <div class="top-switch">
        <button class="side-link active" data-side="analytics" type="button">
          <span class="ico" data-icon="analytics"></span>
          <span class="label">Analytics</span>
        </button>
        <button class="side-link" data-side="crm" type="button">
          <span class="ico" data-icon="database"></span>
          <span class="label">CRM</span>
        </button>
      </div>

      <div class="side-section-title">Analytics</div>
      <nav class="side-nav">
        <button class="side-link active" data-section="home" type="button"><span class="ico" data-icon="home"></span><span class="label">Home</span><span>›</span></button>
        <button class="side-link" data-section="realtime" type="button"><span class="ico" data-icon="pulse"></span><span class="label">Realtime</span></button>
        <button class="side-link" data-section="acquisition" type="button"><span class="ico" data-icon="users"></span><span class="label">Acquisition</span><span>›</span></button>
        <button class="side-link" data-section="engagement" type="button"><span class="ico" data-icon="chat"></span><span class="label">Engagement</span></button>
        <button class="side-link" data-section="monetization" type="button"><span class="ico" data-icon="coin"></span><span class="label">Monetization</span></button>
        <button class="side-link" data-section="explore" type="button"><span class="ico" data-icon="compass"></span><span class="label">Explore</span></button>
        <button class="side-link" data-section="ai" type="button"><span class="ico" data-icon="sparkles"></span><span class="label">AI Studio</span><small>AI</small></button>
        <button class="side-link" data-section="configure" type="button"><span class="ico" data-icon="gear"></span><span class="label">Configure</span></button>
      </nav>

      <div class="insight-card">
        <h3><span data-icon="sparkles"></span> AI Insights</h3>
        <p id="sidebarInsight">Your site traffic is up 24% this week.</p>
        <button type="button" data-explain="overview">View full report →</button>
      </div>

      <div class="admin-card">
        <div class="avatar">AD</div>
        <div>
          <strong>Admin</strong>
          <span id="adminEmail">admin@constrava.com</span>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="shell">
        <header class="hero">
          <div>
            <h1>Constrava Dashboard</h1>
            <p class="subtitle">Token-auth dashboard • secure it later with accounts if desired 🔒</p>
          </div>
          <div class="status-pill"><span class="dot"></span><span id="statusText">Status: ready</span> <span data-icon="shield"></span></div>
        </header>

        <section class="toolbar">
          <label class="select-wrap" title="Range">
            <span data-icon="calendar"></span>
            <select id="rangeSelect">
              <option value="7">7 days</option>
              <option value="14">14 days</option>
              <option value="30">30 days</option>
            </select>
          </label>
          <button class="btn" type="button" id="seedBtn"><span data-icon="database"></span> Seed demo data</button>
          <button class="btn" type="button" id="reportBtn"><span data-icon="sparkles"></span> Generate AI report <span class="new">New</span></button>
          <button class="btn" type="button" id="refreshBtn"><span data-icon="refresh"></span> Refresh</button>
          <button class="btn" type="button" id="plansBtn"><span data-icon="crown"></span> Plans</button>
          <button class="btn" type="button" id="crmBtn"><span data-icon="users"></span> CRM</button>
          <button class="btn tip" type="button" data-explain="tip">
            <span>Tip: Use the sidebar tabs in Analytics • Click any “AI explain” to get a popup</span>
            <span data-icon="sparkles"></span>
          </button>
        </section>

        <section class="top-tabs" aria-label="Dashboard tabs">
          <button class="tab-btn active" type="button" data-side="analytics">Analytics</button>
          <button class="tab-btn" type="button" data-side="crm">CRM</button>
        </section>

        <div id="analyticsArea">
          <section class="section-page active" id="section-home">
            <div class="grid kpi-grid">
              <article class="card"><div class="card-inner kpi"><div class="kpi-icon" data-icon="users"></div><div><h3>Visits ⓘ</h3><div class="value" id="visitsValue">0</div><div class="trend-up">↑ 24.6% <span>vs previous 7 days</span></div></div><div id="visitsSpark"></div></div></article>
              <article class="card"><div class="card-inner kpi"><div class="kpi-icon" data-icon="target"></div><div><h3>Leads ⓘ</h3><div class="value" id="leadsValue">0</div><div class="trend-up">↑ 18.3% <span>vs previous 7 days</span></div></div><div id="leadsSpark"></div></div></article>
              <article class="card"><div class="card-inner kpi"><div class="kpi-icon" data-icon="cart"></div><div><h3>Purchases ⓘ</h3><div class="value" id="purchasesValue">0</div><div class="trend-up">↑ 16.8% <span>vs previous 7 days</span></div></div><div id="purchasesSpark"></div></div></article>
              <article class="card"><div class="card-inner kpi"><div class="kpi-icon" data-icon="cursor"></div><div><h3>CTA clicks ⓘ</h3><div class="value" id="clicksValue">0</div><div class="trend-up">↑ 22.1% <span>vs previous 7 days</span></div></div><div id="clicksSpark"></div></div></article>
            </div>

            <div class="grid panel-grid">
              <article class="card">
                <div class="card-inner">
                  <div class="card-title">
                    <div>
                      <h2>Traffic trend</h2>
                      <p><span id="chartSubtitle">Visits per day</span> (<span id="dataModeLabel">demo</span>)</p>
                    </div>
                    <div class="panel-actions">
                      <label class="select-wrap" style="min-height:42px">
                        <select id="metricSelect">
                          <option value="visits">Visits</option>
                          <option value="leads">Leads</option>
                          <option value="purchases">Purchases</option>
                          <option value="clicks">CTA clicks</option>
                          <option value="revenue">Revenue</option>
                        </select>
                      </label>
                      <button class="mini-btn" type="button" data-explain="traffic"><span data-icon="sparkles"></span> AI explain</button>
                      <button class="mini-btn" type="button" data-explain="menu">⋮</button>
                    </div>
                  </div>
                  <div class="chart-wrap" id="chartWrap"></div>
                  <div class="metric-strip">
                    <div><strong id="stripTotal">0</strong><span>Total visits</span></div>
                    <div><strong id="stripAverage">0</strong><span>Daily average</span></div>
                    <div><strong id="stripBest" style="color:#059669">0</strong><span>Best day</span></div>
                    <div><strong id="stripDuration">0:00</strong><span>Avg. session duration</span></div>
                  </div>
                </div>
              </article>

              <article class="card">
                <div class="card-inner">
                  <div class="card-title">
                    <div>
                      <h2>Conversation funnel</h2>
                      <p>Visits → Leads → Purchases</p>
                    </div>
                    <div class="panel-actions">
                      <button class="mini-btn" type="button" data-explain="funnel"><span data-icon="sparkles"></span> AI explain</button>
                      <button class="mini-btn" type="button" data-explain="menu">⋮</button>
                    </div>
                  </div>
                  <div class="funnel">
                    <div class="funnel-row"><div><strong>Visits</strong><span id="funnelVisits">0</span></div><div class="funnel-shape" style="width:100%"></div><div class="funnel-stat">100%</div></div>
                    <div class="funnel-row"><div><strong>Leads</strong><span id="funnelLeads">0</span></div><div class="funnel-shape" id="leadFunnelShape"></div><div class="funnel-stat"><span id="leadRate">0%</span><small>Conversion rate</small></div></div>
                    <div class="funnel-row"><div><strong>Purchases</strong><span id="funnelPurchases">0</span></div><div class="funnel-shape" id="purchaseFunnelShape"></div><div class="funnel-stat"><span id="purchaseRate">0%</span><small>Conversion rate</small></div></div>
                  </div>
                  <div class="revenue-box">
                    <div><small>Revenue (demo)</small><strong id="revenueValue">$0</strong></div>
                    <div><small>AOV (demo)</small><strong id="aovValue">$0.00</strong></div>
                  </div>
                </div>
              </article>
            </div>

            <article class="card simulate-card">
              <div class="card-inner">
                <div class="card-title">
                  <div>
                    <h2>Simulate events</h2>
                    <p>Generate demo activity instantly</p>
                  </div>
                </div>
                <div class="simulate-row">
                  <button class="btn" type="button" data-sim="page_view"><span data-icon="eye"></span> Sim page_view</button>
                  <button class="btn" type="button" data-sim="lead"><span data-icon="userPlus"></span> Sim lead</button>
                  <button class="btn" type="button" data-sim="purchase"><span data-icon="bag"></span> Sim purchase</button>
                  <button class="btn" type="button" data-sim="cta_click"><span data-icon="cursor"></span> Sim cta_click</button>
                </div>
                <svg class="sim-visual" viewBox="0 0 360 140" aria-hidden="true">
                  <defs><linearGradient id="screenGrad" x1="0" x2="1"><stop offset="0" stop-color="#064e3b"/><stop offset="1" stop-color="#10b981"/></linearGradient></defs>
                  <path d="M20 120 C80 72 120 40 190 60 C260 80 260 24 340 48 L340 140 L20 140 Z" fill="#d1fae5"/>
                  <rect x="180" y="20" width="126" height="82" rx="10" fill="url(#screenGrad)" stroke="#03402f" stroke-width="4"/>
                  <rect x="196" y="43" width="12" height="36" fill="#a7f3d0"/><rect x="215" y="55" width="12" height="24" fill="#a7f3d0"/><rect x="234" y="33" width="12" height="46" fill="#a7f3d0"/><rect x="253" y="62" width="12" height="17" fill="#a7f3d0"/>
                  <rect x="199" y="85" width="28" height="9" rx="3" fill="#dcfce7"/><rect x="234" y="85" width="28" height="9" rx="3" fill="#dcfce7"/>
                  <rect x="85" y="88" width="14" height="32" fill="#34d399"/><rect x="105" y="74" width="14" height="46" fill="#10b981"/><rect x="125" y="60" width="14" height="60" fill="#059669"/>
                </svg>
              </div>
            </article>
          </section>

          <section class="section-page" id="section-realtime">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Realtime activity</h2><p>Newest tracked events</p></div><button class="mini-btn" type="button" id="liveRefreshBtn">Refresh live</button></div><div class="activity-list" id="activityList"></div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Live pulse</h2><p>Current event mix</p></div><button class="mini-btn" type="button" data-explain="realtime"><span data-icon="sparkles"></span> AI explain</button></div><div class="bar-list" id="topTypesLive"></div></div></article>
            </div>
          </section>

          <section class="section-page" id="section-acquisition">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Traffic sources</h2><p>Where visitors came from</p></div></div><div class="bar-list" id="sourceList"></div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Device mix</h2><p>Desktop, mobile, tablet split</p></div></div><div class="bar-list" id="deviceList"></div></div></article>
            </div>
          </section>

          <section class="section-page" id="section-engagement">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Top pages</h2><p>Pages creating the most activity</p></div><button class="mini-btn" type="button" data-explain="pages"><span data-icon="sparkles"></span> AI explain</button></div><div class="bar-list" id="topPages"></div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Event types</h2><p>Most common visitor actions</p></div></div><div class="bar-list" id="topTypes"></div></div></article>
            </div>
          </section>

          <section class="section-page" id="section-monetization">
            <div class="grid three-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h3>Revenue</h3><p>Estimated tracked revenue</p></div></div><div class="value" id="moneyRevenue">$0</div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h3>Average order value</h3><p>Revenue / purchases</p></div></div><div class="value" id="moneyAov">$0.00</div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h3>Purchase rate</h3><p>Purchases / visits</p></div></div><div class="value" id="moneyRate">0%</div></div></article>
            </div>
            <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Revenue by day</h2><p>Demo or live purchase values</p></div></div><div id="revenueChart" class="chart-wrap"></div></div></article>
          </section>

          <section class="section-page" id="section-explore">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Explore insights</h2><p>Quick questions a client would ask</p></div></div><div class="bar-list">
                <button class="btn" type="button" data-explain="whyUp">Why is traffic up?</button>
                <button class="btn" type="button" data-explain="leadQuality">Where are leads coming from?</button>
                <button class="btn" type="button" data-explain="nextAction">What should we improve next?</button>
              </div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Data health</h2><p>Tracker and database status</p></div></div><div class="activity-list" id="healthList"></div></div></article>
            </div>
          </section>

          <section class="section-page" id="section-ai">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>AI Studio</h2><p>Readable report generated from current metrics</p></div><button class="mini-btn" type="button" id="reportBtn2"><span data-icon="sparkles"></span> Generate report</button></div><pre class="report-box" id="reportOutput">No report generated yet.</pre></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Saved reports</h2><p>Latest database report previews</p></div></div><div id="savedReports" class="activity-list"></div></div></article>
            </div>
          </section>

          <section class="section-page" id="section-configure">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Install tracker</h2><p>Paste this snippet on any page you want to track.</p></div></div><div class="code-box"><code id="trackingScript"></code><button class="mini-btn" type="button" id="copyScriptBtn">Copy</button></div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>Dashboard links</h2><p>Useful routes for demos and testing</p></div></div><div class="bar-list">
                <a class="btn" id="exportBtn" href="#">Export CSV</a>
                <a class="btn" id="dataBtn" href="#">View JSON data</a>
                <a class="btn" href="/db-test">DB test</a>
              </div></div></article>
            </div>
          </section>
        </div>

        <div id="crmArea" style="display:none">
          <section class="section-page active">
            <div class="grid two-grid">
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>CRM pipeline</h2><p>Recent leads connected to the dashboard</p></div><button class="mini-btn" type="button" data-explain="crm"><span data-icon="sparkles"></span> AI explain</button></div><div style="overflow:auto"><table id="crmTable"></table></div></div></article>
              <article class="card"><div class="card-inner"><div class="card-title"><div><h2>CRM actions</h2><p>Client-demo friendly follow-ups</p></div></div><div class="bar-list">
                <button class="btn" type="button" data-explain="followup">Draft follow-up strategy</button>
                <button class="btn" type="button" data-explain="qualify">Explain lead quality</button>
                <button class="btn" type="button" data-explain="pipeline">Summarize pipeline</button>
              </div></div></article>
            </div>
          </section>
        </div>
      </div>
    </main>
  </div>

  <div class="toast" id="toast">Ready</div>

  <div class="modal-backdrop" id="modalBackdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <div class="modal-head">
        <div>
          <h2 id="modalTitle">AI insight</h2>
          <p id="modalBody">Insight text</p>
        </div>
        <button class="close" type="button" id="closeModal">×</button>
      </div>
      <div id="modalExtra"></div>
    </div>
  </div>

  <script>
    const token = ${safeJson(token)};
    let dashboardData = ${initial};
    let selectedRange = 7;
    let selectedMetric = "visits";
    let activeSide = "analytics";
    let activeSection = "home";
    let toastTimer = null;

    const icons = {
      analytics: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M4 19V5M4 19H20M8 16V11M12 16V8M16 16V13M20 16V6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      database: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><ellipse cx="12" cy="5" rx="7" ry="3" stroke="currentColor" stroke-width="2"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" stroke="currentColor" stroke-width="2"/></svg>',
      home: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M4 11.5 12 5l8 6.5V20a1 1 0 0 1-1 1h-5v-6H10v6H5a1 1 0 0 1-1-1v-8.5Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
      pulse: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M3 12h4l2-6 4 13 2-7h6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      users: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M16 19c0-2.2-1.8-4-4-4H8c-2.2 0-4 1.8-4 4M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM20 19c0-1.8-1.2-3.3-2.9-3.8M16.5 3.4a4 4 0 0 1 0 7.2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      chat: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M4 5h16v11H8l-4 4V5Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M8 9h8M8 13h5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      coin: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="M14.5 8.5H11a2 2 0 0 0 0 4h2a2 2 0 0 1 0 4H9.5M12 6.5v11" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      compass: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="m15.5 8.5-2 5-5 2 2-5 5-2Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
      gear: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z" stroke="currentColor" stroke-width="2"/><path d="M19 13.5v-3l-2.1-.5a7.7 7.7 0 0 0-.8-1.9l1.1-1.8-2.1-2.1-1.8 1.1a7.7 7.7 0 0 0-1.9-.8L11 2H8l-.5 2.1a7.7 7.7 0 0 0-1.9.8L3.8 3.8 1.7 5.9l1.1 1.8a7.7 7.7 0 0 0-.8 1.9L0 10v3l2.1.5c.2.7.5 1.3.8 1.9l-1.1 1.8 2.1 2.1 1.8-1.1c.6.3 1.2.6 1.9.8L8 22h3l.5-2.1c.7-.2 1.3-.5 1.9-.8l1.8 1.1 2.1-2.1-1.1-1.8c.3-.6.6-1.2.8-1.9l2-.4Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" transform="translate(2 0) scale(.85)"/></svg>',
      sparkles: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l1.4 4.3L18 9l-4.6 1.7L12 15l-1.4-4.3L6 9l4.6-1.7L12 3ZM18 14l.9 2.6L22 18l-3.1 1.4L18 22l-.9-2.6L14 18l3.1-1.4L18 14ZM5 14l.7 2.1L8 17l-2.3.9L5 20l-.7-2.1L2 17l2.3-.9L5 14Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
      calendar: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M7 3v3M17 3v3M4 9h16M5 5h14v15H5V5Z" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      refresh: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M20 12a8 8 0 0 1-13.7 5.6M4 12A8 8 0 0 1 17.7 6.4M17 3v4h4M7 21v-4H3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      crown: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="m4 8 4 4 4-7 4 7 4-4-2 11H6L4 8Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
      shield: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 3 20 6v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6l8-3Z" stroke="currentColor" stroke-width="2"/><path d="m8.5 12 2.2 2.2 4.8-5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      target: '<svg width="26" height="26" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="2"/><path d="M12 2v3M22 12h-3M12 22v-3M2 12h3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      cart: '<svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M3 4h2l2.3 11h9.5l2-8H7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="9" cy="20" r="1.5" fill="currentColor"/><circle cx="17" cy="20" r="1.5" fill="currentColor"/></svg>',
      cursor: '<svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M5 3l14 10-6.2 1.2L10 20 5 3Z" fill="currentColor"/></svg>',
      eye: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg>',
      userPlus: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M15 19c0-2.2-1.8-4-4-4H7c-2.2 0-4 1.8-4 4M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM19 8v6M16 11h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
      bag: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M6 8h12l-1 13H7L6 8Z" stroke="currentColor" stroke-width="2"/><path d="M9 8a3 3 0 0 1 6 0" stroke="currentColor" stroke-width="2"/></svg>'
    };

    document.querySelectorAll("[data-icon]").forEach(function(el){
      el.innerHTML = icons[el.getAttribute("data-icon")] || "";
    });

    function number(value) { return Number(value || 0); }
    function format(value) { return new Intl.NumberFormat("en-US").format(Math.round(number(value))); }
    function formatMoney(value, digits) {
      return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", minimumFractionDigits: digits || 0, maximumFractionDigits: digits || 0 }).format(number(value));
    }
    function percent(part, whole, digits) {
      if (!number(whole)) return "0.00";
      return ((number(part) / number(whole)) * 100).toFixed(digits == null ? 2 : digits);
    }
    function byId(id) { return document.getElementById(id); }

    function toast(message) {
      const node = byId("toast");
      node.textContent = message;
      node.classList.add("show");
      clearTimeout(toastTimer);
      toastTimer = setTimeout(function(){ node.classList.remove("show"); }, 2600);
    }

    function setStatus(text) {
      byId("statusText").textContent = text;
    }

    function normalizeDays() {
      const days = ((dashboardData.summary && dashboardData.summary.days) || []).slice();
      return days.slice(Math.max(0, days.length - selectedRange));
    }

    function metricLabel(metric) {
      return { visits: "Visits", leads: "Leads", purchases: "Purchases", clicks: "CTA clicks", revenue: "Revenue" }[metric] || "Visits";
    }

    function makeSpark(values) {
      values = values && values.length ? values : [2,5,3,6,5,8,7];
      const width = 94;
      const height = 34;
      const max = Math.max.apply(null, values.concat([1]));
      const min = Math.min.apply(null, values.concat([0]));
      const pts = values.map(function(v, i){
        const x = (i * width) / Math.max(values.length - 1, 1);
        const y = height - ((v - min) / Math.max(max - min, 1)) * height;
        return x + "," + y;
      }).join(" ");
      return '<svg class="spark" viewBox="0 0 ' + width + ' ' + height + '"><polyline points="' + pts + '"></polyline></svg>';
    }

    function drawChart(targetId, metric) {
      const target = byId(targetId);
      const days = normalizeDays();
      const points = days.map(function(d) {
        return {
          label: (d.day || "Today").slice(5),
          day: d.day || "Today",
          value: number(d[metric] || 0)
        };
      });

      if (!points.length) points.push({ label: "Today", day: "Today", value: 0 });

      const width = 820;
      const height = 335;
      const padX = 52;
      const padY = 38;
      const max = Math.max.apply(null, points.map(function(p){ return p.value; }).concat([1]));
      const coords = points.map(function(p, i) {
        const x = padX + (i * (width - padX * 2)) / Math.max(points.length - 1, 1);
        const y = height - padY - (p.value / max) * (height - padY * 2);
        return Object.assign({}, p, { x: x, y: y });
      });

      const line = coords.map(function(p){ return p.x + "," + p.y; }).join(" ");
      const area = padX + "," + (height - padY) + " " + line + " " + (width - padX) + "," + (height - padY);
      let grid = "";
      for (let i = 0; i <= 4; i++) {
        const y = padY + (i * (height - padY * 2)) / 4;
        grid += '<line x1="' + padX + '" y1="' + y + '" x2="' + (width - padX) + '" y2="' + y + '" class="grid-line"></line>';
      }

      let dots = "";
      coords.forEach(function(p) {
        const displayValue = metric === "revenue" ? formatMoney(p.value, 0) : format(p.value);
        dots += '<circle cx="' + p.x + '" cy="' + p.y + '" r="6" class="chart-dot" data-day="' + escapeHtml(p.day) + '" data-value="' + escapeHtml(displayValue) + '"></circle>';
      });

      let labels = "";
      coords.forEach(function(p) {
        labels += '<text x="' + p.x + '" y="' + (height - 9) + '" text-anchor="middle" class="axis-label">' + escapeHtml(p.label) + '</text>';
      });

      const peak = coords.reduce(function(best, p){ return p.value > best.value ? p : best; }, coords[0]);
      const peakX = Math.min(peak.x + 14, width - 170);
      const peakY = Math.max(peak.y - 86, 18);
      const peakValue = metric === "revenue" ? formatMoney(peak.value, 0) : format(peak.value);

      target.innerHTML =
        '<svg class="traffic-svg" viewBox="0 0 ' + width + ' ' + height + '" role="img">' +
        '<defs><linearGradient id="trafficFill' + targetId + '" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#10b981" stop-opacity="0.44"/><stop offset="58%" stop-color="#34d399" stop-opacity="0.15"/><stop offset="100%" stop-color="#ffffff" stop-opacity="0"/></linearGradient><filter id="glow' + targetId + '"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>' +
        grid +
        '<polygon points="' + area + '" fill="url(#trafficFill' + targetId + ')"></polygon>' +
        '<polyline points="' + line + '" class="chart-line" filter="url(#glow' + targetId + ')"></polyline>' +
        dots +
        labels +
        '<g class="chart-tooltip" transform="translate(' + peakX + ', ' + peakY + ')"><rect width="150" height="78" rx="14"></rect><text x="14" y="24" class="tip-small">Best day</text><text x="14" y="49" class="tip-big">' + peakValue + '</text><text x="14" y="65" class="tip-green">↑ strong activity</text></g>' +
        '</svg>';

      target.querySelectorAll(".chart-dot").forEach(function(dot) {
        dot.addEventListener("mouseenter", function() {
          toast(dot.getAttribute("data-day") + ": " + dot.getAttribute("data-value") + " " + metricLabel(metric).toLowerCase());
        });
      });
    }

    function bestDay(days, metric) {
      if (!days.length) return { day: "Today", value: 0 };
      return days.map(function(d){ return { day: d.day, value: number(d[metric] || 0) }; }).sort(function(a,b){ return b.value - a.value; })[0];
    }

    function renderBarList(id, items, emptyText, percentMode) {
      const node = byId(id);
      items = items || [];
      if (!items.length) {
        node.innerHTML = '<div class="empty">' + escapeHtml(emptyText || "No data yet.") + '</div>';
        return;
      }

      const max = Math.max.apply(null, items.map(function(item){ return number(item[1]); }).concat([1]));
      node.innerHTML = items.map(function(item) {
        const label = item[0];
        const count = number(item[1]);
        const width = percentMode ? count : (count / max) * 100;
        const display = percentMode ? count + "%" : format(count);
        return '<div class="bar-row"><strong>' + escapeHtml(label) + '</strong><div class="bar-track"><div class="bar-fill" style="width:' + Math.max(4, Math.min(100, width)) + '%"></div></div><span>' + display + '</span></div>';
      }).join("");
    }

    function renderActivity() {
      const rows = dashboardData.recentEvents || [];
      const node = byId("activityList");
      if (!rows.length) {
        node.innerHTML = '<div class="empty">No recent activity yet. Use the simulate buttons to create events.</div>';
        return;
      }

      node.innerHTML = rows.slice(0, 18).map(function(event) {
        const type = String(event.type || "event");
        const icon = type.indexOf("lead") >= 0 ? "◎" : type.indexOf("purchase") >= 0 ? "$" : "↗";
        const time = String(event.time || "Just now").replace("T", " ").slice(0, 19);
        return '<div class="activity-row"><div class="activity-icon">' + icon + '</div><div><strong>' + escapeHtml(type) + '</strong><span>' + escapeHtml(event.path || "/") + '</span></div><em>' + escapeHtml(time) + '</em></div>';
      }).join("");
    }

    function renderReports() {
      const saved = byId("savedReports");
      const reports = dashboardData.reports || [];

      if (!reports.length) {
        saved.innerHTML = '<div class="empty">No saved reports yet. Generate one to store it in Neon if the table supports it.</div>';
        return;
      }

      saved.innerHTML = reports.slice(0, 6).map(function(report) {
        return '<div class="activity-row"><div class="activity-icon">AI</div><div><strong>' + escapeHtml(String(report.date || "Report").slice(0, 19)) + '</strong><span>' + escapeHtml(String(report.text || "").slice(0, 140)) + '</span></div><em>report</em></div>';
      }).join("");
    }

    function renderCrm() {
      const table = byId("crmTable");
      const leads = dashboardData.leads || [];
      if (!leads.length) {
        table.innerHTML = '<tbody><tr><td><div class="empty">No CRM leads yet.</div></td></tr></tbody>';
        return;
      }

      table.innerHTML =
        '<thead><tr><th>Name</th><th>Email</th><th>Company</th><th>Status</th><th>Source</th></tr></thead><tbody>' +
        leads.map(function(lead) {
          return '<tr><td><strong>' + escapeHtml(lead.name) + '</strong></td><td>' + escapeHtml(lead.email) + '</td><td>' + escapeHtml(lead.company || "—") + '</td><td><span class="pill">' + escapeHtml(lead.status || "New") + '</span></td><td>' + escapeHtml(lead.source || "Website") + '</td></tr>';
        }).join("") +
        '</tbody>';
    }

    function renderHealth() {
      const items = [
        ["Database", dashboardData.dbConnected ? "Connected" : "Demo preview"],
        ["Data mode", dashboardData.usingFallback ? "Fallback demo data" : "Live Neon events"],
        ["Dashboard token", token ? "Present" : "Missing"],
        ["Tracker endpoint", "/events"],
      ];

      byId("healthList").innerHTML = items.map(function(item) {
        return '<div class="activity-row"><div class="activity-icon">✓</div><div><strong>' + escapeHtml(item[0]) + '</strong><span>' + escapeHtml(item[1]) + '</span></div><em>ready</em></div>';
      }).join("");
    }

    function renderDashboard() {
      const s = dashboardData.summary || {};
      const days = normalizeDays();
      const visits = number(s.visits);
      const leads = number(s.leads);
      const purchases = number(s.purchases);
      const clicks = number(s.clicks);
      const revenue = number(s.revenue);
      const best = bestDay(days, "visits");
      const average = days.length ? visits / days.length : 0;
      const aov = purchases ? revenue / purchases : 0;
      const duration = number(s.avgDurationSeconds || 0);
      const mins = Math.floor(duration / 60);
      const secs = String(duration % 60).padStart(2, "0");

      byId("adminEmail").textContent = (dashboardData.site && dashboardData.site.owner_email) || "admin@constrava.com";
      byId("visitsValue").textContent = format(visits);
      byId("leadsValue").textContent = format(leads);
      byId("purchasesValue").textContent = format(purchases);
      byId("clicksValue").textContent = format(clicks);

      byId("visitsSpark").innerHTML = makeSpark(days.map(function(d){ return number(d.visits); }));
      byId("leadsSpark").innerHTML = makeSpark(days.map(function(d){ return number(d.leads); }));
      byId("purchasesSpark").innerHTML = makeSpark(days.map(function(d){ return number(d.purchases); }));
      byId("clicksSpark").innerHTML = makeSpark(days.map(function(d){ return number(d.clicks); }));

      byId("stripTotal").textContent = format(visits);
      byId("stripAverage").textContent = format(average);
      byId("stripBest").textContent = format(best.value);
      byId("stripDuration").textContent = mins + ":" + secs;

      byId("funnelVisits").textContent = format(visits);
      byId("funnelLeads").textContent = format(leads);
      byId("funnelPurchases").textContent = format(purchases);
      byId("leadRate").textContent = percent(leads, visits, 2) + "%";
      byId("purchaseRate").textContent = percent(purchases, visits, 2) + "%";
      byId("leadFunnelShape").style.width = Math.max(18, Math.min(100, number(percent(leads, visits, 2)) * 5.5)) + "%";
      byId("purchaseFunnelShape").style.width = Math.max(18, Math.min(100, number(percent(purchases, visits, 2)) * 18)) + "%";
      byId("revenueValue").textContent = formatMoney(revenue, 0);
      byId("aovValue").textContent = formatMoney(aov, 2);

      byId("moneyRevenue").textContent = formatMoney(revenue, 0);
      byId("moneyAov").textContent = formatMoney(aov, 2);
      byId("moneyRate").textContent = percent(purchases, visits, 2) + "%";

      byId("dataModeLabel").textContent = dashboardData.usingFallback ? "demo preview" : "live database";
      byId("sidebarInsight").textContent = dashboardData.usingFallback
        ? "This dashboard is showing polished demo data. Seed live events to make it interactive."
        : "Your dashboard is using live Neon events and updates when activity is simulated.";

      renderBarList("topPages", s.pageCounts || [], "No pages tracked yet.");
      renderBarList("topTypes", s.typeCounts || [], "No event types tracked yet.");
      renderBarList("topTypesLive", s.typeCounts || [], "No events yet.");
      renderBarList("sourceList", s.sources || [], "No acquisition data yet.");
      renderBarList("deviceList", s.devices || [], "No device data yet.", true);

      renderActivity();
      renderReports();
      renderCrm();
      renderHealth();
      drawChart("chartWrap", selectedMetric);
      drawChart("revenueChart", "revenue");

      const siteId = (dashboardData.site && dashboardData.site.site_id) || token;
      byId("trackingScript").textContent = '<script src="' + location.origin + '/tracker.js" data-site-id="' + siteId + '"><\\/script>';
      byId("exportBtn").href = "/dashboard/export.csv?token=" + encodeURIComponent(token);
      byId("dataBtn").href = "/dashboard/data?token=" + encodeURIComponent(token);
    }

    async function refreshData(silent) {
      setStatus("Status: refreshing...");
      try {
        const response = await fetch("/dashboard/data?token=" + encodeURIComponent(token));
        const data = await response.json();

        if (!response.ok || !data.ok) {
          throw new Error(data.error || "Could not refresh dashboard.");
        }

        dashboardData = data;
        renderDashboard();
        setStatus("Status: ready");
        if (!silent) toast("Dashboard refreshed.");
      } catch (err) {
        setStatus("Status: error");
        toast(err.message || "Refresh failed.");
      }
    }

    async function simulateEvent(type) {
      setStatus("Status: simulating...");
      toast("Creating " + type + " event...");
      try {
        const response = await fetch("/dashboard/simulate?token=" + encodeURIComponent(token) + "&type=" + encodeURIComponent(type), {
          method: "POST",
          headers: { "Content-Type": "application/json" }
        });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "Could not create event.");
        await refreshData(true);
        setStatus("Status: ready");
        toast(type + " created.");
      } catch (err) {
        setStatus("Status: error");
        toast(err.message || "Could not create event.");
      }
    }

    async function seedDemo() {
      setStatus("Status: seeding...");
      toast("Seeding demo activity...");
      try {
        const response = await fetch("/dashboard/seed?token=" + encodeURIComponent(token), { method: "POST", headers: { "Content-Type": "application/json" } });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "Could not seed demo data.");
        await refreshData(true);
        setStatus("Status: ready");
        toast("Demo data added.");
      } catch (err) {
        setStatus("Status: error");
        toast(err.message || "Seed failed.");
      }
    }

    async function generateReport() {
      setStatus("Status: generating report...");
      toast("Generating report...");
      try {
        const response = await fetch("/dashboard/report?token=" + encodeURIComponent(token), { method: "POST", headers: { "Content-Type": "application/json" } });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "Could not generate report.");
        byId("reportOutput").textContent = data.report || "Report generated.";
        await refreshData(true);
        setStatus("Status: ready");
        openModal("AI report complete", "The report was generated from the current dashboard metrics.", "<pre class='report-box'>" + escapeHtml(data.report || "") + "</pre>");
      } catch (err) {
        setStatus("Status: error");
        toast(err.message || "Report failed.");
      }
    }

    function switchSide(side) {
      activeSide = side;
      document.querySelectorAll("[data-side]").forEach(function(btn) {
        btn.classList.toggle("active", btn.getAttribute("data-side") === side);
      });
      byId("analyticsArea").style.display = side === "analytics" ? "" : "none";
      byId("crmArea").style.display = side === "crm" ? "" : "none";
      if (side === "crm") renderCrm();
    }

    function switchSection(section) {
      activeSection = section;
      document.querySelectorAll(".side-nav .side-link").forEach(function(btn) {
        btn.classList.toggle("active", btn.getAttribute("data-section") === section);
      });
      document.querySelectorAll("#analyticsArea .section-page").forEach(function(page) {
        page.classList.toggle("active", page.id === "section-" + section);
      });
      switchSide("analytics");
      setTimeout(function(){
        if (section === "monetization") drawChart("revenueChart", "revenue");
        if (section === "home") drawChart("chartWrap", selectedMetric);
      }, 30);
    }

    function buildPlansHtml() {
      return '<div class="plan-grid">' +
        '<div class="plan"><strong>Starter</strong><span>$499+</span><small>Landing page, analytics setup, and basic lead routing for a new client project.</small></div>' +
        '<div class="plan"><strong>Growth</strong><span>$1,500+</span><small>Custom dashboard, CRM workflow, reports, and demo automation for active businesses.</small></div>' +
        '<div class="plan"><strong>Custom</strong><span>Quoted</span><small>Full-stack internal tools, AI-assisted operations, and private integrations.</small></div>' +
      '</div>';
    }

    function insightFor(topic) {
      const s = dashboardData.summary || {};
      const leadRate = percent(s.leads, s.visits, 2);
      const purchaseRate = percent(s.purchases, s.visits, 2);
      const topPage = (s.pageCounts && s.pageCounts[0] && s.pageCounts[0][0]) || "/";
      const topSource = (s.sources && s.sources[0] && s.sources[0][0]) || "Direct";

      const messages = {
        overview: "The dashboard shows the full story: traffic, leads, purchases, revenue, top pages, CRM leads, and live event simulation. For a client demo, start with the funnel and then simulate an event so they see the system update.",
        tip: "The sidebar tabs are functional sections. Realtime shows recent events, Acquisition shows sources/devices, Engagement shows pages/actions, Monetization shows revenue, AI Studio generates reports, and Configure gives the tracker snippet.",
        traffic: "Traffic is strongest around the best day in the chart. The main thing to explain is whether the spike came from a campaign, a high-performing page, or repeated returning visitors.",
        funnel: "The lead conversion rate is " + leadRate + "% and the purchase conversion rate is " + purchaseRate + "%. Small improvements between visits and leads can create a large downstream lift.",
        realtime: "Realtime activity is useful in demos because it proves the tracker and database are connected. Click a simulation button, refresh, and the event appears here.",
        pages: "The current top page is " + topPage + ". This is the page to study first because it is producing the most activity.",
        whyUp: "Traffic appears up because the dashboard is concentrating activity into recent days and the strongest pages are carrying more visits.",
        leadQuality: "The strongest lead source is " + topSource + ". Compare that source against CRM status to decide where to spend attention.",
        nextAction: "The next best action is to improve the highest-traffic page with a clearer CTA and then watch whether leads increase.",
        crm: "The CRM tab turns analytics into action. It shows who came in, their source, and their stage so the client can follow up.",
        followup: "Suggested follow-up: contact qualified/proposal leads first, ask one direct question about their project goal, and link them to the most relevant service.",
        qualify: "A high-quality lead usually has a real company, a clear source, a direct request, and movement past the New stage.",
        pipeline: "The pipeline should be judged by stage movement: New → Qualified → Proposal. The dashboard helps show which pages create each type.",
        menu: "This menu is a placeholder for production actions like pin card, export image, or compare date range."
      };

      return messages[topic] || "AI insight ready.";
    }

    function openModal(title, body, extra) {
      byId("modalTitle").textContent = title;
      byId("modalBody").textContent = body;
      byId("modalExtra").innerHTML = extra || "";
      byId("modalBackdrop").classList.add("open");
    }

    function closeModal() {
      byId("modalBackdrop").classList.remove("open");
    }

    function escapeHtml(value) {
      return String(value == null ? "" : value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    document.querySelectorAll("[data-section]").forEach(function(btn) {
      btn.addEventListener("click", function(){ switchSection(btn.getAttribute("data-section")); });
    });

    document.querySelectorAll("[data-side]").forEach(function(btn) {
      btn.addEventListener("click", function(){ switchSide(btn.getAttribute("data-side")); });
    });

    document.querySelectorAll("[data-sim]").forEach(function(btn) {
      btn.addEventListener("click", function(){ simulateEvent(btn.getAttribute("data-sim")); });
    });

    document.querySelectorAll("[data-explain]").forEach(function(btn) {
      btn.addEventListener("click", function(){
        const topic = btn.getAttribute("data-explain");
        openModal("AI explain", insightFor(topic));
      });
    });

    byId("rangeSelect").addEventListener("change", function(event) {
      selectedRange = Number(event.target.value || 7);
      renderDashboard();
      toast("Range changed to " + selectedRange + " days.");
    });

    byId("metricSelect").addEventListener("change", function(event) {
      selectedMetric = event.target.value;
      byId("chartSubtitle").textContent = metricLabel(selectedMetric) + " per day";
      drawChart("chartWrap", selectedMetric);
    });

    byId("seedBtn").addEventListener("click", seedDemo);
    byId("refreshBtn").addEventListener("click", function(){ refreshData(false); });
    byId("liveRefreshBtn").addEventListener("click", function(){ refreshData(false); });
    byId("reportBtn").addEventListener("click", generateReport);
    byId("reportBtn2").addEventListener("click", generateReport);
    byId("plansBtn").addEventListener("click", function(){ openModal("Constrava Plans", "Use these as simple pricing cards inside the demo.", buildPlansHtml()); });
    byId("crmBtn").addEventListener("click", function(){ switchSide("crm"); });
    byId("closeModal").addEventListener("click", closeModal);
    byId("modalBackdrop").addEventListener("click", function(event){ if (event.target.id === "modalBackdrop") closeModal(); });
    byId("copyScriptBtn").addEventListener("click", async function(){
      const text = byId("trackingScript").textContent;
      try {
        await navigator.clipboard.writeText(text);
        toast("Tracking script copied.");
      } catch (err) {
        toast("Copy failed. Select and copy the snippet manually.");
      }
    });

    renderDashboard();
  </script>
</body>
</html>`;
}

app.get("/dashboard", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();

    if (!token) {
      return res.status(400).send(`
        <h1>Missing dashboard token</h1>
        <p>Use <code>/dashboard?token=YOUR_TOKEN</code>.</p>
        <p>For a local preview without Neon, try <code>/dashboard?token=demo</code>.</p>
      `);
    }

    const payload = await getDashboardPayload(token);

    if (!payload) {
      return res.status(404).send(`
        <h1>Dashboard not found</h1>
        <p>No site was found for that token.</p>
      `);
    }

    res.send(dashboardHtml(token, payload));
  } catch (err) {
    console.error("DASHBOARD ERROR:", err);
    res.status(500).send(`
      <h1>Dashboard error</h1>
      <p>${esc(err.message)}</p>
      <p>Check Render logs and make sure DATABASE_URL is set if you want live Neon data.</p>
    `);
  }
});

app.get("/", servePage("index.html", `
  <!doctype html><html><head><title>Constrava</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fffc;color:#0f172a}main{max-width:900px;margin:0 auto;padding:80px 24px}a{color:#047857;font-weight:800}</style></head><body><main><h1>Constrava</h1><p>Rapid custom app development, analytics, and AI-assisted business tools.</p><p><a href="/dashboard?token=demo">Open dashboard demo</a></p></main></body></html>
`));
app.get("/services", servePage("services.html", "<h1>Constrava Services</h1>"));
app.get("/process", servePage("process.html", "<h1>Constrava Process</h1>"));
app.get("/work", servePage("work.html", "<h1>Constrava Work</h1>"));
app.get("/contact", servePage("contact.html", "<h1>Contact Constrava</h1>"));

app.use((req, res) => {
  res.status(404).send(`
    <h1>404</h1>
    <p>Route not found.</p>
    <p><a href="/">Back to Constrava</a></p>
  `);
});

app.listen(PORT, () => {
  console.log("Constrava running on port", PORT);
});
