import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";
import { Pool } from "pg";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "200kb" }));
app.use(express.static(__dirname));

app.get("/health", (req, res) => res.status(200).send("ok"));

const resend = new Resend(process.env.RESEND_API_KEY);
const TO_EMAIL = "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL;

function esc(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

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
      website
    } = req.body || {};

    // Honeypot
    if (website && website.trim() !== "") {
      return res.json({ ok: true });
    }

    if (!name || !email || !message) {
      return res.status(400).json({ ok: false, error: "Please include name, email, and message." });
    }

    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ ok: false, error: "Missing RESEND_API_KEY env var." });
    }
    if (!FROM_EMAIL) {
      return res.status(500).json({ ok: false, error: "Missing FROM_EMAIL env var." });
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
      html
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("SEND ERROR:", err);
    return res.status(500).json({ ok: false, error: "Email send failed (see logs)." });
  }
});
// ----------------------
// Neon / Dashboard setup
// ----------------------

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.PGSSLMODE === "disable"
          ? false
          : { rejectUnauthorized: false },
    })
  : null;



function requireDb() {
  if (!pool) {
    throw new Error(
      "Missing DATABASE_URL. Add your Neon connection string in Render Environment Variables."
    );
  }
  return pool;
}

function quoteId(name) {
  return `"${String(name).replaceAll('"', '""')}"`;
}

const columnCache = new Map();

async function getColumns(tableName) {
  if (columnCache.has(tableName)) return columnCache.get(tableName);

  const result = await requireDb().query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1
     ORDER BY ordinal_position`,
    [tableName]
  );

  const columns = result.rows.map((row) => row.column_name);
  columnCache.set(tableName, columns);
  return columns;
}

function firstExisting(columns, possibleNames) {
  return possibleNames.find((name) => columns.includes(name));
}

function valueFrom(row, possibleNames, fallback = "") {
  for (const name of possibleNames) {
    if (
      row &&
      row[name] !== undefined &&
      row[name] !== null &&
      row[name] !== ""
    ) {
      return row[name];
    }
  }
  return fallback;
}

function nestedValue(row, possibleNames, fallback = "") {
  for (const name of possibleNames) {
    if (
      row &&
      row[name] !== undefined &&
      row[name] !== null &&
      row[name] !== ""
    ) {
      return row[name];
    }

    if (
      row?.payload &&
      typeof row.payload === "object" &&
      row.payload[name] !== undefined
    ) {
      return row.payload[name];
    }

    if (
      row?.metadata &&
      typeof row.metadata === "object" &&
      row.metadata[name] !== undefined
    ) {
      return row.metadata[name];
    }

    if (
      row?.data &&
      typeof row.data === "object" &&
      row.data[name] !== undefined
    ) {
      return row.data[name];
    }
  }

  return fallback;
}

async function findSiteByToken(token) {
  const columns = await getColumns("sites");

  const possibleTokenColumns = [
    "dashboard_token",
    "token",
    "demo_token",
    "access_token",
    "public_token",
    "site_token",
    "id",
    "site_id",
  ].filter((name) => columns.includes(name));

  if (possibleTokenColumns.length === 0) {
    throw new Error("The sites table has no recognized token column.");
  }

  const where = possibleTokenColumns
    .map((col) => `${quoteId(col)}::text = $1`)
    .join(" OR ");

  const result = await requireDb().query(
    `SELECT * FROM sites WHERE ${where} LIMIT 1`,
    [token]
  );

  return result.rows[0] || null;
}

async function getEvents(siteId) {
  const columns = await getColumns("events_raw");

  const siteColumn = firstExisting(columns, [
    "site_id",
    "site",
    "client_site_id",
    "project_id",
  ]);

  const timeColumn = firstExisting(columns, [
    "created_at",
    "timestamp",
    "time",
    "event_time",
    "received_at",
    "inserted_at",
  ]);

  if (!siteColumn) return [];

  const order = timeColumn ? `ORDER BY ${quoteId(timeColumn)} DESC` : "";

  const result = await requireDb().query(
    `SELECT * FROM events_raw 
     WHERE ${quoteId(siteColumn)}::text = $1 
     ${order} 
     LIMIT 100`,
    [siteId]
  );

  return result.rows;
}

async function getReports(siteId) {
  const columns = await getColumns("daily_reports");

  const siteColumn = firstExisting(columns, [
    "site_id",
    "site",
    "client_site_id",
    "project_id",
  ]);

  const timeColumn = firstExisting(columns, [
    "created_at",
    "report_date",
    "date",
    "generated_at",
  ]);

  if (!siteColumn) return [];

  const order = timeColumn ? `ORDER BY ${quoteId(timeColumn)} DESC` : "";

  const result = await requireDb().query(
    `SELECT * FROM daily_reports 
     WHERE ${quoteId(siteColumn)}::text = $1 
     ${order} 
     LIMIT 10`,
    [siteId]
  );

  return result.rows;
}

function eventType(event) {
  return String(
    nestedValue(event, ["event_type", "type", "name", "event", "action"], "event")
  );
}

function eventPath(event) {
  return String(
    nestedValue(event, ["path", "url", "page", "pathname", "href", "route"], "/")
  );
}

function eventTime(event) {
  return String(
    nestedValue(
      event,
      ["created_at", "timestamp", "time", "event_time", "received_at"],
      ""
    )
  );
}

function summarizeEvents(events) {
  const typeCounts = new Map();
  const pageCounts = new Map();

  let pageViews = 0;
  let leads = 0;
  let purchases = 0;
  let revenue = 0;

  for (const event of events) {
    const type = eventType(event).toLowerCase();
    const pathName = eventPath(event);

    typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    pageCounts.set(pathName, (pageCounts.get(pathName) || 0) + 1);

    if (type.includes("page")) pageViews++;
    if (type.includes("lead") || type.includes("contact") || type.includes("form")) {
      leads++;
    }
    if (
      type.includes("purchase") ||
      type.includes("checkout") ||
      type.includes("sale")
    ) {
      purchases++;
    }

    const amount = Number(
      nestedValue(event, ["amount", "revenue", "value", "price"], 0)
    );

    if (Number.isFinite(amount)) revenue += amount;
  }

  return {
    total: events.length,
    pageViews,
    leads,
    purchases,
    revenue,
    topTypes: [...typeCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6),
    topPages: [...pageCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6),
  };
}

function renderRows(rows) {
  if (!rows.length) {
    return `<div class="empty">No recent activity yet.</div>`;
  }

  return `
    <table>
      <thead>
        <tr>
          <th>Event</th>
          <th>Page</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        ${rows
          .map(
            (event) => `
          <tr>
            <td>${esc(eventType(event))}</td>
            <td>${esc(eventPath(event))}</td>
            <td>${esc(eventTime(event) || "—")}</td>
          </tr>
        `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderList(items) {
  if (!items.length) return `<div class="empty">No data yet.</div>`;

  return items
    .map(
      ([label, count]) => `
    <div class="list-row">
      <span>${esc(label)}</span>
      <strong>${esc(count)}</strong>
    </div>
  `
    )
    .join("");
}

function renderReports(reports) {
  if (!reports.length) {
    return `<div class="empty">No AI reports found yet.</div>`;
  }

  return reports
    .map((report) => {
      const date = valueFrom(
        report,
        ["report_date", "date", "created_at", "generated_at"],
        "Report"
      );

      const text = valueFrom(
        report,
        ["summary", "report", "content", "body", "insights", "ai_summary"],
        JSON.stringify(report, null, 2)
      );

      return `
      <div class="report-card">
        <strong>${esc(date)}</strong>
        <pre>${esc(text)}</pre>
      </div>
    `;
    })
    .join("");
}

app.get("/db-test", async (req, res) => {
  try {
    const result = await requireDb().query("SELECT NOW() AS now");
    res.json({ ok: true, now: result.rows[0].now });
  } catch (err) {
    console.error("DB TEST ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/dashboard", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();

    if (!token) {
      return res.status(400).json({
        ok: false,
        error: "Missing token. Use /api/dashboard?token=YOUR_TOKEN",
      });
    }

    const site = await findSiteByToken(token);

    if (!site) {
      return res.status(404).json({
        ok: false,
        error: "No site found for that token.",
      });
    }

    const siteId = String(valueFrom(site, ["site_id", "id"], ""));
    const events = await getEvents(siteId);
    const reports = await getReports(siteId);

    res.json({
      ok: true,
      site,
      events,
      reports,
      summary: summarizeEvents(events),
    });
  } catch (err) {
    console.error("API DASHBOARD ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ============================================================
// Premium Constrava Dashboard
// Replace your old app.get("/dashboard") route with this block.
// Requires your existing Neon `pool` connection to already exist.
// ============================================================

// ============================================================
// Constrava Premium Interactive Dashboard v2
// Drop this block before app.listen(...)
// Requires an existing Neon `pool` variable from pg.
// ============================================================

const cxDashCache = new Map();

function cxDb() {
  if (typeof pool !== "undefined" && pool) return pool;
  throw new Error("Database pool was not found. Make sure your Neon pg Pool is created before this dashboard block.");
}

function cxQ(name) {
  return `"${String(name).replaceAll('"', '""')}"`;
}

function cxEsc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function cxFmt(num) {
  return new Intl.NumberFormat("en-US").format(Math.round(Number(num || 0)));
}

function cxMoney(num) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(Number(num || 0));
}

async function cxTableInfo(tableName) {
  if (cxDashCache.has(tableName)) return cxDashCache.get(tableName);

  const result = await cxDb().query(
    `SELECT column_name, data_type, udt_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1
     ORDER BY ordinal_position`,
    [tableName]
  );

  const info = result.rows;
  cxDashCache.set(tableName, info);
  return info;
}

function cxCols(info) {
  return info.map((c) => c.column_name);
}

function cxFirst(cols, names) {
  return names.find((name) => cols.includes(name));
}

function cxColInfo(info, name) {
  return info.find((c) => c.column_name === name);
}

function cxIsJson(info, name) {
  const c = cxColInfo(info, name);
  return c && ["json", "jsonb"].includes(c.udt_name);
}

function cxValue(row, names, fallback = "") {
  for (const name of names) {
    if (row && row[name] !== undefined && row[name] !== null && row[name] !== "") {
      return row[name];
    }

    for (const obj of ["payload", "metadata", "data", "properties"]) {
      if (
        row &&
        row[obj] &&
        typeof row[obj] === "object" &&
        row[obj][name] !== undefined &&
        row[obj][name] !== null &&
        row[obj][name] !== ""
      ) {
        return row[obj][name];
      }
    }
  }

  return fallback;
}

function cxEventType(event) {
  return String(cxValue(event, ["event_type", "type", "name", "event", "action"], "event"));
}

function cxEventPath(event) {
  return String(cxValue(event, ["path", "url", "page", "pathname", "href", "route"], "/"));
}

function cxEventTime(event) {
  return String(cxValue(event, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"], ""));
}

function cxEventAmount(event) {
  const n = Number(cxValue(event, ["amount", "revenue", "value", "price", "total"], 0));
  return Number.isFinite(n) ? n : 0;
}

async function cxFindSite(token) {
  const info = await cxTableInfo("sites");
  const cols = cxCols(info);

  const tokenCols = [
    "dashboard_token",
    "token",
    "demo_token",
    "access_token",
    "public_token",
    "site_token",
    "site_id",
    "id",
  ].filter((c) => cols.includes(c));

  if (!tokenCols.length) {
    throw new Error("No usable token column found in sites table.");
  }

  const where = tokenCols.map((c) => `${cxQ(c)}::text = $1`).join(" OR ");
  const result = await cxDb().query(`SELECT * FROM sites WHERE ${where} LIMIT 1`, [token]);
  return result.rows[0] || null;
}

async function cxEvents(siteId, limit = 500) {
  const info = await cxTableInfo("events_raw");
  const cols = cxCols(info);

  const siteCol = cxFirst(cols, ["site_id", "site", "client_site_id", "project_id"]);
  const timeCol = cxFirst(cols, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);

  if (!siteCol) return [];

  const order = timeCol ? `ORDER BY ${cxQ(timeCol)} DESC` : "";
  const result = await cxDb().query(
    `SELECT *
     FROM events_raw
     WHERE ${cxQ(siteCol)}::text = $1
     ${order}
     LIMIT $2`,
    [siteId, limit]
  );

  return result.rows;
}

async function cxReports(siteId) {
  const info = await cxTableInfo("daily_reports");
  const cols = cxCols(info);

  const siteCol = cxFirst(cols, ["site_id", "site", "client_site_id", "project_id"]);
  const timeCol = cxFirst(cols, ["created_at", "report_date", "date", "generated_at"]);

  if (!siteCol) return [];

  const order = timeCol ? `ORDER BY ${cxQ(timeCol)} DESC` : "";
  const result = await cxDb().query(
    `SELECT *
     FROM daily_reports
     WHERE ${cxQ(siteCol)}::text = $1
     ${order}
     LIMIT 8`,
    [siteId]
  );

  return result.rows;
}

async function cxCrmLeads(siteId) {
  try {
    const info = await cxTableInfo("crm_leads");
    const cols = cxCols(info);

    const siteCol = cxFirst(cols, ["site_id", "site", "client_site_id", "project_id"]);
    const timeCol = cxFirst(cols, ["created_at", "timestamp", "time", "received_at", "inserted_at"]);

    if (!cols.length) return [];

    if (siteCol) {
      const order = timeCol ? `ORDER BY ${cxQ(timeCol)} DESC` : "";
      const result = await cxDb().query(
        `SELECT *
         FROM crm_leads
         WHERE ${cxQ(siteCol)}::text = $1
         ${order}
         LIMIT 50`,
        [siteId]
      );
      return result.rows;
    }

    const result = await cxDb().query(`SELECT * FROM crm_leads LIMIT 50`);
    return result.rows;
  } catch {
    return [];
  }
}

function cxSummarize(events) {
  let visits = 0;
  let leads = 0;
  let purchases = 0;
  let clicks = 0;
  let revenue = 0;

  const typeCounts = new Map();
  const pageCounts = new Map();
  const dayMetrics = new Map();

  for (const event of events) {
    const type = cxEventType(event).toLowerCase();
    const path = cxEventPath(event);
    const time = cxEventTime(event);
    const day = time ? String(time).slice(0, 10) : new Date().toISOString().slice(0, 10);
    const amount = cxEventAmount(event);

    if (!dayMetrics.has(day)) {
      dayMetrics.set(day, { day, visits: 0, leads: 0, purchases: 0, clicks: 0, revenue: 0 });
    }

    const bucket = dayMetrics.get(day);

    typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    pageCounts.set(path, (pageCounts.get(path) || 0) + 1);

    if (type.includes("page") || type.includes("visit")) {
      visits++;
      bucket.visits++;
    }

    if (type.includes("lead") || type.includes("form") || type.includes("contact")) {
      leads++;
      bucket.leads++;
    }

    if (type.includes("purchase") || type.includes("sale") || type.includes("checkout")) {
      purchases++;
      bucket.purchases++;
      revenue += amount || 129;
      bucket.revenue += amount || 129;
    }

    if (type.includes("cta") || type.includes("click")) {
      clicks++;
      bucket.clicks++;
    }
  }

  const days = [...dayMetrics.values()].sort((a, b) => a.day.localeCompare(b.day));

  return {
    total: events.length,
    visits,
    leads,
    purchases,
    clicks,
    revenue,
    days,
    typeCounts: [...typeCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    pageCounts: [...pageCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
  };
}

function cxFallbackSummary() {
  return {
    total: 24968,
    visits: 18426,
    leads: 1284,
    purchases: 392,
    clicks: 2781,
    revenue: 24680,
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
    ],
    pageCounts: [
      ["/", 6820],
      ["/services", 4210],
      ["/contact", 1984],
      ["/work", 1432],
      ["/process", 1130],
    ],
  };
}

function cxPrepared(events) {
  const live = cxSummarize(events);
  if (live.total === 0) {
    return { summary: cxFallbackSummary(), usingFallback: true };
  }
  return { summary: live, usingFallback: false };
}

async function cxInsertEvent(siteId, type, options = {}) {
  const info = await cxTableInfo("events_raw");
  const cols = cxCols(info);

  const siteCol = cxFirst(cols, ["site_id", "site", "client_site_id", "project_id"]);
  const typeCol = cxFirst(cols, ["event_type", "type", "name", "event", "action"]);
  const pathCol = cxFirst(cols, ["path", "url", "page", "pathname", "href", "route"]);
  const timeCol = cxFirst(cols, ["created_at", "timestamp", "time", "event_time", "received_at", "inserted_at"]);
  const payloadCol = cxFirst(cols, ["payload", "metadata", "data", "properties"]);
  const amountCol = cxFirst(cols, ["amount", "revenue", "value", "price", "total"]);

  if (!siteCol) throw new Error("events_raw needs a site_id-like column.");

  const path =
    options.path ||
    (type === "lead"
      ? "/contact"
      : type === "purchase"
      ? "/checkout"
      : type === "cta_click"
      ? "/services"
      : "/");

  const amount = type === "purchase" ? Number(options.amount || 129) : Number(options.amount || 0);
  const eventTime = options.time || new Date();

  const insertCols = [siteCol];
  const values = [siteId];

  if (typeCol) {
    insertCols.push(typeCol);
    values.push(type);
  }

  if (pathCol) {
    insertCols.push(pathCol);
    values.push(path);
  }

  if (timeCol) {
    insertCols.push(timeCol);
    values.push(eventTime);
  }

  if (amountCol) {
    insertCols.push(amountCol);
    values.push(amount);
  }

  if (payloadCol) {
    insertCols.push(payloadCol);
    const payload = {
      demo: true,
      source: "dashboard",
      event_type: type,
      path,
      amount,
      campaign: options.campaign || "client-demo",
      visitor: options.visitor || `visitor_${Math.random().toString(16).slice(2, 8)}`,
    };
    values.push(cxIsJson(info, payloadCol) ? payload : JSON.stringify(payload));
  }

  const sqlCols = insertCols.map(cxQ).join(", ");
  const placeholders = values.map((_, i) => `$${i + 1}`).join(", ");

  await cxDb().query(`INSERT INTO events_raw (${sqlCols}) VALUES (${placeholders})`, values);
}

async function cxInsertReport(siteId, text) {
  const info = await cxTableInfo("daily_reports");
  const cols = cxCols(info);

  const siteCol = cxFirst(cols, ["site_id", "site", "client_site_id", "project_id"]);
  const textCol = cxFirst(cols, ["summary", "report", "content", "body", "insights", "ai_summary"]);
  const dateCol = cxFirst(cols, ["created_at", "report_date", "date", "generated_at"]);

  if (!siteCol || !textCol) return false;

  const insertCols = [siteCol, textCol];
  const values = [siteId, text];

  if (dateCol) {
    insertCols.push(dateCol);
    values.push(new Date());
  }

  const sqlCols = insertCols.map(cxQ).join(", ");
  const placeholders = values.map((_, i) => `$${i + 1}`).join(", ");

  await cxDb().query(`INSERT INTO daily_reports (${sqlCols}) VALUES (${placeholders})`, values);
  return true;
}

function cxReportText(summary) {
  const leadRate = summary.visits ? ((summary.leads / summary.visits) * 100).toFixed(2) : "0.00";
  const purchaseRate = summary.visits ? ((summary.purchases / summary.visits) * 100).toFixed(2) : "0.00";

  return [
    `Constrava AI Report`,
    ``,
    `Traffic is showing ${cxFmt(summary.visits)} visits, ${cxFmt(summary.leads)} leads, and ${cxFmt(summary.purchases)} purchases in the selected demo window.`,
    `Lead conversion is ${leadRate}%. Purchase conversion is ${purchaseRate}%. Estimated revenue is ${cxMoney(summary.revenue)}.`,
    ``,
    `Recommended next actions:`,
    `1. Review the top pages and repeat the content or campaign that produced the most engagement.`,
    `2. Improve the contact/lead step because small gains there create large downstream impact.`,
    `3. Use CTA click behavior to identify which offer should be emphasized in the client pitch.`,
  ].join("\n");
}

function cxJsonForClient(site, events, reports, leads) {
  const { summary, usingFallback } = cxPrepared(events);

  return {
    ok: true,
    usingFallback,
    site: {
      site_id: String(cxValue(site, ["site_id", "id"], "")),
      site_name: String(cxValue(site, ["site_name", "name", "business_name", "domain"], "Client Demo")),
      owner_email: String(cxValue(site, ["owner_email", "email", "contact_email"], "admin@constrava.com")),
      plan: String(cxValue(site, ["plan", "tier", "status"], "demo")),
    },
    summary,
    reports: reports.map((r) => ({
      date: String(cxValue(r, ["report_date", "date", "created_at", "generated_at"], "Latest report")),
      text: String(cxValue(r, ["summary", "report", "content", "body", "insights", "ai_summary"], "")),
    })),
    leads: leads.map((lead) => ({
      name: String(cxValue(lead, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead")),
      email: String(cxValue(lead, ["email", "lead_email", "contact_email"], "lead@example.com")),
      status: String(cxValue(lead, ["status", "stage", "lead_status"], "New")),
      source: String(cxValue(lead, ["source", "channel", "campaign"], "Website")),
      created_at: String(cxValue(lead, ["created_at", "timestamp", "received_at"], "")),
    })),
    recentEvents: events.slice(0, 30).map((event) => ({
      type: cxEventType(event),
      path: cxEventPath(event),
      time: cxEventTime(event),
      amount: cxEventAmount(event),
    })),
  };
}

app.get("/dashboard/data", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const site = await cxFindSite(token);
    if (!site) return res.status(404).json({ ok: false, error: "Site not found." });

    const siteId = String(cxValue(site, ["site_id", "id"], ""));
    const [events, reports, leads] = await Promise.all([
      cxEvents(siteId),
      cxReports(siteId),
      cxCrmLeads(siteId),
    ]);

    res.json(cxJsonForClient(site, events, reports, leads));
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

    const site = await cxFindSite(token);
    if (!site) return res.status(404).json({ ok: false, error: "Site not found." });

    const siteId = String(cxValue(site, ["site_id", "id"], ""));
    await cxInsertEvent(siteId, type);

    res.json({ ok: true, type, site_id: siteId });
  } catch (err) {
    console.error("SIMULATE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/dashboard/seed", async (req, res) => {
  try {
    const token = String(req.query.token || req.body?.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const site = await cxFindSite(token);
    if (!site) return res.status(404).json({ ok: false, error: "Site not found." });

    const siteId = String(cxValue(site, ["site_id", "id"], ""));
    const now = Date.now();

    const types = [
      "page_view", "page_view", "page_view", "page_view", "page_view",
      "cta_click", "cta_click", "lead", "purchase",
    ];

    for (let day = 0; day < 7; day++) {
      const count = 6 + Math.floor(Math.random() * 8);

      for (let i = 0; i < count; i++) {
        const type = types[Math.floor(Math.random() * types.length)];
        const time = new Date(now - day * 86400000 - Math.floor(Math.random() * 72000000));
        await cxInsertEvent(siteId, type, { time });
      }
    }

    res.json({ ok: true, message: "Demo data seeded." });
  } catch (err) {
    console.error("SEED ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/dashboard/report", async (req, res) => {
  try {
    const token = String(req.query.token || req.body?.token || "").trim();
    if (!token) return res.status(400).json({ ok: false, error: "Missing token." });

    const site = await cxFindSite(token);
    if (!site) return res.status(404).json({ ok: false, error: "Site not found." });

    const siteId = String(cxValue(site, ["site_id", "id"], ""));
    const events = await cxEvents(siteId);
    const { summary } = cxPrepared(events);
    const text = cxReportText(summary);

    await cxInsertReport(siteId, text);

    res.json({ ok: true, report: text });
  } catch (err) {
    console.error("REPORT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/dashboard/export.csv", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).send("Missing token.");

    const site = await cxFindSite(token);
    if (!site) return res.status(404).send("Site not found.");

    const siteId = String(cxValue(site, ["site_id", "id"], ""));
    const events = await cxEvents(siteId, 1000);

    const rows = [["type", "path", "time", "amount"]];

    for (const event of events) {
      rows.push([
        cxEventType(event),
        cxEventPath(event),
        cxEventTime(event),
        String(cxEventAmount(event)),
      ]);
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

app.get("/dashboard", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();

    if (!token) {
      return res.status(400).send(`
        <h1>Missing dashboard token</h1>
        <p>Use <code>/dashboard?token=YOUR_TOKEN</code>.</p>
      `);
    }

    const site = await cxFindSite(token);

    if (!site) {
      return res.status(404).send(`
        <h1>Dashboard not found</h1>
        <p>No site was found for that token.</p>
      `);
    }

    const siteId = String(cxValue(site, ["site_id", "id"], ""));
    const siteName = String(cxValue(site, ["site_name", "name", "business_name", "domain"], "Client Demo"));
    const ownerEmail = String(cxValue(site, ["owner_email", "email", "contact_email"], "admin@constrava.com"));
    const plan = String(cxValue(site, ["plan", "tier", "status"], "demo"));

    const [events, reports, leads] = await Promise.all([
      cxEvents(siteId),
      cxReports(siteId),
      cxCrmLeads(siteId),
    ]);

    const initialData = cxJsonForClient(site, events, reports, leads);

    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${cxEsc(siteName)} | Constrava Dashboard</title>

  <style>
    :root {
      --forest:#042f22;
      --forest2:#064e3b;
      --green:#10b981;
      --green2:#22c55e;
      --mint:#d1fae5;
      --mint2:#ecfdf5;
      --ink:#071a14;
      --muted:#5f716a;
      --line:rgba(4,120,87,.16);
      --card:rgba(255,255,255,.86);
      --shadow:0 24px 80px rgba(7,26,20,.10);
    }

    * { box-sizing:border-box; }

    body {
      margin:0;
      font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      color:var(--ink);
      background:
        radial-gradient(circle at 18% 8%,rgba(16,185,129,.20),transparent 30%),
        radial-gradient(circle at 88% 4%,rgba(34,197,94,.16),transparent 28%),
        linear-gradient(135deg,#f7fffb 0%,#eefcf4 42%,#ffffff 100%);
      min-height:100vh;
    }

    .shell { display:grid; grid-template-columns:292px 1fr; min-height:100vh; }

    .sidebar {
      position:sticky;
      top:0;
      height:100vh;
      padding:28px 22px;
      color:white;
      background:radial-gradient(circle at 40% 0%,rgba(34,197,94,.28),transparent 34%),linear-gradient(180deg,#063f2f 0%,#03251d 100%);
      border-right:1px solid rgba(255,255,255,.12);
      overflow:auto;
    }

    .brand { display:flex; align-items:center; gap:14px; margin-bottom:34px; }
    .brand-mark {
      width:43px; height:43px; border-radius:15px;
      background:linear-gradient(135deg,#10b981,#34d399);
      box-shadow:0 18px 50px rgba(16,185,129,.38);
      position:relative;
    }
    .brand-mark:before,.brand-mark:after {
      content:""; position:absolute; background:#ecfdf5; border-radius:999px; transform:rotate(-35deg);
    }
    .brand-mark:before { width:27px; height:7px; left:8px; top:17px; }
    .brand-mark:after { width:7px; height:27px; left:18px; top:8px; }
    .brand h1 { margin:0; font-size:17px; letter-spacing:.18em; }

    .nav-label { margin:28px 10px 10px; color:rgba(255,255,255,.52); font-size:12px; font-weight:800; letter-spacing:.12em; }
    .nav-item {
      height:50px; border-radius:16px; padding:0 15px; display:flex; align-items:center; gap:13px;
      color:rgba(255,255,255,.84); text-decoration:none; margin-bottom:8px; border:1px solid transparent; cursor:pointer;
    }
    .nav-item.active {
      color:white; background:linear-gradient(135deg,rgba(16,185,129,.42),rgba(255,255,255,.10));
      border-color:rgba(110,231,183,.30); box-shadow:inset 4px 0 0 #10b981;
    }
    .nav-icon {
      width:25px; height:25px; display:grid; place-items:center; border-radius:9px; color:#d1fae5;
    }

    .ai-card {
      margin-top:28px; padding:20px; border-radius:22px;
      background:radial-gradient(circle at 100% 0%,rgba(52,211,153,.28),transparent 30%),rgba(255,255,255,.08);
      border:1px solid rgba(255,255,255,.13); box-shadow:0 25px 80px rgba(0,0,0,.18);
    }
    .ai-card strong { display:block; margin-bottom:10px; }
    .ai-card p { color:rgba(255,255,255,.76); line-height:1.55; margin:0 0 16px; }
    .admin {
      margin-top:22px; padding-top:22px; border-top:1px solid rgba(255,255,255,.12);
      display:flex; align-items:center; gap:12px;
    }
    .avatar {
      width:44px; height:44px; border-radius:16px;
      background:linear-gradient(135deg,#6ee7b7,#059669);
      display:grid; place-items:center; font-weight:900;
    }
    .admin span { display:block; font-size:12px; color:rgba(255,255,255,.62); }

    .main { padding:32px clamp(22px,3vw,48px) 56px; overflow:hidden; }
    .topbar { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; margin-bottom:22px; }
    .title h2 { margin:0 0 8px; font-size:clamp(32px,4vw,54px); letter-spacing:-.06em; color:#073b2c; }
    .title p { margin:0; color:var(--muted); }

    .status {
      display:flex; align-items:center; gap:10px; border:1px solid rgba(16,185,129,.22);
      background:rgba(236,253,245,.82); border-radius:17px; padding:12px 15px;
      font-weight:850; box-shadow:0 15px 40px rgba(4,120,87,.08); white-space:nowrap;
    }
    .dot { width:11px; height:11px; background:#10b981; border-radius:50%; box-shadow:0 0 0 6px rgba(16,185,129,.12); }

    .toolbar { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:20px; }
    .btn, select {
      min-height:46px; border:1px solid var(--line); background:rgba(255,255,255,.76);
      border-radius:15px; padding:0 15px; font-weight:800; color:#064e3b;
      box-shadow:0 12px 30px rgba(7,26,20,.055); cursor:pointer;
    }
    .btn.primary {
      background:linear-gradient(135deg,#10b981,#34d399); color:white; border:0;
      box-shadow:0 18px 38px rgba(16,185,129,.28);
    }
    .tip {
      flex:1; min-width:280px; display:flex; align-items:center; justify-content:space-between;
      min-height:46px; border-radius:15px; border:1px solid var(--line);
      background:rgba(255,255,255,.62); color:var(--muted); padding:0 16px; font-size:13px;
    }

    .tabs {
      display:flex; gap:12px; padding:12px; border-radius:22px; background:rgba(255,255,255,.58);
      border:1px solid var(--line); box-shadow:var(--shadow); margin-bottom:20px;
    }
    .tab {
      border:0; border-radius:14px; background:transparent; padding:13px 18px;
      font-weight:900; color:#38534a; cursor:pointer;
    }
    .tab.active {
      color:#047857; background:white; box-shadow:inset 0 -3px 0 #10b981,0 12px 28px rgba(7,26,20,.06);
    }

    .view { display:none; }
    .view.active { display:block; }

    .metrics { display:grid; grid-template-columns:repeat(4,minmax(180px,1fr)); gap:18px; margin-bottom:20px; }
    .metric {
      position:relative; overflow:hidden; min-height:150px; padding:22px; border-radius:25px;
      background:var(--card); border:1px solid var(--line); box-shadow:var(--shadow);
    }
    .metric:after {
      content:""; position:absolute; inset:auto -28px -48px auto; width:130px; height:130px;
      border-radius:999px; background:rgba(16,185,129,.11);
    }
    .metric-top { display:flex; justify-content:space-between; gap:12px; align-items:center; }
    .metric-icon {
      width:52px; height:52px; border-radius:18px; background:linear-gradient(135deg,#d1fae5,#a7f3d0);
      color:#047857; display:grid; place-items:center; font-size:24px; font-weight:950;
    }
    .metric label { display:block; color:#123c30; font-weight:950; margin-top:12px; }
    .metric strong { display:block; font-size:34px; letter-spacing:-.055em; margin:5px 0 3px; }
    .change { color:#059669; font-size:13px; font-weight:850; }

    .spark { width:84px; height:30px; overflow:visible; }
    .spark polyline { fill:none; stroke:#059669; stroke-width:3; stroke-linecap:round; stroke-linejoin:round; }

    .content-grid { display:grid; grid-template-columns:minmax(0,1.55fr) minmax(340px,.9fr); gap:20px; margin-bottom:20px; }
    .bottom-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px; }

    .panel {
      border-radius:26px; background:rgba(255,255,255,.82); border:1px solid var(--line);
      box-shadow:var(--shadow); overflow:hidden;
    }
    .panel-head { padding:22px 24px 0; display:flex; align-items:start; justify-content:space-between; gap:16px; }
    .panel h3 { margin:0 0 4px; font-size:20px; letter-spacing:-.025em; }
    .panel p { margin:0; color:var(--muted); font-size:13px; }
    .panel-actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .ai-btn {
      border:1px solid var(--line); background:rgba(255,255,255,.78); color:#047857;
      border-radius:13px; padding:10px 12px; font-weight:900; cursor:pointer; white-space:nowrap;
    }

    .chart-wrap { padding:10px 18px 18px; position:relative; }
    .traffic-svg { width:100%; min-height:290px; }
    .grid-line { stroke:rgba(7,26,20,.08); stroke-width:1; }
    .chart-line { fill:none; stroke:#047857; stroke-width:4; stroke-linecap:round; stroke-linejoin:round; }
    .chart-area { fill:url(#trafficFill); }
    .chart-dot { fill:#ecfdf5; stroke:#047857; stroke-width:3; cursor:pointer; }
    .chart-dot-core { fill:#10b981; pointer-events:none; }
    .axis-label { fill:#668078; font-size:12px; font-weight:800; }
    .chart-hover-box {
      position:absolute; min-width:150px; pointer-events:none; display:none; z-index:5;
      background:rgba(255,255,255,.94); border:1px solid rgba(4,120,87,.18);
      border-radius:16px; padding:12px 14px; box-shadow:0 18px 45px rgba(7,26,20,.14);
    }
    .chart-hover-box span { display:block; color:#668078; font-size:12px; font-weight:800; }
    .chart-hover-box strong { display:block; font-size:22px; margin-top:4px; }

    .chart-footer {
      margin:0 18px 18px; display:grid; grid-template-columns:repeat(4,1fr);
      border:1px solid var(--line); border-radius:18px; overflow:hidden; background:rgba(236,253,245,.55);
    }
    .chart-stat { padding:16px; border-right:1px solid var(--line); }
    .chart-stat:last-child { border-right:0; }
    .chart-stat strong { display:block; font-size:22px; letter-spacing:-.04em; }
    .chart-stat span { color:var(--muted); font-size:12px; font-weight:750; }

    .funnel { padding:20px 18px 18px; }
    .funnel-row {
      display:grid; grid-template-columns:100px 1fr 92px; align-items:center; gap:12px;
      margin-bottom:12px; padding:14px; border-radius:17px;
      background:linear-gradient(135deg,rgba(236,253,245,.75),rgba(255,255,255,.72));
      border:1px solid rgba(4,120,87,.10);
    }
    .funnel-row strong { display:block; }
    .funnel-row span { color:var(--muted); font-size:12px; font-weight:800; }
    .funnel-bar {
      height:48px; border-radius:13px; background:linear-gradient(135deg,#047857,#34d399);
      box-shadow:inset 0 0 0 1px rgba(255,255,255,.22); transition:.25s ease;
    }
    .funnel-rate { text-align:right; color:#047857; font-weight:950; }
    .funnel-bottom { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:16px; }
    .money-card { border-radius:18px; border:1px solid var(--line); padding:17px; background:white; }
    .money-card span { color:var(--muted); font-size:12px; font-weight:850; }
    .money-card strong { display:block; margin-top:5px; font-size:24px; color:#047857; }

    .simulate { padding:22px 24px 24px; position:relative; overflow:hidden; }
    .simulate:after {
      content:""; position:absolute; right:-60px; bottom:-70px; width:280px; height:190px; border-radius:42px;
      background:linear-gradient(135deg,rgba(16,185,129,.18),transparent),radial-gradient(circle,rgba(16,185,129,.22),transparent 58%);
      transform:rotate(-8deg);
    }
    .simulate-buttons { position:relative; z-index:1; display:flex; flex-wrap:wrap; gap:12px; margin-top:18px; }
    .sim-btn {
      height:50px; border:1px solid var(--line); background:white; color:#064e3b;
      border-radius:16px; padding:0 17px; font-weight:900; cursor:pointer; box-shadow:0 12px 30px rgba(7,26,20,.055);
    }

    .activity-list,.mini-list { padding:16px 22px 22px; }
    .activity-row {
      display:grid; grid-template-columns:42px 1fr auto; gap:12px; align-items:center;
      padding:13px 0; border-bottom:1px solid rgba(4,120,87,.10);
    }
    .activity-row:last-child { border-bottom:0; }
    .activity-icon {
      width:38px; height:38px; border-radius:14px; background:#d1fae5; color:#047857;
      display:grid; place-items:center; font-weight:950;
    }
    .activity-row strong { display:block; font-size:14px; }
    .activity-row span,.activity-row em { color:var(--muted); font-size:12px; font-style:normal; }

    .mini-row { display:flex; justify-content:space-between; gap:16px; padding:12px 0; border-bottom:1px solid rgba(4,120,87,.10); }
    .mini-row:last-child { border-bottom:0; }
    .mini-row span { color:var(--muted); overflow-wrap:anywhere; }
    .mini-row strong { color:#047857; }

    .ai-report-preview {
      margin:16px 22px 22px; display:grid; grid-template-columns:50px 1fr; gap:14px; padding:18px;
      border-radius:20px; background:radial-gradient(circle at 100% 0%,rgba(16,185,129,.16),transparent 34%),#ffffff;
      border:1px solid var(--line);
    }
    .ai-orb {
      width:50px; height:50px; border-radius:18px; background:linear-gradient(135deg,#064e3b,#10b981);
      color:white; display:grid; place-items:center; font-weight:950; box-shadow:0 14px 30px rgba(16,185,129,.22);
    }
    .ai-report-preview p { line-height:1.55; margin-top:6px; }

    .empty-state { color:var(--muted); padding:14px 0; line-height:1.5; }

    .section-anchor { scroll-margin-top:24px; }
    .config-box {
      padding:16px 22px 22px;
    }
    .codebox {
      margin-top:12px; background:#042f22; color:#d1fae5; border-radius:18px; padding:16px;
      font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; overflow:auto;
    }

    .modal-backdrop {
      position:fixed; inset:0; background:rgba(3,37,29,.42); display:none; place-items:center; z-index:30; padding:20px;
    }
    .modal-backdrop.show { display:grid; }
    .modal {
      width:min(720px,100%); background:white; border:1px solid var(--line); border-radius:28px; box-shadow:0 30px 100px rgba(0,0,0,.24);
      padding:24px;
    }
    .modal-top { display:flex; justify-content:space-between; gap:16px; align-items:start; margin-bottom:16px; }
    .modal h3 { margin:0; font-size:24px; }
    .x { border:0; background:#ecfdf5; color:#064e3b; border-radius:12px; width:38px; height:38px; font-weight:950; cursor:pointer; }
    .plans { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
    .plan {
      border:1px solid var(--line); border-radius:20px; padding:18px; background:linear-gradient(180deg,#fff,#f4fff9);
    }
    .plan strong { display:block; font-size:18px; }
    .plan span { color:#047857; font-size:26px; font-weight:950; display:block; margin:12px 0; }

    .toast {
      position:fixed; right:22px; bottom:22px; padding:14px 16px; border-radius:16px;
      color:white; background:#064e3b; box-shadow:0 18px 50px rgba(7,26,20,.22);
      opacity:0; transform:translateY(10px); transition:.2s ease; pointer-events:none; z-index:40;
    }
    .toast.show { opacity:1; transform:translateY(0); }

    @media (max-width:1100px) {
      .shell { grid-template-columns:1fr; }
      .sidebar { position:static; height:auto; }
      .metrics,.content-grid,.bottom-grid { grid-template-columns:1fr; }
    }
    @media (max-width:720px) {
      .main { padding:22px 14px 40px; }
      .topbar,.panel-head { flex-direction:column; }
      .chart-footer,.plans { grid-template-columns:1fr; }
      .funnel-row { grid-template-columns:1fr; }
      .funnel-rate { text-align:left; }
    }
  </style>
</head>

<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark"></div>
        <h1>CONSTRAVA</h1>
      </div>

      <a class="nav-item active" data-tab="analytics"><span class="nav-icon">⌁</span><strong>Analytics</strong></a>
      <a class="nav-item" data-tab="crm"><span class="nav-icon">◎</span><strong>CRM</strong></a>

      <div class="nav-label">ANALYTICS</div>

      <a class="nav-item active" data-scroll="home"><span class="nav-icon">⌂</span><strong>Home</strong></a>
      <a class="nav-item" data-scroll="realtime"><span class="nav-icon">∿</span><strong>Realtime</strong></a>
      <a class="nav-item" data-scroll="acquisition"><span class="nav-icon">◌</span><strong>Acquisition</strong></a>
      <a class="nav-item" data-scroll="engagement"><span class="nav-icon">▣</span><strong>Engagement</strong></a>
      <a class="nav-item" data-scroll="monetization"><span class="nav-icon">$</span><strong>Monetization</strong></a>
      <a class="nav-item" data-scroll="explore"><span class="nav-icon">◇</span><strong>Explore</strong></a>
      <a class="nav-item" data-scroll="ai"><span class="nav-icon">AI</span><strong>AI Studio</strong></a>
      <a class="nav-item" data-scroll="configure"><span class="nav-icon">⚙</span><strong>Configure</strong></a>

      <div class="ai-card">
        <strong>✦ AI Insights</strong>
        <p id="sidebarInsight">Your site traffic is ready to analyze. Generate demo data or review live activity.</p>
        <strong style="cursor:pointer" onclick="aiExplain('report')">View full report →</strong>
      </div>

      <div class="admin">
        <div class="avatar">AD</div>
        <div>
          <strong>Admin</strong>
          <span>${cxEsc(ownerEmail)}</span>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div class="title">
          <h2>Constrava Dashboard</h2>
          <p>Token-auth dashboard • secure it later with accounts if desired 🔒</p>
        </div>

        <div class="status">
          <span class="dot"></span>
          <span id="statusText">Status: ready</span>
        </div>
      </div>

      <div class="toolbar">
        <select id="rangeSelect">
          <option value="7">7 days</option>
          <option value="30">30 days</option>
          <option value="90">90 days</option>
        </select>

        <button class="btn primary" onclick="seedDemo()">Seed demo data</button>
        <button class="btn" onclick="generateReport()">✦ Generate AI report</button>
        <button class="btn" onclick="refreshData()">Refresh</button>
        <button class="btn" onclick="openModal('plans')">Plans</button>
        <button class="btn" onclick="switchTab('crm')">CRM</button>
        <button class="btn" onclick="copyLink()">Copy link</button>
        <a class="btn" id="exportBtn" href="#" style="display:grid;place-items:center;text-decoration:none;">Export CSV</a>

        <div class="tip">
          <span>Tip: use the sidebar tabs • hover the chart • simulate events live</span>
          <strong>✦</strong>
        </div>
      </div>

      <div class="tabs">
        <button class="tab active" data-tab-button="analytics" onclick="switchTab('analytics')">Analytics</button>
        <button class="tab" data-tab-button="crm" onclick="switchTab('crm')">CRM</button>
      </div>

      <section id="analyticsView" class="view active">
        <section id="home" class="section-anchor metrics">
          <div class="metric">
            <div class="metric-top"><div class="metric-icon">☷</div><svg class="spark" viewBox="0 0 84 30"><polyline points="0,24 12,18 24,20 36,12 48,15 60,8 84,4"></polyline></svg></div>
            <label>Visits</label><strong id="mVisits">0</strong><div class="change">↑ 24.6% vs previous 7 days</div>
          </div>
          <div class="metric">
            <div class="metric-top"><div class="metric-icon">◎</div><svg class="spark" viewBox="0 0 84 30"><polyline points="0,24 14,19 28,21 42,15 56,10 70,13 84,6"></polyline></svg></div>
            <label>Leads</label><strong id="mLeads">0</strong><div class="change">↑ 18.3% vs previous 7 days</div>
          </div>
          <div class="metric">
            <div class="metric-top"><div class="metric-icon">▱</div><svg class="spark" viewBox="0 0 84 30"><polyline points="0,26 14,24 28,19 42,21 56,15 70,10 84,7"></polyline></svg></div>
            <label>Purchases</label><strong id="mPurchases">0</strong><div class="change">↑ 16.8% vs previous 7 days</div>
          </div>
          <div class="metric">
            <div class="metric-top"><div class="metric-icon">↗</div><svg class="spark" viewBox="0 0 84 30"><polyline points="0,22 12,18 24,20 36,13 48,16 60,10 84,5"></polyline></svg></div>
            <label>CTA clicks</label><strong id="mClicks">0</strong><div class="change">↑ 22.1% vs previous 7 days</div>
          </div>
        </section>

        <section id="realtime" class="section-anchor content-grid">
          <div class="panel">
            <div class="panel-head">
              <div><h3>Traffic trend</h3><p id="chartSubtitle">Visits per day</p></div>
              <div class="panel-actions">
                <select id="metricSelect">
                  <option value="visits">Visits</option>
                  <option value="leads">Leads</option>
                  <option value="purchases">Purchases</option>
                  <option value="clicks">CTA clicks</option>
                  <option value="revenue">Revenue</option>
                </select>
                <button class="ai-btn" onclick="aiExplain('traffic')">✦ AI explain</button>
              </div>
            </div>
            <div class="chart-wrap">
              <div id="chartTooltip" class="chart-hover-box"></div>
              <svg id="trafficChart" class="traffic-svg" viewBox="0 0 760 300"></svg>
            </div>
            <div class="chart-footer">
              <div class="chart-stat"><strong id="sTotal">0</strong><span>Total selected</span></div>
              <div class="chart-stat"><strong id="sAverage">0</strong><span>Daily average</span></div>
              <div class="chart-stat"><strong id="sBest">0</strong><span>Best day</span></div>
              <div class="chart-stat"><strong>1:42</strong><span>Avg. session duration</span></div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <div><h3>Conversation funnel</h3><p>Visits → Leads → Purchases</p></div>
              <button class="ai-btn" onclick="aiExplain('funnel')">✦ AI explain</button>
            </div>

            <div class="funnel">
              <div class="funnel-row"><div><strong>Visits</strong><span id="fVisits">0</span></div><div class="funnel-bar" id="barVisits"></div><div class="funnel-rate">100%</div></div>
              <div class="funnel-row"><div><strong>Leads</strong><span id="fLeads">0</span></div><div class="funnel-bar" id="barLeads"></div><div class="funnel-rate" id="rateLeads">0%</div></div>
              <div class="funnel-row"><div><strong>Purchases</strong><span id="fPurchases">0</span></div><div class="funnel-bar" id="barPurchases"></div><div class="funnel-rate" id="ratePurchases">0%</div></div>

              <div class="funnel-bottom">
                <div class="money-card"><span>Revenue</span><strong id="revenueText">$0</strong></div>
                <div class="money-card"><span>AOV</span><strong id="aovText">$0</strong></div>
              </div>
            </div>
          </div>
        </section>

        <section id="acquisition" class="section-anchor bottom-grid">
          <div class="panel">
            <div class="panel-head"><div><h3>Top pages</h3><p>Most active routes</p></div></div>
            <div id="topPages" class="mini-list"></div>
          </div>
          <div class="panel">
            <div class="panel-head"><div><h3>Top event types</h3><p>Most common tracked actions</p></div></div>
            <div id="topTypes" class="mini-list"></div>
          </div>
        </section>

        <section id="engagement" class="section-anchor panel" style="margin-bottom:20px">
          <div class="panel-head"><div><h3>Recent activity</h3><p>Latest events connected to this site</p></div></div>
          <div id="activityList" class="activity-list"></div>
        </section>

        <section id="monetization" class="section-anchor bottom-grid">
          <div class="panel simulate">
            <h3>Simulate events</h3>
            <p>Generate demo activity instantly for this client dashboard.</p>
            <div class="simulate-buttons">
              <button class="sim-btn" onclick="simulateEvent('page_view')">◉ Sim page_view</button>
              <button class="sim-btn" onclick="simulateEvent('lead')">◎ Sim lead</button>
              <button class="sim-btn" onclick="simulateEvent('purchase')">▱ Sim purchase</button>
              <button class="sim-btn" onclick="simulateEvent('cta_click')">↗ Sim cta_click</button>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head"><div><h3>Revenue summary</h3><p>Demo revenue and purchase value</p></div></div>
            <div class="mini-list">
              <div class="mini-row"><span>Total revenue</span><strong id="revMini">$0</strong></div>
              <div class="mini-row"><span>Purchases</span><strong id="purchaseMini">0</strong></div>
              <div class="mini-row"><span>Average order value</span><strong id="aovMini">$0</strong></div>
            </div>
          </div>
        </section>

        <section id="explore" class="section-anchor panel" style="margin-bottom:20px">
          <div class="panel-head"><div><h3>Explore</h3><p>Quick analysis tools</p></div></div>
          <div class="mini-list">
            <div class="mini-row"><span>Current chart metric</span><strong id="currentMetricLabel">Visits</strong></div>
            <div class="mini-row"><span>Date range</span><strong id="currentRangeLabel">7 days</strong></div>
            <div class="mini-row"><span>Data mode</span><strong id="dataModeLabel">Demo preview</strong></div>
          </div>
        </section>

        <section id="ai" class="section-anchor panel" style="margin-bottom:20px">
          <div class="panel-head">
            <div><h3>AI report</h3><p>Generated insights and recommended actions</p></div>
            <button class="ai-btn" onclick="generateReport()">✦ Generate</button>
          </div>
          <div id="reportBox"></div>
        </section>

        <section id="configure" class="section-anchor panel">
          <div class="panel-head"><div><h3>Configure</h3><p>Client tracking setup</p></div></div>
          <div class="config-box">
            <button class="btn primary" onclick="copyTrackingScript()">Copy tracking script</button>
            <button class="btn" onclick="copyLink()">Copy dashboard link</button>
            <div class="codebox" id="trackingScript"></div>
          </div>
        </section>
      </section>

      <section id="crmView" class="view">
        <section class="metrics">
          <div class="metric"><div class="metric-icon">◎</div><label>Total leads</label><strong id="crmTotal">0</strong><div class="change">CRM connected</div></div>
          <div class="metric"><div class="metric-icon">✉</div><label>New contacts</label><strong id="crmNew">0</strong><div class="change">From site forms</div></div>
          <div class="metric"><div class="metric-icon">↗</div><label>Follow-ups</label><strong id="crmFollow">3</strong><div class="change">Suggested by AI</div></div>
          <div class="metric"><div class="metric-icon">$</div><label>Pipeline</label><strong>$8.4K</strong><div class="change">Demo estimate</div></div>
        </section>

        <section class="content-grid">
          <div class="panel">
            <div class="panel-head">
              <div><h3>CRM leads</h3><p>Contacts connected to this demo/client site</p></div>
              <button class="ai-btn" onclick="simulateEvent('lead')">Add demo lead</button>
            </div>
            <div id="crmList" class="activity-list"></div>
          </div>

          <div class="panel">
            <div class="panel-head"><div><h3>CRM assistant</h3><p>Suggested next actions</p></div></div>
            <div class="ai-report-preview">
              <div class="ai-orb">AI</div>
              <div>
                <strong>Recommended follow-up</strong>
                <p>Prioritize leads who came from the services page and clicked a CTA before submitting a form. These leads usually have stronger intent.</p>
              </div>
            </div>
          </div>
        </section>
      </section>
    </main>
  </div>

  <div id="modalBackdrop" class="modal-backdrop">
    <div class="modal">
      <div class="modal-top">
        <div><h3 id="modalTitle">Plans</h3><p id="modalText">Upgrade paths for client dashboards.</p></div>
        <button class="x" onclick="closeModal()">×</button>
      </div>
      <div id="modalContent"></div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    const token = ${JSON.stringify(token)};
    const siteId = ${JSON.stringify(siteId)};
    let dashboardData = ${JSON.stringify(initialData)};
    let selectedMetric = "visits";
    let selectedRange = 7;

    const fmt = new Intl.NumberFormat("en-US");
    const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 });

    function toast(message) {
      const el = document.getElementById("toast");
      el.textContent = message;
      el.classList.add("show");
      setTimeout(() => el.classList.remove("show"), 2400);
    }

    function setStatus(text) {
      document.getElementById("statusText").textContent = text;
    }

    function switchTab(tab) {
      document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
      document.querySelectorAll("[data-tab-button]").forEach(b => b.classList.remove("active"));

      document.getElementById(tab + "View").classList.add("active");
      const btn = document.querySelector("[data-tab-button='" + tab + "']");
      if (btn) btn.classList.add("active");

      document.querySelectorAll("[data-tab]").forEach(item => {
        item.classList.toggle("active", item.dataset.tab === tab);
      });
    }

    document.querySelectorAll("[data-tab]").forEach(item => {
      item.addEventListener("click", () => switchTab(item.dataset.tab));
    });

    document.querySelectorAll("[data-scroll]").forEach(item => {
      item.addEventListener("click", () => {
        switchTab("analytics");
        document.querySelectorAll("[data-scroll]").forEach(i => i.classList.remove("active"));
        item.classList.add("active");
        const target = document.getElementById(item.dataset.scroll);
        if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });

    document.getElementById("rangeSelect").addEventListener("change", e => {
      selectedRange = Number(e.target.value);
      renderDashboard();
    });

    document.getElementById("metricSelect").addEventListener("change", e => {
      selectedMetric = e.target.value;
      renderDashboard();
    });

    function metricLabel(metric) {
      return {
        visits: "Visits",
        leads: "Leads",
        purchases: "Purchases",
        clicks: "CTA clicks",
        revenue: "Revenue"
      }[metric] || "Visits";
    }

    function filteredDays() {
      const days = dashboardData.summary.days || [];
      return days.slice(-selectedRange);
    }

    function renderChart() {
      const svg = document.getElementById("trafficChart");
      const tooltip = document.getElementById("chartTooltip");
      const days = filteredDays();

      const w = 760;
      const h = 300;
      const px = 44;
      const py = 34;

      const values = days.map(d => Number(d[selectedMetric] || 0));
      const max = Math.max(...values, 1);

      const coords = days.map((d, i) => {
        const x = px + (i * (w - px * 2)) / Math.max(days.length - 1, 1);
        const y = h - py - (Number(d[selectedMetric] || 0) / max) * (h - py * 2);
        return { ...d, x, y, value: Number(d[selectedMetric] || 0) };
      });

      const line = coords.map(p => p.x + "," + p.y).join(" ");
      const area = px + "," + (h - py) + " " + line + " " + (w - px) + "," + (h - py);

      const grid = [0,1,2,3,4].map(i => {
        const y = py + (i * (h - py * 2)) / 4;
        return '<line x1="' + px + '" y1="' + y + '" x2="' + (w - px) + '" y2="' + y + '" class="grid-line"></line>';
      }).join("");

      const labels = coords.map(p => {
        const label = String(p.day || "").slice(5);
        return '<text x="' + p.x + '" y="' + (h - 7) + '" text-anchor="middle" class="axis-label">' + label + '</text>';
      }).join("");

      const dots = coords.map((p, i) => {
        return '<circle data-i="' + i + '" cx="' + p.x + '" cy="' + p.y + '" r="5.5" class="chart-dot"></circle><circle cx="' + p.x + '" cy="' + p.y + '" r="2.5" class="chart-dot-core"></circle>';
      }).join("");

      svg.innerHTML = \`
        <defs>
          <linearGradient id="trafficFill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stop-color="#10b981" stop-opacity="0.45"></stop>
            <stop offset="58%" stop-color="#34d399" stop-opacity="0.16"></stop>
            <stop offset="100%" stop-color="#ffffff" stop-opacity="0"></stop>
          </linearGradient>
        </defs>
        \${grid}
        <polygon points="\${area}" class="chart-area"></polygon>
        <polyline points="\${line}" class="chart-line"></polyline>
        \${dots}
        \${labels}
      \`;

      svg.querySelectorAll(".chart-dot").forEach(dot => {
        dot.addEventListener("mousemove", e => {
          const p = coords[Number(dot.dataset.i)];
          tooltip.style.display = "block";
          tooltip.style.left = Math.min(e.offsetX + 18, svg.clientWidth - 170) + "px";
          tooltip.style.top = Math.max(e.offsetY - 70, 8) + "px";
          tooltip.innerHTML = '<span>' + p.day + '</span><strong>' + (selectedMetric === "revenue" ? money.format(p.value) : fmt.format(p.value)) + '</strong><span>' + metricLabel(selectedMetric) + '</span>';
        });

        dot.addEventListener("mouseleave", () => {
          tooltip.style.display = "none";
        });
      });

      const total = values.reduce((a,b) => a + b, 0);
      const avg = total / Math.max(values.length, 1);
      const best = Math.max(...values, 0);

      document.getElementById("sTotal").textContent = selectedMetric === "revenue" ? money.format(total) : fmt.format(Math.round(total));
      document.getElementById("sAverage").textContent = selectedMetric === "revenue" ? money.format(avg) : fmt.format(Math.round(avg));
      document.getElementById("sBest").textContent = selectedMetric === "revenue" ? money.format(best) : fmt.format(Math.round(best));
      document.getElementById("chartSubtitle").textContent = metricLabel(selectedMetric) + " per day";
    }

    function renderMiniList(id, items, empty) {
      const el = document.getElementById(id);
      if (!items || !items.length) {
        el.innerHTML = '<div class="empty-state">' + empty + '</div>';
        return;
      }

      el.innerHTML = items.map(([label, count]) => {
        return '<div class="mini-row"><span>' + escapeHtml(label) + '</span><strong>' + fmt.format(count) + '</strong></div>';
      }).join("");
    }

    function renderActivity() {
      const el = document.getElementById("activityList");
      const events = dashboardData.recentEvents || [];

      if (!events.length) {
        el.innerHTML = '<div class="empty-state">No live events yet. Use the simulate buttons to generate activity.</div>';
        return;
      }

      el.innerHTML = events.map(event => {
        const icon = event.type.includes("lead") ? "◎" : event.type.includes("purchase") ? "$" : "↗";
        const time = String(event.time || "Just now").replace("T", " ").slice(0, 19);

        return \`
          <div class="activity-row">
            <div class="activity-icon">\${icon}</div>
            <div><strong>\${escapeHtml(event.type)}</strong><span>\${escapeHtml(event.path)}</span></div>
            <em>\${escapeHtml(time)}</em>
          </div>
        \`;
      }).join("");
    }

    function renderReports() {
      const el = document.getElementById("reportBox");
      const reports = dashboardData.reports || [];

      if (!reports.length) {
        el.innerHTML = \`
          <div class="ai-report-preview">
            <div class="ai-orb">AI</div>
            <div>
              <strong>AI summary preview</strong>
              <p>This dashboard is ready for a client demo. Generate a report after seeding or tracking events to produce a sharper analysis.</p>
            </div>
          </div>
        \`;
        return;
      }

      el.innerHTML = reports.slice(0, 3).map(report => {
        return \`
          <div class="ai-report-preview">
            <div class="ai-orb">AI</div>
            <div>
              <strong>\${escapeHtml(String(report.date).slice(0, 19))}</strong>
              <p>\${escapeHtml(report.text).slice(0, 700)}</p>
            </div>
          </div>
        \`;
      }).join("");
    }

    function renderCrm() {
      const leads = dashboardData.leads || [];
      document.getElementById("crmTotal").textContent = fmt.format(leads.length);
      document.getElementById("crmNew").textContent = fmt.format(leads.filter(l => String(l.status).toLowerCase().includes("new")).length || leads.length);
      document.getElementById("crmFollow").textContent = fmt.format(Math.max(3, Math.ceil(leads.length / 3)));

      const el = document.getElementById("crmList");

      if (!leads.length) {
        el.innerHTML = '<div class="empty-state">No CRM leads found yet. Use “Sim lead” to create lead activity.</div>';
        return;
      }

      el.innerHTML = leads.map(lead => {
        return \`
          <div class="activity-row">
            <div class="activity-icon">◎</div>
            <div><strong>\${escapeHtml(lead.name)}</strong><span>\${escapeHtml(lead.email)} • \${escapeHtml(lead.source)}</span></div>
            <em>\${escapeHtml(lead.status)}</em>
          </div>
        \`;
      }).join("");
    }

    function renderDashboard() {
      const s = dashboardData.summary;
      const leadRate = s.visits ? ((s.leads / s.visits) * 100) : 0;
      const purchaseRate = s.visits ? ((s.purchases / s.visits) * 100) : 0;
      const aov = s.purchases ? s.revenue / s.purchases : 0;

      document.getElementById("mVisits").textContent = fmt.format(s.visits);
      document.getElementById("mLeads").textContent = fmt.format(s.leads);
      document.getElementById("mPurchases").textContent = fmt.format(s.purchases);
      document.getElementById("mClicks").textContent = fmt.format(s.clicks);

      document.getElementById("fVisits").textContent = fmt.format(s.visits);
      document.getElementById("fLeads").textContent = fmt.format(s.leads);
      document.getElementById("fPurchases").textContent = fmt.format(s.purchases);
      document.getElementById("rateLeads").textContent = leadRate.toFixed(2) + "%";
      document.getElementById("ratePurchases").textContent = purchaseRate.toFixed(2) + "%";
      document.getElementById("revenueText").textContent = money.format(s.revenue);
      document.getElementById("aovText").textContent = money.format(aov);
      document.getElementById("revMini").textContent = money.format(s.revenue);
      document.getElementById("purchaseMini").textContent = fmt.format(s.purchases);
      document.getElementById("aovMini").textContent = money.format(aov);

      document.getElementById("barLeads").style.width = Math.max(18, Math.min(100, leadRate * 8)) + "%";
      document.getElementById("barPurchases").style.width = Math.max(18, Math.min(100, purchaseRate * 18)) + "%";

      renderMiniList("topPages", s.pageCounts, "No pages tracked yet.");
      renderMiniList("topTypes", s.typeCounts, "No event types tracked yet.");
      renderActivity();
      renderReports();
      renderCrm();
      renderChart();

      document.getElementById("currentMetricLabel").textContent = metricLabel(selectedMetric);
      document.getElementById("currentRangeLabel").textContent = selectedRange + " days";
      document.getElementById("dataModeLabel").textContent = dashboardData.usingFallback ? "Demo preview" : "Live database";
      document.getElementById("sidebarInsight").textContent = dashboardData.usingFallback
        ? "This dashboard is showing polished demo data. Seed live demo events to make it interactive."
        : "Your dashboard is using live events from Neon and updates when new activity is simulated.";

      document.getElementById("trackingScript").textContent = '<script src="' + location.origin + '/tracker.js" data-site-id="' + siteId + '"><\\/script>';
      document.getElementById("exportBtn").href = "/dashboard/export.csv?token=" + encodeURIComponent(token);
    }

    async function refreshData() {
      setStatus("Status: refreshing...");
      const response = await fetch("/dashboard/data?token=" + encodeURIComponent(token));
      const data = await response.json();

      if (!response.ok || !data.ok) {
        toast(data.error || "Could not refresh dashboard.");
        setStatus("Status: error");
        return;
      }

      dashboardData = data;
      renderDashboard();
      setStatus("Status: ready");
      toast("Dashboard refreshed.");
    }

    async function simulateEvent(type) {
      setStatus("Status: simulating...");
      toast("Creating " + type + " event...");

      const response = await fetch("/dashboard/simulate?token=" + encodeURIComponent(token) + "&type=" + encodeURIComponent(type), {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        toast(data.error || "Could not create event.");
        setStatus("Status: error");
        return;
      }

      await refreshData();
      toast(type + " created.");
    }

    async function seedDemo() {
      setStatus("Status: seeding...");
      toast("Seeding demo activity...");

      const response = await fetch("/dashboard/seed?token=" + encodeURIComponent(token), {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        toast(data.error || "Could not seed demo data.");
        setStatus("Status: error");
        return;
      }

      await refreshData();
      toast("Demo data added.");
    }

    async function generateReport() {
      setStatus("Status: generating report...");
      toast("Generating AI-style report...");

      const response = await fetch("/dashboard/report?token=" + encodeURIComponent(token), {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        toast(data.error || "Could not generate report.");
        setStatus("Status: error");
        return;
      }

      await refreshData();
      switchTab("analytics");
      document.getElementById("ai").scrollIntoView({ behavior: "smooth" });
      toast("Report generated.");
    }

    function aiExplain(topic) {
      const messages = {
        traffic: "Traffic insight: the chart shows how attention changes over time. Use the metric selector to compare visits, leads, purchases, clicks, and revenue.",
        funnel: "Funnel insight: this shows where visitors convert or drop off. A client should focus on the largest step-down between visits, leads, and purchases.",
        report: "AI report: this summarizes performance and suggests next actions. It becomes more useful after events are seeded or tracked live."
      };

      openModal("explain", messages[topic] || "Insight ready.");
    }

    function openModal(kind, text) {
      const backdrop = document.getElementById("modalBackdrop");
      const title = document.getElementById("modalTitle");
      const modalText = document.getElementById("modalText");
      const content = document.getElementById("modalContent");

      if (kind === "plans") {
        title.textContent = "Constrava Plans";
        modalText.textContent = "Example upgrade paths for turning a demo into a client account.";
        content.innerHTML = \`
          <div class="plans">
            <div class="plan"><strong>Starter</strong><span>$99</span><p>Simple dashboard, tracking, and monthly report.</p></div>
            <div class="plan"><strong>Growth</strong><span>$249</span><p>CRM, AI reports, conversion insights, and priority updates.</p></div>
            <div class="plan"><strong>Custom</strong><span>Quote</span><p>Custom workflows, integrations, and advanced automation.</p></div>
          </div>
        \`;
      } else {
        title.textContent = "AI Explain";
        modalText.textContent = "Constrava assistant insight";
        content.innerHTML = '<div class="ai-report-preview"><div class="ai-orb">AI</div><div><strong>Insight</strong><p>' + escapeHtml(text) + '</p></div></div>';
      }

      backdrop.classList.add("show");
    }

    function closeModal() {
      document.getElementById("modalBackdrop").classList.remove("show");
    }

    document.getElementById("modalBackdrop").addEventListener("click", e => {
      if (e.target.id === "modalBackdrop") closeModal();
    });

    async function copyLink() {
      await navigator.clipboard.writeText(location.href);
      toast("Dashboard link copied.");
    }

    async function copyTrackingScript() {
      const script = document.getElementById("trackingScript").textContent;
      await navigator.clipboard.writeText(script);
      toast("Tracking script copied.");
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    renderDashboard();
  </script>
</body>
</html>`);
  } catch (err) {
    console.error("INTERACTIVE DASHBOARD ERROR:", err);
    res.status(500).send(\`
      <h1>Dashboard error</h1>
      <p>\${cxEsc(err.message)}</p>
      <p>Check Render logs and make sure DATABASE_URL is set.</p>
    \`);
  }
});
app.get("/dashboard", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();

    if (!token) {
      return res.status(400).send(`
        <h1>Missing dashboard token</h1>
        <p>Use <code>/dashboard?token=YOUR_TOKEN</code>.</p>
      `);
    }

    const site = await premiumDashFindSite(token);

    if (!site) {
      return res.status(404).send(`
        <h1>Dashboard not found</h1>
        <p>No site was found for that token.</p>
      `);
    }

    const siteId = String(premiumDashValue(site, ["site_id", "id"], ""));
    const siteName = String(
      premiumDashValue(site, ["site_name", "name", "business_name", "domain"], "Client Demo")
    );
    const ownerEmail = String(
      premiumDashValue(site, ["owner_email", "email", "contact_email"], "admin@constrava.com")
    );
    const plan = String(premiumDashValue(site, ["plan", "tier", "status"], "demo"));

    const events = await premiumDashEvents(siteId);
    const reports = await premiumDashReports(siteId);
    const rawSummary = premiumDashSummary(events);

    const usingFallback = rawSummary.total === 0;

    const summary = usingFallback
      ? {
          ...rawSummary,
          total: 18426,
          visits: 18426,
          leads: 1284,
          purchases: 392,
          clicks: 2781,
          revenue: 24680,
          typeCounts: [
            ["page_view", 18426],
            ["cta_click", 2781],
            ["lead", 1284],
            ["purchase", 392],
          ],
          pageCounts: [
            ["/", 6820],
            ["/services", 4210],
            ["/contact", 1984],
            ["/work", 1432],
            ["/process", 1130],
          ],
          dayCounts: rawSummary.dayCounts,
        }
      : rawSummary;

    const trend = premiumDashTrendData(summary);
    const leadRate = summary.visits ? ((summary.leads / summary.visits) * 100).toFixed(2) : "0.00";
    const purchaseRate = summary.visits ? ((summary.purchases / summary.visits) * 100).toFixed(2) : "0.00";
    const aov = summary.purchases ? summary.revenue / summary.purchases : 62.96;

    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${premiumDashEsc(siteName)} | Constrava Dashboard</title>

  <style>
    :root {
      --forest: #042f22;
      --forest-2: #064e3b;
      --green: #10b981;
      --green-2: #22c55e;
      --mint: #d1fae5;
      --mint-2: #ecfdf5;
      --ink: #071a14;
      --muted: #5f716a;
      --line: rgba(4, 120, 87, .16);
      --card: rgba(255,255,255,.86);
      --shadow: 0 24px 80px rgba(7, 26, 20, .10);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 18% 8%, rgba(16,185,129,.20), transparent 30%),
        radial-gradient(circle at 88% 4%, rgba(34,197,94,.16), transparent 28%),
        linear-gradient(135deg, #f7fffb 0%, #eefcf4 42%, #ffffff 100%);
      min-height: 100vh;
    }

    .shell {
      display: grid;
      grid-template-columns: 292px 1fr;
      min-height: 100vh;
    }

    .sidebar {
      position: sticky;
      top: 0;
      height: 100vh;
      padding: 28px 22px;
      color: white;
      background:
        radial-gradient(circle at 40% 0%, rgba(34,197,94,.28), transparent 34%),
        linear-gradient(180deg, #063f2f 0%, #03251d 100%);
      border-right: 1px solid rgba(255,255,255,.12);
      overflow: auto;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
      margin-bottom: 34px;
    }

    .brand-mark {
      width: 43px;
      height: 43px;
      border-radius: 15px;
      background: linear-gradient(135deg, #10b981, #34d399);
      box-shadow: 0 18px 50px rgba(16,185,129,.38);
      position: relative;
    }

    .brand-mark:before,
    .brand-mark:after {
      content: "";
      position: absolute;
      background: #ecfdf5;
      border-radius: 999px;
      transform: rotate(-35deg);
    }

    .brand-mark:before {
      width: 27px;
      height: 7px;
      left: 8px;
      top: 17px;
    }

    .brand-mark:after {
      width: 7px;
      height: 27px;
      left: 18px;
      top: 8px;
    }

    .brand h1 {
      margin: 0;
      font-size: 17px;
      letter-spacing: .18em;
    }

    .nav-label {
      margin: 28px 10px 10px;
      color: rgba(255,255,255,.52);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .12em;
    }

    .nav-item {
      height: 50px;
      border-radius: 16px;
      padding: 0 15px;
      display: flex;
      align-items: center;
      gap: 13px;
      color: rgba(255,255,255,.84);
      text-decoration: none;
      margin-bottom: 8px;
      border: 1px solid transparent;
    }

    .nav-item.active {
      color: white;
      background: linear-gradient(135deg, rgba(16,185,129,.42), rgba(255,255,255,.10));
      border-color: rgba(110,231,183,.30);
      box-shadow: inset 4px 0 0 #10b981;
    }

    .nav-icon {
      width: 25px;
      height: 25px;
      display: grid;
      place-items: center;
      border-radius: 9px;
      color: #d1fae5;
    }

    .ai-card {
      margin-top: 28px;
      padding: 20px;
      border-radius: 22px;
      background:
        radial-gradient(circle at 100% 0%, rgba(52,211,153,.28), transparent 30%),
        rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.13);
      box-shadow: 0 25px 80px rgba(0,0,0,.18);
    }

    .ai-card strong {
      display: block;
      margin-bottom: 10px;
    }

    .ai-card p {
      color: rgba(255,255,255,.76);
      line-height: 1.55;
      margin: 0 0 16px;
    }

    .admin {
      margin-top: 22px;
      padding-top: 22px;
      border-top: 1px solid rgba(255,255,255,.12);
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .avatar {
      width: 44px;
      height: 44px;
      border-radius: 16px;
      background: linear-gradient(135deg, #6ee7b7, #059669);
      display: grid;
      place-items: center;
      font-weight: 900;
    }

    .admin span {
      display: block;
      font-size: 12px;
      color: rgba(255,255,255,.62);
    }

    .main {
      padding: 32px clamp(22px, 3vw, 48px) 56px;
      overflow: hidden;
    }

    .topbar {
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: flex-start;
      margin-bottom: 22px;
    }

    .title h2 {
      margin: 0 0 8px;
      font-size: clamp(32px, 4vw, 54px);
      letter-spacing: -.06em;
      color: #073b2c;
    }

    .title p {
      margin: 0;
      color: var(--muted);
    }

    .status {
      display: flex;
      align-items: center;
      gap: 10px;
      border: 1px solid rgba(16,185,129,.22);
      background: rgba(236,253,245,.82);
      border-radius: 17px;
      padding: 12px 15px;
      font-weight: 850;
      box-shadow: 0 15px 40px rgba(4,120,87,.08);
      white-space: nowrap;
    }

    .dot {
      width: 11px;
      height: 11px;
      background: #10b981;
      border-radius: 50%;
      box-shadow: 0 0 0 6px rgba(16,185,129,.12);
    }

    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }

    .btn,
    select {
      min-height: 46px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.76);
      border-radius: 15px;
      padding: 0 15px;
      font-weight: 800;
      color: #064e3b;
      box-shadow: 0 12px 30px rgba(7,26,20,.055);
      cursor: pointer;
    }

    .btn.primary {
      background: linear-gradient(135deg, #10b981, #34d399);
      color: white;
      border: 0;
      box-shadow: 0 18px 38px rgba(16,185,129,.28);
    }

    .tip {
      flex: 1;
      min-width: 280px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 46px;
      border-radius: 15px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.62);
      color: var(--muted);
      padding: 0 16px;
      font-size: 13px;
    }

    .tabs {
      display: flex;
      gap: 12px;
      padding: 12px;
      border-radius: 22px;
      background: rgba(255,255,255,.58);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      margin-bottom: 20px;
    }

    .tab {
      border: 0;
      border-radius: 14px;
      background: transparent;
      padding: 13px 18px;
      font-weight: 900;
      color: #38534a;
    }

    .tab.active {
      color: #047857;
      background: white;
      box-shadow: inset 0 -3px 0 #10b981, 0 12px 28px rgba(7,26,20,.06);
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(180px, 1fr));
      gap: 18px;
      margin-bottom: 20px;
    }

    .metric {
      position: relative;
      overflow: hidden;
      min-height: 150px;
      padding: 22px;
      border-radius: 25px;
      background: var(--card);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }

    .metric:after {
      content: "";
      position: absolute;
      inset: auto -28px -48px auto;
      width: 130px;
      height: 130px;
      border-radius: 999px;
      background: rgba(16,185,129,.11);
    }

    .metric-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
    }

    .metric-icon {
      width: 52px;
      height: 52px;
      border-radius: 18px;
      background: linear-gradient(135deg, #d1fae5, #a7f3d0);
      color: #047857;
      display: grid;
      place-items: center;
      font-size: 24px;
      font-weight: 950;
    }

    .metric label {
      display: block;
      color: #123c30;
      font-weight: 950;
      margin-top: 12px;
    }

    .metric strong {
      display: block;
      font-size: 34px;
      letter-spacing: -.055em;
      margin: 5px 0 3px;
    }

    .change {
      color: #059669;
      font-size: 13px;
      font-weight: 850;
    }

    .spark {
      width: 84px;
      height: 30px;
      overflow: visible;
    }

    .spark polyline {
      fill: none;
      stroke: #059669;
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .content-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) minmax(340px, .9fr);
      gap: 20px;
      margin-bottom: 20px;
    }

    .panel {
      border-radius: 26px;
      background: rgba(255,255,255,.82);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .panel-head {
      padding: 22px 24px 0;
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 16px;
    }

    .panel h3 {
      margin: 0 0 4px;
      font-size: 20px;
      letter-spacing: -.025em;
    }

    .panel p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
    }

    .panel-actions {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .ai-btn {
      border: 1px solid var(--line);
      background: rgba(255,255,255,.78);
      color: #047857;
      border-radius: 13px;
      padding: 10px 12px;
      font-weight: 900;
      cursor: pointer;
      white-space: nowrap;
    }

    .chart-wrap {
      padding: 10px 18px 18px;
    }

    .traffic-svg {
      width: 100%;
      min-height: 290px;
    }

    .grid-line {
      stroke: rgba(7,26,20,.08);
      stroke-width: 1;
    }

    .chart-line {
      fill: none;
      stroke: #047857;
      stroke-width: 4;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .chart-dot {
      fill: #ecfdf5;
      stroke: #047857;
      stroke-width: 3;
    }

    .chart-dot-core {
      fill: #10b981;
    }

    .axis-label {
      fill: #668078;
      font-size: 12px;
      font-weight: 800;
    }

    .chart-tooltip rect {
      fill: rgba(255,255,255,.92);
      stroke: rgba(4,120,87,.18);
      filter: drop-shadow(0 14px 25px rgba(7,26,20,.12));
    }

    .tip-small {
      fill: #668078;
      font-size: 12px;
      font-weight: 800;
    }

    .tip-big {
      fill: #071a14;
      font-size: 22px;
      font-weight: 950;
    }

    .tip-green {
      fill: #059669;
      font-size: 11px;
      font-weight: 900;
    }

    .chart-footer {
      margin: 0 18px 18px;
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      border: 1px solid var(--line);
      border-radius: 18px;
      overflow: hidden;
      background: rgba(236,253,245,.55);
    }

    .chart-stat {
      padding: 16px;
      border-right: 1px solid var(--line);
    }

    .chart-stat:last-child {
      border-right: 0;
    }

    .chart-stat strong {
      display: block;
      font-size: 22px;
      letter-spacing: -.04em;
    }

    .chart-stat span {
      color: var(--muted);
      font-size: 12px;
      font-weight: 750;
    }

    .funnel {
      padding: 20px 18px 18px;
    }

    .funnel-row {
      display: grid;
      grid-template-columns: 100px 1fr 92px;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
      padding: 14px;
      border-radius: 17px;
      background: linear-gradient(135deg, rgba(236,253,245,.75), rgba(255,255,255,.72));
      border: 1px solid rgba(4,120,87,.10);
    }

    .funnel-row strong {
      display: block;
    }

    .funnel-row span {
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
    }

    .funnel-bar {
      height: 48px;
      border-radius: 13px;
      background: linear-gradient(135deg, #047857, #34d399);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.22);
    }

    .funnel-bar.mid {
      width: 78%;
    }

    .funnel-bar.small {
      width: 54%;
    }

    .funnel-rate {
      text-align: right;
      color: #047857;
      font-weight: 950;
    }

    .funnel-bottom {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 16px;
    }

    .money-card {
      border-radius: 18px;
      border: 1px solid var(--line);
      padding: 17px;
      background: white;
    }

    .money-card span {
      color: var(--muted);
      font-size: 12px;
      font-weight: 850;
    }

    .money-card strong {
      display: block;
      margin-top: 5px;
      font-size: 24px;
      color: #047857;
    }

    .bottom-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }

    .simulate {
      padding: 22px 24px 24px;
      position: relative;
      overflow: hidden;
    }

    .simulate:after {
      content: "";
      position: absolute;
      right: -60px;
      bottom: -70px;
      width: 280px;
      height: 190px;
      border-radius: 42px;
      background:
        linear-gradient(135deg, rgba(16,185,129,.18), transparent),
        radial-gradient(circle, rgba(16,185,129,.22), transparent 58%);
      transform: rotate(-8deg);
    }

    .simulate-buttons {
      position: relative;
      z-index: 1;
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 18px;
    }

    .sim-btn {
      height: 50px;
      border: 1px solid var(--line);
      background: white;
      color: #064e3b;
      border-radius: 16px;
      padding: 0 17px;
      font-weight: 900;
      cursor: pointer;
      box-shadow: 0 12px 30px rgba(7,26,20,.055);
    }

    .activity-list,
    .mini-list {
      padding: 16px 22px 22px;
    }

    .activity-row {
      display: grid;
      grid-template-columns: 42px 1fr auto;
      gap: 12px;
      align-items: center;
      padding: 13px 0;
      border-bottom: 1px solid rgba(4,120,87,.10);
    }

    .activity-row:last-child {
      border-bottom: 0;
    }

    .activity-icon {
      width: 38px;
      height: 38px;
      border-radius: 14px;
      background: #d1fae5;
      color: #047857;
      display: grid;
      place-items: center;
      font-weight: 950;
    }

    .activity-row strong {
      display: block;
      font-size: 14px;
    }

    .activity-row span,
    .activity-row em {
      color: var(--muted);
      font-size: 12px;
      font-style: normal;
    }

    .mini-row {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 12px 0;
      border-bottom: 1px solid rgba(4,120,87,.10);
    }

    .mini-row:last-child {
      border-bottom: 0;
    }

    .mini-row span {
      color: var(--muted);
      overflow-wrap: anywhere;
    }

    .mini-row strong {
      color: #047857;
    }

    .ai-report-preview {
      margin: 16px 22px 22px;
      display: grid;
      grid-template-columns: 50px 1fr;
      gap: 14px;
      padding: 18px;
      border-radius: 20px;
      background:
        radial-gradient(circle at 100% 0%, rgba(16,185,129,.16), transparent 34%),
        #ffffff;
      border: 1px solid var(--line);
    }

    .ai-orb {
      width: 50px;
      height: 50px;
      border-radius: 18px;
      background: linear-gradient(135deg, #064e3b, #10b981);
      color: white;
      display: grid;
      place-items: center;
      font-weight: 950;
      box-shadow: 0 14px 30px rgba(16,185,129,.22);
    }

    .ai-report-preview p {
      line-height: 1.55;
      margin-top: 6px;
    }

    .empty-state {
      color: var(--muted);
      padding: 14px 0;
      line-height: 1.5;
    }

    .toast {
      position: fixed;
      right: 22px;
      bottom: 22px;
      padding: 14px 16px;
      border-radius: 16px;
      color: white;
      background: #064e3b;
      box-shadow: 0 18px 50px rgba(7,26,20,.22);
      opacity: 0;
      transform: translateY(10px);
      transition: .2s ease;
      pointer-events: none;
      z-index: 20;
    }

    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }

    @media (max-width: 1100px) {
      .shell {
        grid-template-columns: 1fr;
      }

      .sidebar {
        position: static;
        height: auto;
      }

      .metrics,
      .content-grid,
      .bottom-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 720px) {
      .main {
        padding: 22px 14px 40px;
      }

      .topbar,
      .panel-head {
        flex-direction: column;
      }

      .chart-footer {
        grid-template-columns: 1fr 1fr;
      }

      .funnel-row {
        grid-template-columns: 1fr;
      }

      .funnel-rate {
        text-align: left;
      }
    }
  </style>
</head>

<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark"></div>
        <h1>CONSTRAVA</h1>
      </div>

      <a class="nav-item active" href="#">
        <span class="nav-icon">⌁</span>
        <strong>Analytics</strong>
      </a>

      <a class="nav-item" href="#">
        <span class="nav-icon">◎</span>
        <strong>CRM</strong>
      </a>

      <div class="nav-label">ANALYTICS</div>

      <a class="nav-item active" href="#"><span class="nav-icon">⌂</span><strong>Home</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">∿</span><strong>Realtime</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">◌</span><strong>Acquisition</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">▣</span><strong>Engagement</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">$</span><strong>Monetization</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">◇</span><strong>Explore</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">AI</span><strong>AI Studio</strong></a>
      <a class="nav-item" href="#"><span class="nav-icon">⚙</span><strong>Configure</strong></a>

      <div class="ai-card">
        <strong>✦ AI Insights</strong>
        <p>Your site traffic is up ${usingFallback ? "24%" : "based on recent activity"} this week. Review the top pages and conversion flow for the best next action.</p>
        <strong>View full report →</strong>
      </div>

      <div class="admin">
        <div class="avatar">AD</div>
        <div>
          <strong>Admin</strong>
          <span>${premiumDashEsc(ownerEmail)}</span>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <div class="title">
          <h2>Constrava Dashboard</h2>
          <p>Token-auth dashboard • secure it later with accounts if desired 🔒</p>
        </div>

        <div class="status">
          <span class="dot"></span>
          Status: ready
        </div>
      </div>

      <div class="toolbar">
        <select>
          <option>7 days</option>
          <option>30 days</option>
          <option>90 days</option>
        </select>

        <button class="btn primary" onclick="seedDemo()">Seed demo data</button>
        <button class="btn" onclick="aiExplain('report')">✦ Generate AI report</button>
        <button class="btn" onclick="location.reload()">Refresh</button>
        <button class="btn">Plans</button>
        <button class="btn">CRM</button>

        <div class="tip">
          <span>Tip: Use the sidebar tabs in Analytics • Click any AI explain button for a popup</span>
          <strong>✦</strong>
        </div>
      </div>

      <div class="tabs">
        <button class="tab active">Analytics</button>
        <button class="tab">CRM</button>
      </div>

      <section class="metrics">
        <div class="metric">
          <div class="metric-top">
            <div class="metric-icon">☷</div>
            ${premiumDashSpark([8, 12, 10, 15, 13, 18, 22])}
          </div>
          <label>Visits</label>
          <strong>${premiumDashFmt(summary.visits)}</strong>
          <div class="change">↑ 24.6% vs previous 7 days</div>
        </div>

        <div class="metric">
          <div class="metric-top">
            <div class="metric-icon">◎</div>
            ${premiumDashSpark([4, 7, 5, 8, 10, 9, 13])}
          </div>
          <label>Leads</label>
          <strong>${premiumDashFmt(summary.leads)}</strong>
          <div class="change">↑ 18.3% vs previous 7 days</div>
        </div>

        <div class="metric">
          <div class="metric-top">
            <div class="metric-icon">▱</div>
            ${premiumDashSpark([2, 3, 5, 4, 6, 8, 9])}
          </div>
          <label>Purchases</label>
          <strong>${premiumDashFmt(summary.purchases)}</strong>
          <div class="change">↑ 16.8% vs previous 7 days</div>
        </div>

        <div class="metric">
          <div class="metric-top">
            <div class="metric-icon">↗</div>
            ${premiumDashSpark([7, 10, 9, 13, 11, 16, 20])}
          </div>
          <label>CTA clicks</label>
          <strong>${premiumDashFmt(summary.clicks)}</strong>
          <div class="change">↑ 22.1% vs previous 7 days</div>
        </div>
      </section>

      <section class="content-grid">
        <div class="panel">
          <div class="panel-head">
            <div>
              <h3>Traffic trend</h3>
              <p>Visits per day ${usingFallback ? "(demo preview)" : "(live)"}</p>
            </div>

            <div class="panel-actions">
              <select>
                <option>Visits</option>
                <option>Leads</option>
                <option>Purchases</option>
              </select>
              <button class="ai-btn" onclick="aiExplain('traffic')">✦ AI explain</button>
            </div>
          </div>

          <div class="chart-wrap">
            ${premiumDashChart(trend)}
          </div>

          <div class="chart-footer">
            <div class="chart-stat">
              <strong>${premiumDashFmt(summary.visits)}</strong>
              <span>Total visits</span>
            </div>
            <div class="chart-stat">
              <strong>${premiumDashFmt(summary.visits / 7)}</strong>
              <span>Daily average</span>
            </div>
            <div class="chart-stat">
              <strong>${premiumDashFmt(Math.max(...trend.map((p) => p.value)))}</strong>
              <span>Best day</span>
            </div>
            <div class="chart-stat">
              <strong>1:42</strong>
              <span>Avg. session duration</span>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <div>
              <h3>Conversation funnel</h3>
              <p>Visits → Leads → Purchases</p>
            </div>
            <button class="ai-btn" onclick="aiExplain('funnel')">✦ AI explain</button>
          </div>

          <div class="funnel">
            <div class="funnel-row">
              <div><strong>Visits</strong><span>${premiumDashFmt(summary.visits)}</span></div>
              <div class="funnel-bar"></div>
              <div class="funnel-rate">100%</div>
            </div>

            <div class="funnel-row">
              <div><strong>Leads</strong><span>${premiumDashFmt(summary.leads)}</span></div>
              <div class="funnel-bar mid"></div>
              <div class="funnel-rate">${leadRate}%</div>
            </div>

            <div class="funnel-row">
              <div><strong>Purchases</strong><span>${premiumDashFmt(summary.purchases)}</span></div>
              <div class="funnel-bar small"></div>
              <div class="funnel-rate">${purchaseRate}%</div>
            </div>

            <div class="funnel-bottom">
              <div class="money-card">
                <span>Revenue ${usingFallback ? "(demo)" : ""}</span>
                <strong>${premiumDashMoney(summary.revenue)}</strong>
              </div>

              <div class="money-card">
                <span>AOV ${usingFallback ? "(demo)" : ""}</span>
                <strong>${premiumDashMoney(aov)}</strong>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="bottom-grid">
        <div class="panel simulate">
          <h3>Simulate events</h3>
          <p>Generate demo activity instantly for this client dashboard.</p>

          <div class="simulate-buttons">
            <button class="sim-btn" onclick="simulateEvent('page_view')">◉ Sim page_view</button>
            <button class="sim-btn" onclick="simulateEvent('lead')">◎ Sim lead</button>
            <button class="sim-btn" onclick="simulateEvent('purchase')">▱ Sim purchase</button>
            <button class="sim-btn" onclick="simulateEvent('cta_click')">↗ Sim cta_click</button>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <div>
              <h3>Top pages</h3>
              <p>Most active demo/client routes</p>
            </div>
          </div>
          <div class="mini-list">
            ${premiumDashList(summary.pageCounts, "No pages tracked yet.")}
          </div>
        </div>
      </section>

      <section class="content-grid" style="margin-top:20px">
        <div class="panel">
          <div class="panel-head">
            <div>
              <h3>Recent activity</h3>
              <p>Latest events connected to this site</p>
            </div>
          </div>
          <div class="activity-list">
            ${premiumDashRows(events)}
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <div>
              <h3>AI report</h3>
              <p>Generated insights and recommended actions</p>
            </div>
            <button class="ai-btn" onclick="aiExplain('report')">✦ AI explain</button>
          </div>
          ${premiumDashReportsHtml(reports)}
        </div>
      </section>
    </main>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    const token = ${JSON.stringify(token)};

    function toast(message) {
      const el = document.getElementById("toast");
      el.textContent = message;
      el.classList.add("show");
      setTimeout(() => el.classList.remove("show"), 2400);
    }

    async function simulateEvent(type) {
      toast("Creating " + type + " event...");

      const response = await fetch("/dashboard/simulate?token=" + encodeURIComponent(token) + "&type=" + encodeURIComponent(type), {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.ok) {
        toast(data.error || "Could not create event.");
        return;
      }

      toast(type + " created.");
      setTimeout(() => location.reload(), 650);
    }

    async function seedDemo() {
      const events = [
        "page_view", "page_view", "page_view", "page_view",
        "cta_click", "cta_click", "lead", "purchase"
      ];

      toast("Seeding demo activity...");

      for (const type of events) {
        await fetch("/dashboard/simulate?token=" + encodeURIComponent(token) + "&type=" + encodeURIComponent(type), {
          method: "POST",
          headers: { "Content-Type": "application/json" }
        });
      }

      toast("Demo data added.");
      setTimeout(() => location.reload(), 900);
    }

    function aiExplain(topic) {
      const messages = {
        traffic: "AI insight: Traffic is strongest around the highest chart peak. The next move is to identify what page or source caused that spike and repeat the campaign.",
        funnel: "AI insight: The funnel shows how many visitors become leads and purchases. Improving the lead step usually creates the biggest gain.",
        report: "AI insight: This dashboard is ready for a client demo. Show traffic, conversion rate, top pages, and the ability to simulate events live."
      };

      alert(messages[topic] || "AI insight ready.");
    }
  </script>
</body>
</html>`);
  } catch (err) {
    console.error("PREMIUM DASHBOARD ERROR:", err);

    res.status(500).send(`
      <h1>Dashboard error</h1>
      <p>${premiumDashEsc(err.message)}</p>
      <p>Check Render logs and make sure DATABASE_URL is set.</p>
    `);
  }
});
// nice routes (optional)
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/services", (req, res) => res.sendFile(path.join(__dirname, "services.html")));
app.get("/process", (req, res) => res.sendFile(path.join(__dirname, "process.html")));
app.get("/work", (req, res) => res.sendFile(path.join(__dirname, "work.html")));
app.get("/contact", (req, res) => res.sendFile(path.join(__dirname, "contact.html")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Constrava running on port", port));
