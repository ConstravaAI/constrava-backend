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

const premiumDashColumnCache = new Map();
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
