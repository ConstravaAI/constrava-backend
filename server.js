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

function esc(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

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

app.get("/dashboard", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();

    if (!token) {
      return res.status(400).send(`
        <h1>Missing dashboard token</h1>
        <p>Use a URL like <code>/dashboard?token=YOUR_TOKEN</code>.</p>
      `);
    }

    const site = await findSiteByToken(token);

    if (!site) {
      return res.status(404).send(`
        <h1>Dashboard not found</h1>
        <p>No site was found for that token.</p>
      `);
    }

    const siteId = String(valueFrom(site, ["site_id", "id"], ""));
    const siteName = String(
      valueFrom(site, ["site_name", "name", "business_name", "domain"], siteId)
    );
    const ownerEmail = String(
      valueFrom(site, ["owner_email", "email", "contact_email"], "Not set")
    );
    const plan = String(valueFrom(site, ["plan", "tier", "status"], "demo"));

    const events = await getEvents(siteId);
    const reports = await getReports(siteId);
    const summary = summarizeEvents(events);

    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${esc(siteName)} | Constrava Dashboard</title>

  <style>
    :root {
      --bg: #07130c;
      --panel: rgba(255,255,255,.08);
      --line: rgba(255,255,255,.14);
      --text: #f3fff7;
      --muted: #b8c8be;
      --green: #2ee66b;
      --green2: #16a34a;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 20% 0%, rgba(46,230,107,.18), transparent 30%),
        linear-gradient(135deg, #07130c, #0b1b10 55%, #06100a);
      min-height: 100vh;
    }

    .wrap {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 30px 0 60px;
    }

    .top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 22px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo {
      width: 42px;
      height: 42px;
      border-radius: 14px;
      background: linear-gradient(135deg, var(--green), var(--green2));
      box-shadow: 0 18px 60px rgba(46,230,107,.25);
    }

    h1, h2, h3, p {
      margin-top: 0;
    }

    .brand h1 {
      font-size: 18px;
      margin-bottom: 2px;
    }

    .brand p,
    .muted {
      color: var(--muted);
      margin-bottom: 0;
    }

    .pill {
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 9px 12px;
      border-radius: 999px;
      color: var(--muted);
      font-size: 13px;
    }

    .hero,
    .panel,
    .metric {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 24px;
      box-shadow: 0 28px 90px rgba(0,0,0,.22);
    }

    .hero {
      padding: 28px;
      margin-bottom: 18px;
      background: linear-gradient(135deg, rgba(255,255,255,.11), rgba(255,255,255,.045));
    }

    .hero-grid {
      display: grid;
      grid-template-columns: 1.4fr .8fr;
      gap: 22px;
    }

    .hero h2 {
      font-size: clamp(32px, 5vw, 58px);
      line-height: .95;
      letter-spacing: -.06em;
      margin-bottom: 12px;
    }

    .meta {
      display: grid;
      gap: 10px;
    }

    .meta-card {
      border: 1px solid var(--line);
      background: rgba(0,0,0,.17);
      border-radius: 18px;
      padding: 14px;
      overflow-wrap: anywhere;
    }

    .meta-card span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      letter-spacing: .08em;
      text-transform: uppercase;
      margin-bottom: 4px;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 18px;
    }

    .metric {
      padding: 18px;
      min-height: 118px;
    }

    .metric span {
      color: var(--muted);
      font-size: 13px;
    }

    .metric strong {
      display: block;
      font-size: 34px;
      letter-spacing: -.05em;
      margin-top: 16px;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }

    .panel {
      padding: 20px;
      overflow: auto;
    }

    .list-row {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      padding: 12px 0;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
    }

    .list-row:last-child {
      border-bottom: 0;
    }

    .list-row strong {
      color: var(--text);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }

    th,
    td {
      padding: 13px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }

    th {
      color: var(--muted);
      text-transform: uppercase;
      font-size: 12px;
      letter-spacing: .08em;
    }

    td {
      overflow-wrap: anywhere;
    }

    .empty {
      color: var(--muted);
      padding: 10px 0;
    }

    .report-card {
      border: 1px solid var(--line);
      background: rgba(0,0,0,.16);
      border-radius: 16px;
      padding: 14px;
      margin-top: 10px;
    }

    pre {
      white-space: pre-wrap;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
      margin-bottom: 0;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }

    button,
    a.button {
      border: 0;
      border-radius: 14px;
      padding: 12px 14px;
      background: var(--green);
      color: #031006;
      font-weight: 800;
      text-decoration: none;
      cursor: pointer;
    }

    .secondary {
      background: rgba(255,255,255,.10);
      color: var(--text);
      border: 1px solid var(--line);
    }

    @media (max-width: 850px) {
      .hero-grid,
      .grid {
        grid-template-columns: 1fr;
      }

      .metrics {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 520px) {
      .metrics {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>

<body>
  <main class="wrap">
    <header class="top">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava AI</h1>
          <p>Client analytics dashboard</p>
        </div>
      </div>

      <div class="pill">${esc(plan)} dashboard</div>
    </header>

    <section class="hero">
      <div class="hero-grid">
        <div>
          <h2>${esc(siteName)}</h2>
          <p class="muted">
            This dashboard shows recent website activity, leads, conversions,
            and AI reports connected to this demo/client site.
          </p>

          <div class="actions">
            <button onclick="copyLink()">Copy dashboard link</button>
            <a class="button secondary" href="/api/dashboard?token=${encodeURIComponent(token)}">
              View JSON
            </a>
          </div>

          <p id="status" class="muted" style="margin-top:12px"></p>
        </div>

        <div class="meta">
          <div class="meta-card">
            <span>Site ID</span>
            <strong>${esc(siteId)}</strong>
          </div>

          <div class="meta-card">
            <span>Owner</span>
            <strong>${esc(ownerEmail)}</strong>
          </div>

          <div class="meta-card">
            <span>Events Loaded</span>
            <strong>${esc(events.length)}</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="metrics">
      <div class="metric">
        <span>Total Events</span>
        <strong>${esc(summary.total)}</strong>
      </div>

      <div class="metric">
        <span>Page Views</span>
        <strong>${esc(summary.pageViews)}</strong>
      </div>

      <div class="metric">
        <span>Leads</span>
        <strong>${esc(summary.leads)}</strong>
      </div>

      <div class="metric">
        <span>Purchases</span>
        <strong>${esc(summary.purchases)}</strong>
      </div>
    </section>

    <section class="grid">
      <div class="panel">
        <h3>Top Event Types</h3>
        ${renderList(summary.topTypes)}
      </div>

      <div class="panel">
        <h3>Top Pages</h3>
        ${renderList(summary.topPages)}
      </div>
    </section>

    <section class="panel">
      <h3>Recent Activity</h3>
      ${renderRows(events.slice(0, 30))}
    </section>

    <section class="panel" style="margin-top:18px">
      <h3>Daily Reports</h3>
      ${renderReports(reports)}
    </section>
  </main>

  <script>
    async function copyLink() {
      await navigator.clipboard.writeText(location.href);
      document.getElementById("status").textContent = "Dashboard link copied.";
    }
  </script>
</body>
</html>`);
  } catch (err) {
    console.error("DASHBOARD ERROR:", err);

    res.status(500).send(`
      <h1>Dashboard error</h1>
      <p>${esc(err.message)}</p>
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
