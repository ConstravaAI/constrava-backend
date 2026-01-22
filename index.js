// index.js (ESM) — Constrava MVP backend
// ✅ Neon Postgres (pg)
// ✅ Event collector (/events)
// ✅ Site onboarding (/sites) generates site_id + dashboard_token
// ✅ Secure dashboard (/dashboard?token=...)
// ✅ Reports: generate, list, latest (all token-secured)
// ✅ Optional: email latest report via Resend (/email-latest)
// ✅ Tracker script served at /tracker.js
// ✅ Auth: /auth/register + /auth/login (JWT)  (for future login-based dashboard)

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL env var");
}

const pool = new Pool({ connectionString: DATABASE_URL });

/** ---------------------------
 *  Helpers
 *  -------------------------*/
function makeSiteId() {
  return "site_" + crypto.randomBytes(6).toString("hex");
}

function publicBaseUrl(req) {
  return (
    process.env.PUBLIC_BASE_URL ||
    `${req.protocol}://${req.get("host")}` ||
    "https://constrava-backend.onrender.com"
  );
}

async function siteIdFromToken(token) {
  if (!token) return null;
  const r = await pool.query(
    "SELECT site_id FROM sites WHERE dashboard_token = $1",
    [token]
  );
  return r.rows[0]?.site_id || null;
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name} env var`);
  return v;
}

// JWT middleware (for later login-based dashboard / APIs)
function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: "Missing token" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.auth = payload; // { user_id, site_id, email }
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid token" });
  }
}

/** ---------------------------
 *  Boot: ensure tables exist
 *  -------------------------*/
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      site_id TEXT PRIMARY KEY,
      site_name TEXT NOT NULL,
      owner_email TEXT NOT NULL,
      dashboard_token TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS events_raw (
      id BIGSERIAL PRIMARY KEY,
      site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
      event_name TEXT NOT NULL,
      page_type TEXT,
      device TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_reports (
      id BIGSERIAL PRIMARY KEY,
      site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
      report_date DATE NOT NULL,
      report_text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(site_id, report_date)
    );
  `);

  console.log("Tables ensured ✅");
}

ensureTables().catch((e) => console.error("ensureTables failed:", e.message));

/** ---------------------------
 *  Basic routes
 *  -------------------------*/
app.get("/", (req, res) => res.send("Backend is running ✅"));

app.get("/db-test", async (req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Onboarding: create a site
 *  POST /sites { site_name, owner_email }
 *  -------------------------*/
app.post("/sites", async (req, res) => {
  try {
    const { site_name, owner_email } = req.body;

    if (!site_name || !owner_email) {
      return res
        .status(400)
        .json({ ok: false, error: "site_name and owner_email required" });
    }

    let site_id = makeSiteId();
    const token = crypto.randomUUID();

    for (let i = 0; i < 3; i++) {
      try {
        await pool.query(
          `INSERT INTO sites (site_id, site_name, owner_email, dashboard_token)
           VALUES ($1, $2, $3, $4)`,
          [site_id, site_name, owner_email, token]
        );
        break;
      } catch (e) {
        if (i === 2) throw e;
        site_id = makeSiteId();
      }
    }

    const base = publicBaseUrl(req);

    res.json({
      ok: true,
      site_id,
      install_snippet: `<script src="${base}/tracker.js" data-site-id="${site_id}"></script>`,
      client_dashboard_url: `${base}/dashboard?token=${token}`,
      token // (optional) for your testing
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Tracker script (client embeds)
 *  GET /tracker.js
 *  -------------------------*/
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");

  res.send(`
(function () {
  try {
    var script = document.currentScript;
    if (!script) return;

    var siteId = script.getAttribute("data-site-id");
    if (!siteId) return;

    var endpoint = "${process.env.PUBLIC_EVENTS_URL || "https://constrava-backend.onrender.com"}" + "/events";

    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        site_id: siteId,
        event_name: "page_view",
        page_type: window.location.pathname,
        device: /Mobi|Android/i.test(navigator.userAgent) ? "mobile" : "desktop"
      })
    }).catch(function(){});
  } catch (e) {}
})();
`);
});

/** ---------------------------
 *  Receive events
 *  POST /events
 *  -------------------------*/
app.post("/events", async (req, res) => {
  const { site_id, event_name, page_type, device } = req.body;

  if (!site_id || !event_name) {
    return res.status(400).json({ ok: false, error: "site_id and event_name required" });
  }

  try {
    const site = await pool.query("SELECT 1 FROM sites WHERE site_id = $1", [site_id]);
    if (site.rows.length === 0) {
      return res.status(403).json({ ok: false, error: "Invalid site_id" });
    }

    await pool.query(
      `INSERT INTO events_raw (site_id, event_name, page_type, device)
       VALUES ($1, $2, $3, $4)`,
      [site_id, event_name, page_type || null, device || null]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Token-secured: list reports
 *  GET /reports?token=...&limit=30
 *  -------------------------*/
app.get("/reports", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });
    }

    const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);

    const r = await pool.query(
      `
      SELECT site_id, report_date, created_at, LEFT(report_text, 220) AS preview
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT $2
      `,
      [site_id, limit]
    );

    res.json({ ok: true, reports: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Token-secured: latest report
 *  GET /reports/latest?token=...
 *  -------------------------*/
app.get("/reports/latest", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });
    }

    const r = await pool.query(
      `
      SELECT site_id, report_date, report_text, created_at
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "No report found" });
    }

    res.json({ ok: true, report: r.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Generate + save report (manual trigger)
 *  POST /generate-report { token? }
 *  -------------------------*/
app.post("/generate-report", async (req, res) => {
  try {
    const token = req.body?.token || req.query?.token || null;
    let siteIds = [];

    if (token) {
      const sid = await siteIdFromToken(token);
      if (!sid) return res.status(401).json({ ok: false, error: "Unauthorized. Invalid token" });
      siteIds = [sid];
    } else {
      const s = await pool.query(`
        SELECT DISTINCT site_id
        FROM events_raw
        WHERE created_at::date = CURRENT_DATE
      `);
      siteIds = s.rows.map((x) => x.site_id);

      if (siteIds.length === 0) {
        const all = await pool.query(`SELECT site_id FROM sites LIMIT 50`);
        siteIds = all.rows.map((x) => x.site_id);
      }
    }

    const results = [];

    for (const site_id of siteIds) {
      const metricsRes = await pool.query(
        `
        SELECT $1::text as site_id, COUNT(*)::int AS total_events
        FROM events_raw
        WHERE site_id = $1 AND created_at::date = CURRENT_DATE
        `,
        [site_id]
      );

      const metrics = metricsRes.rows;

      const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");

      const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: process.env.OPENAI_MODEL || "gpt-4o",
          messages: [
            {
              role: "system",
              content: "You generate short daily business reports. Be specific, actionable, and concise."
            },
            {
              role: "user",
              content:
                `Here are today's metrics (JSON): ${JSON.stringify(metrics)}\n` +
                `Write a daily report with:\n1) Summary\n2) 3 prioritized next actions\n3) One metric to watch tomorrow\n`
            }
          ]
        })
      });

      const aiData = await aiRes.json();
      const reportText = aiData?.choices?.[0]?.message?.content;

      if (!reportText) {
        results.push({ site_id, ok: false, error: "AI response missing" });
        continue;
      }

      const saved = await pool.query(
        `
        INSERT INTO daily_reports (site_id, report_date, report_text)
        VALUES ($1, CURRENT_DATE, $2)
        ON CONFLICT (site_id, report_date)
        DO UPDATE SET report_text = EXCLUDED.report_text
        RETURNING site_id, report_date, report_text, created_at
        `,
        [site_id, reportText]
      );

      results.push({ ok: true, report: saved.rows[0] });
    }

    res.json({ ok: true, results });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Email latest report via Resend (manual)
 *  POST /email-latest { token, to_email }
 *  -------------------------*/
app.post("/email-latest", async (req, res) => {
  try {
    const { token, to_email } = req.body || {};

    if (!to_email) {
      return res.status(400).json({ ok: false, error: "to_email required" });
    }

    const site_id = await siteIdFromToken(token);
    if (!site_id) {
      return res.status(401).json({ ok: false, error: "Unauthorized. Invalid token" });
    }

    const r = await pool.query(
      `
      SELECT report_text, report_date
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "No report found" });
    }

    const RESEND_API_KEY = requireEnv("RESEND_API_KEY");
    const from = process.env.FROM_EMAIL || "onboarding@resend.dev";

    const emailRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from,
        to: [to_email],
        subject: `Daily Report (${site_id})`,
        html: `<pre style="white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;">${r.rows[0].report_text}</pre>`
      })
    });

    const emailData = await emailRes.json();
    res.json({ ok: true, resend: emailData });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});
// DASHBOARD SUMMARY (6 boxes)
// GET /dashboard/summary?token=...
app.get("/dashboard/summary", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });
    }

    // 1) Today events + Yesterday events
    const todayRes = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM events_raw
       WHERE site_id = $1 AND created_at::date = CURRENT_DATE`,
      [site_id]
    );

    const ydayRes = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM events_raw
       WHERE site_id = $1 AND created_at::date = CURRENT_DATE - INTERVAL '1 day'`,
      [site_id]
    );

    const today_total = todayRes.rows[0]?.total ?? 0;
    const yday_total = ydayRes.rows[0]?.total ?? 0;

    // 2) Engagement: actions per page_view (approx)
    const pvRes = await pool.query(
      `SELECT COUNT(*)::int AS page_views
       FROM events_raw
       WHERE site_id = $1
         AND created_at::date = CURRENT_DATE
         AND event_name = 'page_view'`,
      [site_id]
    );
    const page_views = pvRes.rows[0]?.page_views ?? 0;
    const actions_per_visit = page_views > 0 ? (today_total / page_views) : 0;

    let engagement_label = "Low";
    if (actions_per_visit >= 2.2) engagement_label = "High";
    else if (actions_per_visit >= 1.3) engagement_label = "Medium";

    // 3) Top Page today
    const topPageRes = await pool.query(
      `SELECT page_type, COUNT(*)::int AS views
       FROM events_raw
       WHERE site_id = $1 AND created_at::date = CURRENT_DATE
       GROUP BY page_type
       ORDER BY views DESC
       LIMIT 1`,
      [site_id]
    );
    const top_page = topPageRes.rows[0]?.page_type || "(none)";
    const top_page_views = topPageRes.rows[0]?.views ?? 0;

    // 4) Devices today
    const deviceRes = await pool.query(
      `SELECT COALESCE(device,'unknown') AS device, COUNT(*)::int AS c
       FROM events_raw
       WHERE site_id = $1 AND created_at::date = CURRENT_DATE
       GROUP BY COALESCE(device,'unknown')`,
      [site_id]
    );

    const deviceCounts = {};
    for (const row of deviceRes.rows) deviceCounts[row.device] = row.c;

    const desktop = deviceCounts.desktop ?? 0;
    const mobile = deviceCounts.mobile ?? 0;
    const unknown = deviceCounts.unknown ?? 0;
    const devices_total = desktop + mobile + unknown;

    const desktop_pct = devices_total ? Math.round((desktop / devices_total) * 100) : 0;
    const mobile_pct = devices_total ? Math.round((mobile / devices_total) * 100) : 0;

    // 5) Last Activity
    const lastRes = await pool.query(
      `SELECT MAX(created_at) AS last_event_at
       FROM events_raw
       WHERE site_id = $1`,
      [site_id]
    );
    const last_event_at = lastRes.rows[0]?.last_event_at || null;

    // 6) Quick Insight: first line / first sentence from latest report
    const reportRes = await pool.query(
      `SELECT report_text
       FROM daily_reports
       WHERE site_id = $1
       ORDER BY report_date DESC, created_at DESC
       LIMIT 1`,
      [site_id]
    );

    const report_text = reportRes.rows[0]?.report_text || "";
    const firstLine = report_text.split("\n").find(l => l.trim().length > 0) || "";
    const quick_insight = firstLine.slice(0, 160);

    res.json({
      ok: true,
      site_id,

      today_total,
      yday_total,
      delta: today_total - yday_total,

      engagement_label,
      actions_per_visit: Number(actions_per_visit.toFixed(2)),

      top_page,
      top_page_views,

      desktop_pct,
      mobile_pct,
      desktop,
      mobile,
      unknown,

      last_event_at,
      quick_insight
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 *  Secure Dashboard UI (token-based)
 *  GET /dashboard?token=...
 *  -------------------------*/
app.get("/dashboard", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");
    }

    res.setHeader("Content-Type", "text/html");
    res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Constrava Dashboard</title>
  <style>
    :root{
      --bg:#0b0f19;
      --panel:#111827;
      --panel2:#0f172a;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --border:rgba(255,255,255,.08);
      --accent:#60a5fa;
      --accent2:#34d399;
      --danger:#fb7185;
      --shadow: 0 10px 30px rgba(0,0,0,.35);
      --radius:16px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 800px at 20% -10%, rgba(96,165,250,.25), transparent 60%),
                  radial-gradient(900px 600px at 90% 0%, rgba(52,211,153,.18), transparent 55%),
                  var(--bg);
      color:var(--text);
    }
    .wrap{max-width:1100px; margin:0 auto; padding:28px 18px 60px;}
    .topbar{
      display:flex; align-items:center; justify-content:space-between;
      gap:14px; padding:18px 18px;
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    .brand{display:flex; align-items:center; gap:12px;}
    .logo{
      width:40px; height:40px; border-radius:12px;
      background: linear-gradient(135deg, rgba(96,165,250,.9), rgba(52,211,153,.85));
      box-shadow: 0 10px 25px rgba(96,165,250,.25);
    }
    h1{font-size:18px; margin:0;}
    .sub{font-size:12px; color:var(--muted); margin-top:2px;}
    .controls{display:flex; gap:10px; align-items:center; flex-wrap:wrap;}
    .pill{
      font-size:12px; color: var(--muted);
      border:1px solid var(--border);
      padding:6px 10px;
      border-radius:999px;
      background: rgba(15,23,42,.6);
    }
    .btn{
      padding:10px 14px;
      border-radius:12px;
      border:1px solid var(--border);
      background: rgba(96,165,250,.12);
      color: var(--text);
      cursor:pointer;
      font-weight:600;
    }
    .btn:hover{border-color: rgba(96,165,250,.5)}

    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
    }

    .statsGrid{
      margin-top:16px;
      display:grid;
      grid-template-columns: repeat(3, 1fr);
      gap:12px;
    }
    @media (max-width: 900px){
      .statsGrid{grid-template-columns:1fr}
    }
    .statTitle{font-size:12px; color:var(--muted)}
    .statValue{font-size:20px; font-weight:800; margin-top:6px}
    .statSub{font-size:12px; color:var(--muted); margin-top:6px}
    .deltaUp{color: var(--accent2); font-weight:800}
    .deltaDown{color: var(--danger); font-weight:800}

    .grid{
      margin-top:14px;
      display:grid;
      grid-template-columns: 1.2fr .8fr;
      gap:16px;
    }
    @media (max-width: 900px){ .grid{grid-template-columns:1fr} }

    .row{display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;}
    .status{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);}
    .dot{
      width:8px; height:8px; border-radius:50%;
      background: var(--accent2);
      box-shadow: 0 0 0 6px rgba(52,211,153,.12);
    }
    .latest{
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
      font-size: 13px;
      line-height: 1.45;
      background: rgba(15,23,42,.65);
      border:1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      overflow:auto;
      min-height: 220px;
    }
    .muted{color:var(--muted); font-size:12px}
    .historyItem{
      padding:12px;
      border-radius: 14px;
      border:1px solid var(--border);
      background: rgba(15,23,42,.55);
      margin-top:10px;
    }
    .historyItem .date{font-weight:700; font-size:12px}
    .historyItem .preview{margin-top:8px; font-size:13px; color: var(--text)}
    .err{color: var(--danger); font-weight:700}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava Dashboard</h1>
          <div class="sub">Daily AI reports • MVP Analytics</div>
        </div>
      </div>

      <div class="controls">
        <span class="pill">Site: <b>${site_id}</b></span>
        <button class="btn" onclick="refreshAll()">Refresh</button>
      </div>
    </div>

    <!-- 6 NEW BOXES -->
    <div class="statsGrid">
      <div class="card">
        <div class="statTitle">Today</div>
        <div class="statValue" id="todayVal">—</div>
        <div class="statSub" id="todayDelta">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Engagement</div>
        <div class="statValue" id="engLabel">—</div>
        <div class="statSub" id="engSub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Top Page</div>
        <div class="statValue" id="topPage">—</div>
        <div class="statSub" id="topPageSub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Devices</div>
        <div class="statValue" id="devicesVal">—</div>
        <div class="statSub" id="devicesSub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Last Activity</div>
        <div class="statValue" id="lastVal">—</div>
        <div class="statSub" id="lastSub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Quick Insight</div>
        <div class="statValue" style="font-size:14px; font-weight:800; line-height:1.3;" id="insightVal">—</div>
        <div class="statSub">From your latest report</div>
      </div>
    </div>

    <!-- EXISTING REPORT PANELS -->
    <div class="grid">
      <div class="card">
        <div class="row">
          <div>
            <div class="muted">Latest report</div>
            <div id="latestMeta" class="muted"></div>
          </div>
          <div class="status"><span class="dot"></span><span id="statusText">Ready</span></div>
        </div>
        <div id="latest" class="latest">Loading...</div>
      </div>

      <div class="card">
        <div class="row" style="margin:0 0 10px 0;">
          <div>
            <div style="font-weight:800;">Report History</div>
            <div class="muted">Recent reports for this site.</div>
          </div>
          <span class="pill" id="countPill">0</span>
        </div>
        <div id="history"></div>
      </div>
    </div>
  </div>

<script>
  const base = location.origin;
  const token = new URLSearchParams(location.search).get("token");

  function setStatus(text, isError=false){
    const el = document.getElementById("statusText");
    el.textContent = text;
    el.className = isError ? "err" : "";
  }

  function timeAgo(iso){
    if(!iso) return "No events yet";
    const then = new Date(iso).getTime();
    const now = Date.now();
    const s = Math.max(0, Math.floor((now-then)/1000));
    if (s < 60) return s + "s ago";
    const m = Math.floor(s/60);
    if (m < 60) return m + "m ago";
    const h = Math.floor(m/60);
    if (h < 24) return h + "h ago";
    const d = Math.floor(h/24);
    return d + "d ago";
  }

  async function loadSummary(){
    const r = await fetch(\`\${base}/dashboard/summary?token=\${encodeURIComponent(token)}\`);
    const data = await r.json();
    if(!data.ok){
      // keep dashboard usable even if summary fails
      document.getElementById("todayVal").textContent = "—";
      document.getElementById("todayDelta").textContent = data.error || "Summary error";
      return;
    }

    // Today + delta
    document.getElementById("todayVal").textContent = data.today_total + " events";
    const d = data.delta;
    const deltaEl = document.getElementById("todayDelta");
    if (d > 0) deltaEl.innerHTML = \`<span class="deltaUp">▲ +\${d}</span> vs yesterday\`;
    else if (d < 0) deltaEl.innerHTML = \`<span class="deltaDown">▼ \${d}</span> vs yesterday\`;
    else deltaEl.textContent = "No change vs yesterday";

    // Engagement
    document.getElementById("engLabel").textContent = data.engagement_label;
    document.getElementById("engSub").textContent =
      (data.actions_per_visit ? data.actions_per_visit : 0) + " actions per visit (approx)";

    // Top page
    document.getElementById("topPage").textContent = data.top_page;
    document.getElementById("topPageSub").textContent = data.top_page_views + " views today";

    // Devices
    document.getElementById("devicesVal").textContent = data.desktop_pct + "% desktop";
    document.getElementById("devicesSub").textContent =
      data.mobile_pct + "% mobile (+" + (data.unknown || 0) + " unknown)";

    // Last activity
    document.getElementById("lastVal").textContent = timeAgo(data.last_event_at);
    document.getElementById("lastSub").textContent = data.last_event_at ? new Date(data.last_event_at).toLocaleString() : "";

    // Quick insight
    document.getElementById("insightVal").textContent = data.quick_insight || "Generate a report to see this.";
  }

  async function loadLatest() {
    setStatus("Loading latest...");
    const meta = document.getElementById("latestMeta");
    const box = document.getElementById("latest");
    box.textContent = "Loading...";

    const r = await fetch(\`\${base}/reports/latest?token=\${encodeURIComponent(token)}\`);
    const data = await r.json();

    if (!data.ok) {
      setStatus("Ready");
      meta.textContent = "";
      box.textContent = data.error || "No latest report";
      return;
    }

    const d = new Date(data.report.report_date);
    meta.textContent = \`\${d.toDateString()} • \${data.report.site_id}\`;
    box.textContent = data.report.report_text;
    setStatus("Up to date");
  }

  async function loadHistory() {
    setStatus("Loading history...");
    const el = document.getElementById("history");
    const pill = document.getElementById("countPill");
    el.innerHTML = "";

    const r = await fetch(\`\${base}/reports?limit=30&token=\${encodeURIComponent(token)}\`);
    const data = await r.json();

    if (!data.ok) {
      el.innerHTML = \`<div class="historyItem"><div class="err">\${data.error || "No history"}</div></div>\`;
      pill.textContent = "0";
      setStatus("Ready");
      return;
    }

    pill.textContent = data.reports.length;

    el.innerHTML = data.reports.map(rep => {
      const d = new Date(rep.report_date);
      const safePreview = escapeHtml(rep.preview || "");
      return \`
        <div class="historyItem">
          <div class="date">\${d.toDateString()}</div>
          <div class="preview">\${safePreview}...</div>
        </div>
      \`;
    }).join("");

    setStatus("Ready");
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, m => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[m]));
  }

  async function refreshAll(){
    await loadSummary();
    await loadLatest();
    await loadHistory();
  }

  refreshAll();
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});


/** ---------------------------
 *  AUTH (JWT) — for future login-based dashboard
 *  -------------------------*/
app.post("/auth/register", async (req, res) => {
  try {
    const { site_id, email, password } = req.body;

    if (!site_id || !email || !password) {
      return res.status(400).json({ ok: false, error: "site_id, email, password required" });
    }

    const site = await pool.query("SELECT 1 FROM sites WHERE site_id=$1", [site_id]);
    if (site.rows.length === 0) return res.status(404).json({ ok: false, error: "Invalid site_id" });

    const password_hash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (site_id, email, password_hash)
       VALUES ($1,$2,$3)`,
      [site_id, email.toLowerCase(), password_hash]
    );

    res.json({ ok: true });
  } catch (err) {
    if (String(err.message).toLowerCase().includes("duplicate")) {
      return res.status(409).json({ ok: false, error: "Email already exists" });
    }
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ ok: false, error: "email and password required" });
    }

    const r = await pool.query(
      `SELECT id, site_id, email, password_hash
       FROM users
       WHERE email=$1
       LIMIT 1`,
      [email.toLowerCase()]
    );

    if (r.rows.length === 0) return res.status(401).json({ ok: false, error: "Invalid login" });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ ok: false, error: "Invalid login" });

    const jwtSecret = requireEnv("JWT_SECRET");

    const token = jwt.sign(
      { user_id: user.id, site_id: user.site_id, email: user.email },
      jwtSecret,
      { expiresIn: "7d" }
    );

    res.json({ ok: true, token });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Example protected endpoint (optional test)
app.get("/me", requireAuth, async (req, res) => {
  res.json({ ok: true, auth: req.auth });
});

/** ---------------------------
 *  Start server (keep last)
 *  -------------------------*/
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
