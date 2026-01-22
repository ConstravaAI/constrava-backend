// index.js (ESM) — Constrava MVP backend (FIXED + “everything you need”)
// ✅ Neon Postgres (pg)
// ✅ Event collector (/events)
// ✅ Site onboarding (/sites) -> site_id + dashboard_token + install snippet + dashboard link
// ✅ Token-secured dashboard (/dashboard?token=...)
// ✅ Token-secured APIs for dashboard data:
//    - /api/reports/latest?token=...
//    - /api/reports?token=...&limit=30
//    - /api/stats?token=...  (adds 6+ data points + simple charts)
// ✅ Generate daily AI report (manual): POST /generate-report  (optional cost)
// ✅ Email latest report (manual): POST /email-latest          (optional)
// ✅ Tracker script at /tracker.js (auto page_view)

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";
import fetch from "node-fetch";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL env var");
}

const pool = new Pool({ connectionString: DATABASE_URL });

/** ---------------------------
 * Helpers
 * --------------------------*/
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

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name} env var`);
  return v;
}

async function siteIdFromToken(token) {
  if (!token) return null;
  const r = await pool.query(
    "SELECT site_id FROM sites WHERE dashboard_token = $1",
    [token]
  );
  return r.rows[0]?.site_id || null;
}

function clampInt(n, min, max, fallback) {
  const x = parseInt(String(n ?? ""), 10);
  if (Number.isNaN(x)) return fallback;
  return Math.max(min, Math.min(max, x));
}

/** ---------------------------
 * Boot: ensure tables exist
 * --------------------------*/
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

  console.log("✅ Tables ensured");
}
ensureTables().catch((e) => console.error("ensureTables failed:", e.message));

/** ---------------------------
 * Basic routes
 * --------------------------*/
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
 * Onboarding: create a site
 * POST /sites { site_name, owner_email }
 * --------------------------*/
app.post("/sites", async (req, res) => {
  try {
    const { site_name, owner_email } = req.body || {};

    if (!site_name || !owner_email) {
      return res
        .status(400)
        .json({ ok: false, error: "site_name and owner_email required" });
    }

    let site_id = makeSiteId();
    const token = crypto.randomUUID();

    // rare collision retry
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
      token // helpful for your testing; you can remove later
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 * Tracker script served to client sites
 * GET /tracker.js
 * --------------------------*/
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");

  // IMPORTANT:
  // This is NOT HTML — it must be pure JS.
  const eventsBase =
    process.env.PUBLIC_EVENTS_URL || "https://constrava-backend.onrender.com";

  res.send(`
(function () {
  try {
    var script = document.currentScript;
    if (!script) return;

    var siteId = script.getAttribute("data-site-id");
    if (!siteId) return;

    var endpoint = "${eventsBase}".replace(/\\/$/, "") + "/events";

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
 * Receive events
 * POST /events
 * --------------------------*/
app.post("/events", async (req, res) => {
  const { site_id, event_name, page_type, device } = req.body || {};

  if (!site_id || !event_name) {
    return res
      .status(400)
      .json({ ok: false, error: "site_id and event_name required" });
  }

  try {
    // validate site exists
    const site = await pool.query("SELECT 1 FROM sites WHERE site_id = $1", [
      site_id
    ]);
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
 * Token-secured APIs for dashboard
 * --------------------------*/

// Latest report
app.get("/api/reports/latest", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res
        .status(401)
        .json({ ok: false, error: "Unauthorized. Add ?token=..." });
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

// Report history
app.get("/api/reports", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res
        .status(401)
        .json({ ok: false, error: "Unauthorized. Add ?token=..." });
    }

    const limit = clampInt(req.query.limit, 1, 100, 30);

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

// Stats for “boxes” + simple charts
app.get("/api/stats", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res
        .status(401)
        .json({ ok: false, error: "Unauthorized. Add ?token=..." });
    }

    // 1) Total events today
    const today = await pool.query(
      `
      SELECT COUNT(*)::int AS total_events_today
      FROM events_raw
      WHERE site_id = $1 AND created_at::date = CURRENT_DATE
      `,
      [site_id]
    );

    // 2) Total events last 7 days
    const last7 = await pool.query(
      `
      SELECT COUNT(*)::int AS total_events_7d
      FROM events_raw
      WHERE site_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
      `,
      [site_id]
    );

    // 3) Events by device (7d)
    const byDevice = await pool.query(
      `
      SELECT COALESCE(device,'unknown') AS device, COUNT(*)::int AS count
      FROM events_raw
      WHERE site_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
      GROUP BY COALESCE(device,'unknown')
      ORDER BY count DESC
      `,
      [site_id]
    );

    // 4) Top pages (7d)
    const topPages = await pool.query(
      `
      SELECT COALESCE(page_type,'(unknown)') AS page, COUNT(*)::int AS count
      FROM events_raw
      WHERE site_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
      GROUP BY COALESCE(page_type,'(unknown)')
      ORDER BY count DESC
      LIMIT 5
      `,
      [site_id]
    );

    // 5) Events by day (last 7 days) for a chart
    const perDay = await pool.query(
      `
      SELECT (created_at::date) AS day, COUNT(*)::int AS count
      FROM events_raw
      WHERE site_id = $1 AND created_at::date >= CURRENT_DATE - INTERVAL '6 days'
      GROUP BY (created_at::date)
      ORDER BY day ASC
      `,
      [site_id]
    );

    // Fill missing days to always return 7 points
    const map = new Map(perDay.rows.map((r) => [String(r.day), r.count]));
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const iso = d.toISOString().slice(0, 10);
      days.push({ day: iso, count: map.get(iso) || 0 });
    }

    // 6) Most recent event
    const lastEvent = await pool.query(
      `
      SELECT event_name, page_type, device, created_at
      FROM events_raw
      WHERE site_id = $1
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    res.json({
      ok: true,
      site_id,
      totals: {
        today: today.rows[0]?.total_events_today ?? 0,
        last7d: last7.rows[0]?.total_events_7d ?? 0
      },
      by_device: byDevice.rows,
      top_pages: topPages.rows,
      events_7d_series: days,
      last_event: lastEvent.rows[0] || null
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 * Generate + save report (manual trigger)
 * POST /generate-report  body: { token? }  (optional cost)
 * If token provided: generates for that site only
 * If no token: generates for sites that had events today (fallback: all sites)
 * --------------------------*/
app.post("/generate-report", async (req, res) => {
  try {
    const token = req.body?.token || req.query?.token || null;

    let siteIds = [];

    if (token) {
      const sid = await siteIdFromToken(token);
      if (!sid)
        return res.status(401).json({ ok: false, error: "Invalid token" });
      siteIds = [sid];
    } else {
      const s = await pool.query(`
        SELECT DISTINCT site_id
        FROM events_raw
        WHERE created_at::date = CURRENT_DATE
      `);
      siteIds = s.rows.map((x) => x.site_id);

      if (siteIds.length === 0) {
        const all = await pool.query(`SELECT site_id FROM sites LIMIT 100`);
        siteIds = all.rows.map((x) => x.site_id);
      }
    }

    const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");
    const model = process.env.OPENAI_MODEL || "gpt-4o";
    const results = [];

    for (const site_id of siteIds) {
      const metricsRes = await pool.query(
        `
        SELECT
          $1::text AS site_id,
          COUNT(*)::int AS total_events
        FROM events_raw
        WHERE site_id = $1 AND created_at::date = CURRENT_DATE
        `,
        [site_id]
      );

      const metrics = metricsRes.rows;

      const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: "system",
              content:
                "You generate short daily business reports. Be specific, actionable, and concise."
            },
            {
              role: "user",
              content:
                `Here are today's metrics (JSON): ${JSON.stringify(metrics)}\n` +
                `Write a daily report with:\n` +
                `1) Summary\n` +
                `2) 3 prioritized next actions\n` +
                `3) One metric to watch tomorrow\n`
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
 * Email latest report via Resend (manual, optional)
 * POST /email-latest { token, to_email }
 * --------------------------*/
app.post("/email-latest", async (req, res) => {
  try {
    const { token, to_email } = req.body || {};
    if (!to_email) {
      return res.status(400).json({ ok: false, error: "to_email required" });
    }

    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Invalid token" });

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

/** ---------------------------
 * Dashboard UI (token-based)
 * GET /dashboard?token=...
 * --------------------------*/
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
    .wrap{max-width:1200px; margin:0 auto; padding:28px 18px 60px;}
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
    .grid{
      margin-top:18px;
      display:grid;
      grid-template-columns: 1fr;
      gap:16px;
    }
    .cards{
      display:grid;
      grid-template-columns: repeat(6, 1fr);
      gap:12px;
      margin-top:16px;
    }
    @media (max-width: 1100px){ .cards{grid-template-columns: repeat(3, 1fr);} }
    @media (max-width: 700px){ .cards{grid-template-columns: repeat(2, 1fr);} }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
    }
    .statTitle{font-size:12px;color:var(--muted);margin-bottom:8px}
    .statValue{font-size:20px;font-weight:900;letter-spacing:.2px}
    .statSub{font-size:12px;color:var(--muted);margin-top:6px}
    .row{display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;}
    .status{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);}
    .dot{width:8px; height:8px; border-radius:50%; background: var(--accent2); box-shadow: 0 0 0 6px rgba(52,211,153,.12);}
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
    .panelGrid{
      display:grid;
      grid-template-columns: 1.2fr .8fr;
      gap:16px;
      margin-top:16px;
    }
    @media (max-width: 900px){ .panelGrid{grid-template-columns:1fr} }
    .svgWrap{
      margin-top:10px;
      border:1px solid var(--border);
      border-radius: 12px;
      background: rgba(15,23,42,.55);
      padding: 10px;
      overflow:hidden;
    }
    svg{display:block;width:100%;height:80px}
    .barRow{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
    .chip{
      font-size:12px;
      border:1px solid var(--border);
      border-radius:999px;
      padding:6px 10px;
      background: rgba(255,255,255,.04);
      color: var(--text);
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava Dashboard</h1>
          <div class="sub">Daily AI reports • Events • MVP UI</div>
        </div>
      </div>

      <div class="controls">
        <span class="pill">Site: <b>${site_id}</b></span>
        <button class="btn" onclick="loadAll()">Refresh</button>
      </div>
    </div>

    <div class="cards">
      <div class="card">
        <div class="statTitle">Events today</div>
        <div class="statValue" id="statToday">—</div>
        <div class="statSub" id="statTodaySub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Events (last 7d)</div>
        <div class="statValue" id="stat7d">—</div>
        <div class="statSub">Rolling 7 days</div>
      </div>

      <div class="card">
        <div class="statTitle">Last event</div>
        <div class="statValue" style="font-size:14px" id="statLastEvent">—</div>
        <div class="statSub" id="statLastEventSub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Top page</div>
        <div class="statValue" style="font-size:14px" id="statTopPage">—</div>
        <div class="statSub" id="statTopPageSub">—</div>
      </div>

      <div class="card">
        <div class="statTitle">Device mix</div>
        <div class="statValue" style="font-size:14px" id="statDevice">—</div>
        <div class="statSub">Last 7 days</div>
      </div>

      <div class="card">
        <div class="statTitle">7-day trend</div>
        <div class="svgWrap">
          <svg viewBox="0 0 300 80" preserveAspectRatio="none">
            <polyline id="trendLine" fill="none" stroke="rgba(96,165,250,.95)" stroke-width="3" points=""></polyline>
          </svg>
        </div>
        <div class="statSub">Events per day</div>
      </div>
    </div>

    <div class="panelGrid">
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
            <div style="font-weight:900;">Report History</div>
            <div class="muted">Recent reports for this site.</div>
          </div>
          <span class="pill" id="countPill">0</span>
        </div>
        <div id="history"></div>

        <div style="margin-top:14px" class="muted">Top pages (7d)</div>
        <div class="barRow" id="topPagesRow"></div>
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

  // ✅ YOU SAID “there is no loadAll()” — HERE IT IS:
  async function loadAll(){
    await Promise.all([loadStats(), loadLatest(), loadHistory()]);
  }

  async function loadStats(){
    try{
      const r = await fetch(\`\${base}/api/stats?token=\${encodeURIComponent(token)}\`);
      const data = await r.json();
      if(!data.ok){
        document.getElementById("statToday").textContent = "—";
        return;
      }

      // events today / 7d
      document.getElementById("statToday").textContent = data.totals.today;
      document.getElementById("statTodaySub").textContent = data.totals.today === 1 ? "1 event today" : \`\${data.totals.today} events today\`;
      document.getElementById("stat7d").textContent = data.totals.last7d;

      // last event
      if(data.last_event){
        document.getElementById("statLastEvent").textContent = data.last_event.event_name || "(event)";
        const when = new Date(data.last_event.created_at);
        document.getElementById("statLastEventSub").textContent = \`\${when.toLocaleString()} • \${data.last_event.device || "unknown"}\`;
      } else {
        document.getElementById("statLastEvent").textContent = "None yet";
        document.getElementById("statLastEventSub").textContent = "No events recorded";
      }

      // top page
      const top = (data.top_pages && data.top_pages[0]) ? data.top_pages[0] : null;
      document.getElementById("statTopPage").textContent = top ? top.page : "—";
      document.getElementById("statTopPageSub").textContent = top ? \`\${top.count} views (7d)\` : "No page data (7d)";

      // device mix
      const dev = (data.by_device || []).slice(0,3).map(d => \`\${d.device}: \${d.count}\`).join(" • ");
      document.getElementById("statDevice").textContent = dev || "—";

      // top pages chips
      const row = document.getElementById("topPagesRow");
      row.innerHTML = "";
      (data.top_pages || []).forEach(p => {
        const div = document.createElement("div");
        div.className = "chip";
        div.textContent = \`\${p.page} • \${p.count}\`;
        row.appendChild(div);
      });

      // 7-day trend polyline
      const series = data.events_7d_series || [];
      const max = Math.max(1, ...series.map(x => x.count));
      const pts = series.map((x, i) => {
        const px = (i/(series.length-1 || 1)) * 300;
        const py = 70 - (x.count/max) * 60;
        return \`\${px.toFixed(1)},\${py.toFixed(1)}\`;
      }).join(" ");
      document.getElementById("trendLine").setAttribute("points", pts);

    }catch(e){
      // keep silent for MVP
    }
  }

  async function loadLatest() {
    setStatus("Loading latest...");
    const meta = document.getElementById("latestMeta");
    const box = document.getElementById("latest");
    box.textContent = "Loading...";

    const r = await fetch(\`\${base}/api/reports/latest?token=\${encodeURIComponent(token)}\`);
    const data = await r.json();

    if (!data.ok) {
      setStatus("Error", true);
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

    const r = await fetch(\`\${base}/api/reports?limit=30&token=\${encodeURIComponent(token)}\`);
    const data = await r.json();

    if (!data.ok) {
      setStatus("Error", true);
      el.innerHTML = \`<div class="historyItem"><div class="err">\${data.error || "No history"}</div></div>\`;
      pill.textContent = "0";
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

  loadAll();
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});
// -----------------------------
// DEV: seed fake data (token-secured)
// -----------------------------

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Creates fake events for last N days
app.post("/dev/seed-events", async (req, res) => {
  try {
    const token = req.body?.token || req.query?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Invalid token" });

    const days = Math.min(parseInt(req.body?.days || req.query?.days || "14", 10), 60);
    const perDayMin = parseInt(req.body?.perDayMin || "40", 10);
    const perDayMax = parseInt(req.body?.perDayMax || "180", 10);

    const pages = ["/", "/products", "/pricing", "/about", "/contact", "/blog", "/product/widget", "/checkout"];
    const devices = ["desktop", "mobile"];
    const events = ["page_view", "view_product", "add_to_cart", "checkout_start"];

    let inserted = 0;

    for (let d = days - 1; d >= 0; d--) {
      const count = randInt(perDayMin, perDayMax);
      for (let i = 0; i < count; i++) {
        const event_name = pick(events);
        const page_type = pick(pages);
        const device = Math.random() < 0.55 ? "mobile" : "desktop";

        // random timestamp within that day
        const created_at = new Date();
        created_at.setDate(created_at.getDate() - d);
        created_at.setHours(randInt(0, 23), randInt(0, 59), randInt(0, 59), 0);

        await pool.query(
          `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [site_id, event_name, page_type, device, created_at.toISOString()]
        );

        inserted++;
      }
    }

    res.json({ ok: true, site_id, inserted, days });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Creates fake reports for last N days
app.post("/dev/seed-reports", async (req, res) => {
  try {
    const token = req.body?.token || req.query?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Invalid token" });

    const days = Math.min(parseInt(req.body?.days || req.query?.days || "14", 10), 60);

    let inserted = 0;

    for (let d = days - 1; d >= 0; d--) {
      const date = new Date();
      date.setDate(date.getDate() - d);
      const yyyy = date.getFullYear();
      const mm = String(date.getMonth() + 1).padStart(2, "0");
      const dd = String(date.getDate()).padStart(2, "0");
      const isoDate = `${yyyy}-${mm}-${dd}`;

      const fake = `# Daily Business Report

### Summary
Traffic looks healthy with stronger interest in **/products** and **/pricing**. Mobile users are the majority, so speed + mobile layout matter most.

### 3 Next Actions
1) Add a clearer CTA on the homepage (top section + sticky button on mobile).
2) Improve the pricing page: add FAQ + “who it’s for” section.
3) Post 1 short piece of content driving to a product page (IG/TikTok/Reel style).

### Metric to Watch Tomorrow
**Checkout starts** vs **add_to_cart** (conversion drop-off).`;

      await pool.query(
        `
        INSERT INTO daily_reports (site_id, report_date, report_text)
        VALUES ($1, $2::date, $3)
        ON CONFLICT (site_id, report_date)
        DO UPDATE SET report_text = EXCLUDED.report_text
        `,
        [site_id, isoDate, fake]
      );

      inserted++;
    }

    res.json({ ok: true, site_id, inserted, days });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/** ---------------------------
 * Start server (KEEP LAST)
 * --------------------------*/
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
