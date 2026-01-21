// index.js (ESM) — Constrava MVP backend
// ✅ Neon Postgres (pg)
// ✅ Event collector (/events)
// ✅ Site onboarding (/sites) generates site_id + dashboard_token
// ✅ Secure dashboard (/dashboard?token=...)
// ✅ Reports: generate, list, latest (all token-secured)
// ✅ Optional: email latest report via Resend (/email-latest)
// ✅ Tracker script served at /tracker.js

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
  console.error("Missing DATABASE_URL env var");
}

const pool = new Pool({ connectionString: DATABASE_URL });

/** ---------------------------
 *  Helpers
 *  -------------------------*/

function makeSiteId() {
  // simple unique-ish id
  return "site_" + crypto.randomBytes(6).toString("hex");
}

function publicBaseUrl(req) {
  // If you set PUBLIC_BASE_URL on Render, this will use it.
  // Otherwise, it falls back to request host.
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

    // generate ids
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
      token // helpful for your testing; you can remove later if you want
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

  // This script fires a basic page_view event on load.
  // Minimal by design. Expand later.
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
    // validate site exists
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
 *  POST /generate-report { token? } (token optional for your testing)
 *  If token provided => generates report for that site only
 *  If no token => generates report for ALL sites that had events today
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
      // all sites that have events today
      const s = await pool.query(`
        SELECT DISTINCT site_id
        FROM events_raw
        WHERE created_at::date = CURRENT_DATE
      `);
      siteIds = s.rows.map((x) => x.site_id);
      // if no events today, still allow fallback
      if (siteIds.length === 0) {
        const all = await pool.query(`SELECT site_id FROM sites LIMIT 50`);
        siteIds = all.rows.map((x) => x.site_id);
      }
    }

    const results = [];

    for (const site_id of siteIds) {
      // metrics per site for today
      const metricsRes = await pool.query(
        `
        SELECT
          $1::text as site_id,
          COUNT(*)::int AS total_events
        FROM events_raw
        WHERE site_id = $1 AND created_at::date = CURRENT_DATE
        `,
        [site_id]
      );

      const metrics = metricsRes.rows;

      // call OpenAI
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

      // save
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

/** ---------------------------
 *  Secure Dashboard UI
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
    .grid{
      margin-top:18px;
      display:grid;
      grid-template-columns: 1.2fr .8fr;
      gap:16px;
    }
    @media (max-width: 900px){ .grid{grid-template-columns:1fr} }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
    }
    .row{
      display:flex; align-items:center; justify-content:space-between;
      gap:10px; margin-bottom:10px;
    }
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
    .smallBtn{
      padding:8px 10px;
      border-radius:10px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.04);
      color: var(--text);
      cursor:pointer;
      font-size:12px;
    }
    .smallBtn:hover{border-color: rgba(255,255,255,.18)}
    .err{color: var(--danger); font-weight:600}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava Dashboard</h1>
          <div class="sub">Daily AI reports • Live events • MVP UI</div>
        </div>
      </div>

      <div class="controls">
        <span class="pill">Site: <b>${site_id}</b></span>
        <button class="btn" onclick="loadAll()">Refresh</button>
      </div>
    </div>

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

  async function loadAll() {
    await loadLatest();
    await loadHistory();
  }

  async function loadLatest() {
    setStatus("Loading latest...");
    const meta = document.getElementById("latestMeta");
    const box = document.getElementById("latest");
    box.textContent = "Loading...";

    const r = await fetch(\`\${base}/reports/latest?token=\${encodeURIComponent(token)}\`);
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

    const r = await fetch(\`\${base}/reports?limit=30&token=\${encodeURIComponent(token)}\`);
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
          <div class="row" style="margin:0">
            <div class="date">\${d.toDateString()}</div>
          </div>
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

/** ---------------------------
 *  Start server (keep last)
 *  -------------------------*/
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
