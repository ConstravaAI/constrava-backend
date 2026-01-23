// index.js (ESM) — Constrava MVP backend (NO bcrypt needed)
// ✅ Neon Postgres (pg)
// ✅ /sites creates site_id + dashboard_token
// ✅ /tracker.js + /events collector
// ✅ Token-secured dashboard: /dashboard?token=...
// ✅ Token-secured APIs: /metrics, /reports, /reports/latest
// ✅ Demo data: /seed-demo (token-secured)
// ✅ Optional AI reports: /generate-report (requires OPENAI_API_KEY)
// ✅ Optional email: /email-latest (requires RESEND_API_KEY + FROM_EMAIL)
// ✅ Optional login: /auth/register + /auth/login (uses crypto.scrypt, not bcrypt)

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) console.error("Missing DATABASE_URL env var");
const pool = new Pool({ connectionString: DATABASE_URL });

/* ---------------------------
   Helpers
----------------------------*/
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
  const r = await pool.query("SELECT site_id FROM sites WHERE dashboard_token=$1", [token]);
  return r.rows[0]?.site_id || null;
}
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name} env var`);
  return v;
}

// password hashing (no bcrypt)
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, "hex");
  const hash = Buffer.from(hashHex, "hex");
  const test = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(hash, test);
}

/* ---------------------------
   Boot: ensure tables exist
----------------------------*/
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
      password_salt TEXT NOT NULL,
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

/* ---------------------------
   Basic routes
----------------------------*/
app.get("/", (req, res) => res.send("Backend is running ✅"));

app.get("/db-test", async (req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Onboarding: create a site
   POST /sites { site_name, owner_email }
----------------------------*/
app.post("/sites", async (req, res) => {
  try {
    const { site_name, owner_email } = req.body || {};
    if (!site_name || !owner_email) {
      return res.status(400).json({ ok: false, error: "site_name and owner_email required" });
    }

    let site_id = makeSiteId();
    const token = crypto.randomUUID();

    for (let i = 0; i < 3; i++) {
      try {
        await pool.query(
          `INSERT INTO sites (site_id, site_name, owner_email, dashboard_token)
           VALUES ($1,$2,$3,$4)`,
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
      token // keep for YOUR testing; remove later if you want
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Tracker script
   GET /tracker.js
----------------------------*/
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");

  const endpoint = (process.env.PUBLIC_EVENTS_URL || "https://constrava-backend.onrender.com") + "/events";

  res.send(`
(function () {
  try {
    var script = document.currentScript;
    if (!script) return;

    var siteId = script.getAttribute("data-site-id");
    if (!siteId) return;

    fetch("${endpoint}", {
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

/* ---------------------------
   Receive events
   POST /events
----------------------------*/
app.post("/events", async (req, res) => {
  const { site_id, event_name, page_type, device } = req.body || {};
  if (!site_id || !event_name) {
    return res.status(400).json({ ok: false, error: "site_id and event_name required" });
  }

  try {
    const site = await pool.query("SELECT 1 FROM sites WHERE site_id=$1", [site_id]);
    if (site.rows.length === 0) {
      return res.status(403).json({ ok: false, error: "Invalid site_id" });
    }

    await pool.query(
      `INSERT INTO events_raw (site_id, event_name, page_type, device)
       VALUES ($1,$2,$3,$4)`,
      [site_id, event_name, page_type || null, device || null]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Token-secured metrics for dashboard
   GET /metrics?token=...
----------------------------*/
app.get("/metrics", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const today = await pool.query(
      `SELECT COUNT(*)::int AS events_today
       FROM events_raw
       WHERE site_id=$1 AND created_at::date = CURRENT_DATE`,
      [site_id]
    );

    const last7 = await pool.query(
      `SELECT COUNT(*)::int AS events_7d
       FROM events_raw
       WHERE site_id=$1 AND created_at >= NOW() - INTERVAL '7 days'`,
      [site_id]
    );

    const lastEvent = await pool.query(
      `SELECT event_name, page_type, device, created_at
       FROM events_raw
       WHERE site_id=$1
       ORDER BY created_at DESC
       LIMIT 1`,
      [site_id]
    );

    const topPage = await pool.query(
      `SELECT COALESCE(page_type,'(unknown)') AS page, COUNT(*)::int AS cnt
       FROM events_raw
       WHERE site_id=$1 AND created_at >= NOW() - INTERVAL '7 days'
       GROUP BY page
       ORDER BY cnt DESC
       LIMIT 1`,
      [site_id]
    );

    const deviceMix = await pool.query(
      `SELECT COALESCE(device,'unknown') AS device, COUNT(*)::int AS cnt
       FROM events_raw
       WHERE site_id=$1 AND created_at >= NOW() - INTERVAL '7 days'
       GROUP BY device
       ORDER BY cnt DESC`,
      [site_id]
    );

    const trend = await pool.query(
      `SELECT to_char(d, 'YYYY-MM-DD') AS day, COALESCE(c.cnt,0)::int AS cnt
       FROM generate_series(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, INTERVAL '1 day') d
       LEFT JOIN (
         SELECT created_at::date AS day, COUNT(*)::int AS cnt
         FROM events_raw
         WHERE site_id=$1 AND created_at >= NOW() - INTERVAL '7 days'
         GROUP BY day
       ) c ON c.day = d::date
       ORDER BY d`,
      [site_id]
    );

    res.json({
      ok: true,
      site_id,
      events_today: today.rows[0].events_today,
      events_7d: last7.rows[0].events_7d,
      last_event: lastEvent.rows[0] || null,
      top_page: topPage.rows[0] || null,
      device_mix: deviceMix.rows,
      trend_7d: trend.rows
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Reports: list + latest (token-secured)
----------------------------*/
app.get("/reports", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);

    const r = await pool.query(
      `SELECT site_id, report_date, created_at, LEFT(report_text, 220) AS preview
       FROM daily_reports
       WHERE site_id=$1
       ORDER BY report_date DESC, created_at DESC
       LIMIT $2`,
      [site_id, limit]
    );

    res.json({ ok: true, reports: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/reports/latest", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const r = await pool.query(
      `SELECT site_id, report_date, report_text, created_at
       FROM daily_reports
       WHERE site_id=$1
       ORDER BY report_date DESC, created_at DESC
       LIMIT 1`,
      [site_id]
    );

    if (r.rows.length === 0) return res.status(404).json({ ok: false, error: "No report found" });
    res.json({ ok: true, report: r.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Demo data generator (token-secured)
   POST /seed-demo?token=...
----------------------------*/
app.post("/seed-demo", async (req, res) => {
  try {
    const token = req.query.token || req.body?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    // create 7 days of events
    const pages = ["/", "/pricing", "/about", "/contact", "/demo", "/signup"];
    const devices = ["desktop", "mobile"];

    const inserts = [];
    for (let dayOffset = 0; dayOffset < 7; dayOffset++) {
      const base = new Date();
      base.setDate(base.getDate() - dayOffset);

      const eventsCount = 15 + Math.floor(Math.random() * 35); // 15–49/day
      for (let i = 0; i < eventsCount; i++) {
        const t = new Date(base);
        t.setHours(Math.floor(Math.random() * 24), Math.floor(Math.random() * 60), Math.floor(Math.random() * 60), 0);

        const page = pages[Math.floor(Math.random() * pages.length)];
        const device = devices[Math.floor(Math.random() * devices.length)];

        inserts.push(
          pool.query(
            `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
             VALUES ($1,'page_view',$2,$3,$4)`,
            [site_id, page, device, t.toISOString()]
          )
        );
      }
    }

    await Promise.all(inserts);

    // add 2 sample reports so the dashboard isn't empty
    const sample1 =
      `**Summary:**\nTraffic increased today with strong interest in your pricing and demo pages.\n\n` +
      `**Next actions:**\n1) Add a clearer CTA on /pricing\n2) Put a short testimonial on /demo\n3) Track signup clicks as a separate event\n\n` +
      `**Metric to watch:**\nSignup conversion rate`;
    const sample2 =
      `**Summary:**\nVisitors are browsing multiple pages but not converting yet.\n\n` +
      `**Next actions:**\n1) Add “Book a demo” button above the fold\n2) Improve /signup speed and clarity\n3) Add a follow-up email sequence\n\n` +
      `**Metric to watch:**\nClicks to /signup`;

    await pool.query(
      `INSERT INTO daily_reports (site_id, report_date, report_text)
       VALUES ($1, CURRENT_DATE - INTERVAL '1 day', $2)
       ON CONFLICT (site_id, report_date) DO NOTHING`,
      [site_id, sample1]
    );
    await pool.query(
      `INSERT INTO daily_reports (site_id, report_date, report_text)
       VALUES ($1, CURRENT_DATE, $2)
       ON CONFLICT (site_id, report_date) DO NOTHING`,
      [site_id, sample2]
    );

    res.json({ ok: true, seeded_for: site_id });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Optional: AI report generator (manual)
   POST /generate-report?token=...
----------------------------*/
app.post("/generate-report", async (req, res) => {
  try {
    const token = req.query.token || req.body?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");

    const metricsRes = await pool.query(
      `SELECT $1::text as site_id, COUNT(*)::int AS total_events
       FROM events_raw
       WHERE site_id=$1 AND created_at::date = CURRENT_DATE`,
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
        model: process.env.OPENAI_MODEL || "gpt-4o",
        messages: [
          { role: "system", content: "You generate short daily business reports. Be specific, actionable, and concise." },
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
    if (!reportText) return res.status(500).json({ ok: false, error: "AI response missing" });

    const saved = await pool.query(
      `INSERT INTO daily_reports (site_id, report_date, report_text)
       VALUES ($1, CURRENT_DATE, $2)
       ON CONFLICT (site_id, report_date) DO UPDATE SET report_text=EXCLUDED.report_text
       RETURNING site_id, report_date, report_text, created_at`,
      [site_id, reportText]
    );

    res.json({ ok: true, report: saved.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Optional: Email latest report (manual)
   POST /email-latest { token, to_email }
----------------------------*/
app.post("/email-latest", async (req, res) => {
  try {
    const { token, to_email } = req.body || {};
    if (!to_email) return res.status(400).json({ ok: false, error: "to_email required" });

    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Invalid token" });

    const r = await pool.query(
      `SELECT report_text, report_date
       FROM daily_reports
       WHERE site_id=$1
       ORDER BY report_date DESC, created_at DESC
       LIMIT 1`,
      [site_id]
    );
    if (r.rows.length === 0) return res.status(404).json({ ok: false, error: "No report found" });

    const RESEND_API_KEY = requireEnv("RESEND_API_KEY");
    const from = requireEnv("FROM_EMAIL");

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

/* ---------------------------
   Simple username/password login (NO bcrypt)
   - Register requires SITE token (so random people can’t create accounts)
   POST /auth/register { token, email, password }
   POST /auth/login { email, password }
----------------------------*/
app.post("/auth/register", async (req, res) => {
  try {
    const { token, email, password } = req.body || {};
    if (!token || !email || !password) {
      return res.status(400).json({ ok: false, error: "token, email, password required" });
    }

    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Invalid site token" });

    const { salt, hash } = hashPassword(password);

    await pool.query(
      `INSERT INTO users (site_id, email, password_salt, password_hash)
       VALUES ($1,$2,$3,$4)`,
      [site_id, email.toLowerCase(), salt, hash]
    );

    res.json({ ok: true, site_id });
  } catch (err) {
    if (String(err.message).toLowerCase().includes("duplicate")) {
      return res.status(409).json({ ok: false, error: "Email already exists" });
    }
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, error: "email and password required" });

    const r = await pool.query(
      `SELECT u.site_id, u.email, u.password_salt, u.password_hash, s.dashboard_token
       FROM users u
       JOIN sites s ON s.site_id = u.site_id
       WHERE u.email=$1
       LIMIT 1`,
      [email.toLowerCase()]
    );

    if (r.rows.length === 0) return res.status(401).json({ ok: false, error: "Invalid login" });

    const u = r.rows[0];
    const ok = verifyPassword(password, u.password_salt, u.password_hash);
    if (!ok) return res.status(401).json({ ok: false, error: "Invalid login" });

    const base = process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com";
    res.json({
      ok: true,
      site_id: u.site_id,
      dashboard_url: `${base}/dashboard?token=${u.dashboard_token}`
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Dashboard UI (token based)
   GET /dashboard?token=...
----------------------------*/
app.get("/dashboard", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

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
    .grid6{
      margin-top:16px;
      display:grid;
      grid-template-columns: repeat(6, 1fr);
      gap:12px;
    }
    @media (max-width: 1100px){ .grid6{grid-template-columns: repeat(3, 1fr);} }
    @media (max-width: 700px){ .grid6{grid-template-columns: repeat(2, 1fr);} }

    .grid{
      margin-top:16px;
      display:grid;
      grid-template-columns: 1.4fr .9fr;
      gap:16px;
    }
    @media (max-width: 900px){ .grid{grid-template-columns:1fr} }

    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
      overflow:hidden;
    }
    .miniTitle{font-size:12px; color:var(--muted); margin-bottom:8px;}
    .bigNum{font-size:26px; font-weight:900; letter-spacing:.3px;}
    .miniSub{font-size:12px; color:var(--muted); margin-top:8px;}
    .row{display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;}
    .status{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);}
    .dot{width:8px; height:8px; border-radius:50%; background: var(--accent2); box-shadow: 0 0 0 6px rgba(52,211,153,.12);}
    .err{color: var(--danger); font-weight:700}
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
      min-height: 240px;
    }
    .historyItem{
      padding:12px;
      border-radius: 14px;
      border:1px solid var(--border);
      background: rgba(15,23,42,.55);
      margin-top:10px;
    }
    .historyItem .date{font-weight:800; font-size:12px}
    .historyItem .preview{margin-top:8px; font-size:13px;}
    .sparkWrap{
      height:64px; border:1px solid var(--border);
      border-radius: 12px; background: rgba(15,23,42,.55);
      padding:8px; display:flex; align-items:center;
    }
    svg{width:100%; height:100%;}
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

    <div class="grid6">
      <div class="card">
        <div class="miniTitle">Events today</div>
        <div class="bigNum" id="m_events_today">—</div>
        <div class="miniSub" id="m_events_today_sub">—</div>
      </div>
      <div class="card">
        <div class="miniTitle">Events (last 7d)</div>
        <div class="bigNum" id="m_events_7d">—</div>
        <div class="miniSub">Rolling 7 days</div>
      </div>
      <div class="card">
        <div class="miniTitle">Last event</div>
        <div class="bigNum" style="font-size:16px;" id="m_last_event">—</div>
        <div class="miniSub" id="m_last_event_sub">—</div>
      </div>
      <div class="card">
        <div class="miniTitle">Top page</div>
        <div class="bigNum" style="font-size:16px;" id="m_top_page">—</div>
        <div class="miniSub" id="m_top_page_sub">—</div>
      </div>
      <div class="card">
        <div class="miniTitle">Device mix</div>
        <div class="bigNum" style="font-size:16px;" id="m_device_mix">—</div>
        <div class="miniSub">Last 7 days</div>
      </div>
      <div class="card">
        <div class="miniTitle">7-day trend</div>
        <div class="sparkWrap" id="m_spark"></div>
        <div class="miniSub">Events per day</div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="row">
          <div>
            <div class="miniTitle">Latest report</div>
            <div id="latestMeta" class="miniSub"></div>
          </div>
          <div class="status"><span class="dot"></span><span id="statusText">Ready</span></div>
        </div>
        <div id="latest" class="latest">Loading...</div>
      </div>

      <div class="card">
        <div class="row" style="margin:0 0 10px 0;">
          <div>
            <div style="font-weight:900; font-size:18px;">Report History</div>
            <div class="miniTitle">Recent reports for this site.</div>
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

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, m => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[m]));
  }

  function sparkline(points){
    const max = Math.max(...points, 1);
    const min = Math.min(...points, 0);
    const w = 200, h = 40;
    const pad = 4;
    const span = Math.max(max - min, 1);

    const xs = points.map((_, i) => pad + (i * (w - pad*2) / (points.length - 1 || 1)));
    const ys = points.map(v => (h - pad) - ((v - min) * (h - pad*2) / span));

    const d = xs.map((x,i)=> (i===0? "M":"L") + x.toFixed(1) + "," + ys[i].toFixed(1)).join(" ");
    return \`
      <svg viewBox="0 0 \${w} \${h}" preserveAspectRatio="none">
        <path d="\${d}" fill="none" stroke="rgba(96,165,250,.95)" stroke-width="2.5" />
      </svg>\`;
  }

  async function loadMetrics() {
    const r = await fetch(\`\${base}/metrics?token=\${encodeURIComponent(token)}\`);
    const data = await r.json();
    if (!data.ok) {
      setStatus("Error", true);
      return;
    }

    document.getElementById("m_events_today").textContent = data.events_today;
    document.getElementById("m_events_today_sub").textContent = data.events_today + " events today";

    document.getElementById("m_events_7d").textContent = data.events_7d;

    if (data.last_event) {
      document.getElementById("m_last_event").textContent = data.last_event.event_name;
      const dt = new Date(data.last_event.created_at);
      document.getElementById("m_last_event_sub").textContent =
        (data.last_event.page_type || "") + " • " + (data.last_event.device || "") + " • " + dt.toLocaleString();
    } else {
      document.getElementById("m_last_event").textContent = "None yet";
      document.getElementById("m_last_event_sub").textContent = "No events recorded";
    }

    if (data.top_page) {
      document.getElementById("m_top_page").textContent = data.top_page.page;
      document.getElementById("m_top_page_sub").textContent = data.top_page.cnt + " events (7d)";
    } else {
      document.getElementById("m_top_page").textContent = "—";
      document.getElementById("m_top_page_sub").textContent = "No page data (7d)";
    }

    const mix = (data.device_mix || []).map(x => \`\${x.device}: \${x.cnt}\`).join(" • ");
    document.getElementById("m_device_mix").textContent = mix || "—";

    const points = (data.trend_7d || []).map(x => x.cnt);
    document.getElementById("m_spark").innerHTML = sparkline(points);
  }

  async function loadLatest() {
    setStatus("Loading latest...");
    const meta = document.getElementById("latestMeta");
    const box = document.getElementById("latest");
    box.textContent = "Loading...";

    const r = await fetch(\`\${base}/reports/latest?token=\${encodeURIComponent(token)}\`);
    const data = await r.json();

    if (!data.ok) {
      meta.textContent = "";
      box.textContent = data.error || "No latest report";
      setStatus("Error", true);
      return;
    }

    const d = new Date(data.report.report_date);
    meta.textContent = \`\${d.toDateString()} • \${data.report.site_id}\`;
    box.textContent = data.report.report_text;
    setStatus("Ready");
  }

  async function loadHistory() {
    const el = document.getElementById("history");
    const pill = document.getElementById("countPill");
    el.innerHTML = "";

    const r = await fetch(\`\${base}/reports?limit=30&token=\${encodeURIComponent(token)}\`);
    const data = await r.json();

    if (!data.ok) {
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
        </div>\`;
    }).join("");
  }

  async function loadAll(){
    await loadMetrics();
    await loadLatest();
    await loadHistory();
  }

  loadAll();
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/* ---------------------------
   Start server (keep LAST)
----------------------------*/
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
