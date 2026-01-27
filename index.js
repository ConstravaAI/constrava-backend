// index.js (ESM) — Constrava MVP backend (safe dashboard template + time-range selector)
// ✅ Neon Postgres (pg)
// ✅ /sites creates site_id + dashboard_token
// ✅ /tracker.js + /events collector
// ✅ Token-secured dashboard: /dashboard?token=...
// ✅ Token-secured APIs: /metrics, /reports, /reports/latest
// ✅ Demo data: /demo/seed (token-secured, ENABLE_DEMO_SEED=true)
// ✅ Optional AI reports: /generate-report (requires OPENAI_API_KEY)
// ✅ Optional email: /email-latest (requires RESEND_API_KEY + FROM_EMAIL)
// ✅ Optional login: /auth/register + /auth/login (uses crypto.scrypt)

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
function setNoStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

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

// Clamp + map day options (your dropdown options)
function normalizeDays(input) {
  const n = parseInt(String(input || "7"), 10);
  const allowed = new Set([1, 7, 30, 365, 730, 1825]);
  return allowed.has(n) ? n : 7;
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

  const endpoint =
    (process.env.PUBLIC_EVENTS_URL || "https://constrava-backend.onrender.com") + "/events";

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
   Token-secured metrics (range-aware)
   GET /metrics?token=...&days=7
   days allowed: 1, 7, 30, 365, 730, 1825
----------------------------*/
app.get("/metrics", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const days = normalizeDays(req.query.days);
    const startDate = `${days - 1} days`;

    // Visits today (page_view only)
    const todayRes = await pool.query(
      `
      SELECT COUNT(*)::int AS visits_today
      FROM events_raw
      WHERE site_id = $1
        AND event_name = 'page_view'
        AND created_at::date = CURRENT_DATE
      `,
      [site_id]
    );

    // Trend series for selected range (always returns exactly N points)
    const trendRes = await pool.query(
      `
      SELECT d::date AS day, COALESCE(COUNT(e.*),0)::int AS visits
      FROM generate_series(CURRENT_DATE - $2::interval, CURRENT_DATE, INTERVAL '1 day') d
      LEFT JOIN events_raw e
        ON e.site_id = $1
       AND e.event_name = 'page_view'
       AND e.created_at::date = d::date
      GROUP BY d
      ORDER BY d
      `,
      [site_id, startDate]
    );

    const visits_range = trendRes.rows.reduce((sum, r) => sum + (r.visits || 0), 0);

    // Last event (any event)
    const lastEventRes = await pool.query(
      `
      SELECT event_name, page_type, device, created_at
      FROM events_raw
      WHERE site_id = $1
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    // Top page (page_view) in selected range
    const topPageRes = await pool.query(
      `
      SELECT page_type, COUNT(*)::int AS views
      FROM events_raw
      WHERE site_id = $1
        AND event_name = 'page_view'
        AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
        AND page_type IS NOT NULL
      GROUP BY page_type
      ORDER BY views DESC
      LIMIT 1
      `,
      [site_id, days]
    );

    // Device mix (page_view) in selected range
    const deviceRes = await pool.query(
      `
      SELECT
        SUM(CASE WHEN device = 'mobile' THEN 1 ELSE 0 END)::int AS mobile,
        SUM(CASE WHEN device = 'desktop' THEN 1 ELSE 0 END)::int AS desktop
      FROM events_raw
      WHERE site_id = $1
        AND event_name = 'page_view'
        AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
      `,
      [site_id, days]
    );

    // Top pages today (for assistant vibe)
    const todayTopRes = await pool.query(
      `
      SELECT page_type, COUNT(*)::int AS views
      FROM events_raw
      WHERE site_id = $1
        AND event_name = 'page_view'
        AND created_at::date = CURRENT_DATE
        AND page_type IS NOT NULL
      GROUP BY page_type
      ORDER BY views DESC
      LIMIT 3
      `,
      [site_id]
    );

    res.json({
      ok: true,
      site_id,
      days,
      visits_today: todayRes.rows[0]?.visits_today || 0,
      visits_range,
      trend: trendRes.rows.map((r) => ({
        day: String(r.day), // YYYY-MM-DD
        visits: r.visits
      })),
      last_event: lastEventRes.rows[0] || null,
      top_page: topPageRes.rows[0] || null,
      device_mix: deviceRes.rows[0] || { mobile: 0, desktop: 0 },
      top_pages_today: todayTopRes.rows || []
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
    setNoStore(res);

    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);

    const r = await pool.query(
      `SELECT site_id, report_date, created_at, LEFT(report_text, 240) AS preview
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
    setNoStore(res);

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
      `
      SELECT
        $1::text as site_id,
        COUNT(*)::int AS total_events,
        SUM(CASE WHEN event_name='page_view' THEN 1 ELSE 0 END)::int AS page_views
      FROM events_raw
      WHERE site_id=$1 AND created_at >= NOW() - INTERVAL '7 days'
      `,
      [site_id]
    );

    const metrics = metricsRes.rows[0];

    const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o",
        messages: [
          { role: "system", content: "You are a helpful business analytics assistant. Be plain-English, actionable, and concise." },
          {
            role: "user",
            content:
              "Here are metrics for the last 7 days (JSON): " + JSON.stringify(metrics) + "\n" +
              "Write:\n1) What happened (plain English)\n2) Trend + what it means\n3) 3 next steps\n4) One metric to watch"
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
   DEMO DATA SEEDER (DEV ONLY)
   POST /demo/seed?token=...
   body: { days: 7, events_per_day: 40 }
   - also inserts 2 sample reports so /reports/latest shows something
----------------------------*/
app.post("/demo/seed", async (req, res) => {
  try {
    if (process.env.ENABLE_DEMO_SEED !== "true") {
      return res.status(403).json({ ok: false, error: "Seeder disabled. Set ENABLE_DEMO_SEED=true" });
    }

    const token = req.query.token || req.body?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Provide ?token=..." });

    const days = Math.max(1, Math.min(parseInt(req.body?.days || "7", 10), 3650));
    const eventsPerDay = Math.max(5, Math.min(parseInt(req.body?.events_per_day || "40", 10), 500));

    const pages = ["/", "/pricing", "/services", "/about", "/contact", "/blog", "/faq", "/checkout"];
    let inserted = 0;

    for (let d = 0; d < days; d++) {
      const dayStart = new Date();
      dayStart.setHours(0, 0, 0, 0);
      dayStart.setDate(dayStart.getDate() - d);

      for (let i = 0; i < eventsPerDay; i++) {
        const seconds = Math.floor(Math.random() * 86400);
        const ts = new Date(dayStart.getTime() + seconds * 1000);

        const r = Math.random();
        const page =
          r < 0.30 ? "/" :
          r < 0.55 ? "/pricing" :
          r < 0.70 ? "/services" :
          r < 0.80 ? "/contact" :
          pages[Math.floor(Math.random() * pages.length)];

        const device = Math.random() < 0.62 ? "mobile" : "desktop";

        await pool.query(
          `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
           VALUES ($1, 'page_view', $2, $3, $4)`,
          [site_id, page, device, ts.toISOString()]
        );
        inserted++;
      }
    }

    // sample reports (so demo doesn't look empty)
    const sample1 =
      "Summary:\nTraffic is concentrating on Pricing and Services, which suggests purchase intent.\n\n" +
      "Trend:\nVisitors are exploring multiple pages, but your next step is to capture leads.\n\n" +
      "Next steps:\n1) Add a clear primary CTA on Pricing (Book a demo / Get quote)\n2) Add a short proof section (logos/testimonials) above the fold\n3) Track a lead event (button click or form submit)\n\n" +
      "Metric to watch:\nClicks to your main CTA";

    const sample2 =
      "Summary:\nYou’re getting steady visits and people are repeatedly checking Pricing.\n\n" +
      "Trend:\nInterest is consistent — improving conversion copy should raise leads.\n\n" +
      "Next steps:\n1) Put a single strongest offer at the top of Pricing\n2) Add a “what happens next” 3-step section\n3) Reduce friction: shorter forms + faster page load\n\n" +
      "Metric to watch:\nPricing → Contact rate";

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

    res.json({ ok: true, site_id, days, events_per_day: eventsPerDay, inserted });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Dashboard UI (token based, range selector)
   GET /dashboard?token=...
----------------------------*/
app.get("/dashboard", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");
    }

    res.setHeader("Content-Type", "text/html");
    res.send(`<!doctype html>
<html lang="en">
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
    .wrap{max-width:1180px; margin:0 auto; padding:26px 18px 60px;}
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
      font-weight:800;
    }
    .btn:hover{border-color: rgba(96,165,250,.5)}
    .btn:active{transform: translateY(1px)}
    select{
      border-radius:12px;
      border:1px solid var(--border);
      background: rgba(15,23,42,.6);
      color: var(--text);
      padding:10px 12px;
      font-weight:800;
      outline:none;
    }
    select:hover{border-color: rgba(255,255,255,.18)}
    .grid{
      margin-top:18px;
      display:grid;
      grid-template-columns: repeat(12, 1fr);
      gap:16px;
    }
    .span12{grid-column: 1 / -1;}
    .span8{grid-column: span 8;}
    .span6{grid-column: span 6;}
    .span4{grid-column: span 4;}
    .span3{grid-column: span 3;}
    @media (max-width: 1000px){
      .span8,.span6,.span4,.span3{grid-column: 1 / -1;}
    }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
    }
    .card h2{
      margin:0 0 10px 0;
      font-size:13px;
      color: var(--muted);
      letter-spacing:.2px;
      font-weight:900;
      display:flex; align-items:center; justify-content:space-between;
      gap:10px;
    }
    .status{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);}
    .dot{
      width:8px; height:8px; border-radius:50%;
      background: var(--accent2);
      box-shadow: 0 0 0 6px rgba(52,211,153,.12);
    }
    .err{color: var(--danger); font-weight:900}
    .muted{color:var(--muted); font-size:12px}
    .kpi{font-size:26px; font-weight:950; letter-spacing:.2px; margin-top:8px;}
    .hint{margin-top:8px; font-size:12px; color:var(--muted); line-height:1.4;}
    .assistantBox{
      background: rgba(15,23,42,.55);
      border:1px solid var(--border);
      border-radius: 14px;
      padding:14px;
      line-height:1.55;
      font-size:14px;
      white-space:pre-wrap;
    }
    .row{display:flex; align-items:center; justify-content:space-between; gap:12px;}
    .mini{
      display:flex; flex-direction:column; gap:6px;
      background: rgba(15,23,42,.55);
      border:1px solid var(--border);
      border-radius: 14px;
      padding:12px;
    }
    .mini .label{font-size:12px; color:var(--muted); font-weight:900;}
    .mini .value{font-size:14px; font-weight:950;}
    .sparkWrap{
      background: rgba(15,23,42,.55);
      border:1px solid var(--border);
      border-radius: 14px;
      padding:12px;
    }
    svg{width:100%; height:86px; display:block;}
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
    .historyItem{
      padding:12px;
      border-radius: 14px;
      border:1px solid var(--border);
      background: rgba(15,23,42,.55);
      margin-top:10px;
    }
    .historyItem .date{font-weight:950; font-size:12px}
    .historyItem .preview{margin-top:8px; font-size:13px; color: var(--text)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava Dashboard</h1>
          <div class="sub">Your AI tech assistant — conclusions + next steps in plain English</div>
        </div>
      </div>

      <div class="controls">
        <span class="pill">Site: <b>${site_id}</b></span>

        <select id="rangeSel" title="Time range">
          <option value="1">1 day</option>
          <option value="7" selected>1 week</option>
          <option value="30">1 month</option>
          <option value="365">1 year</option>
          <option value="730">2 years</option>
          <option value="1825">5 years</option>
        </select>

        <button class="btn" id="refreshBtn">Refresh</button>
      </div>
    </div>

    <div class="grid">

      <div class="card span12">
        <h2>
          Assistant Brief
          <span class="pill" id="moodPill">Loading…</span>
        </h2>
        <div id="assistantBrief" class="assistantBox">Loading…</div>
      </div>

      <div class="card span3">
        <h2>Visits today <span class="pill" id="todayNote">—</span></h2>
        <div class="kpi" id="visitsToday">0</div>
        <div class="hint" id="todayHint">How many people visited today.</div>
      </div>

      <div class="card span3">
        <h2>Visits (range)</h2>
        <div class="kpi" id="visitsRange">0</div>
        <div class="hint" id="rangeHint">Total visits in the selected time range.</div>
      </div>

      <div class="card span3">
        <h2>Latest activity</h2>
        <div class="kpi" style="font-size:16px" id="lastActivity">—</div>
        <div class="hint" id="lastActivityHint">Most recent interaction we recorded.</div>
      </div>

      <div class="card span3">
        <h2>Most popular page (range)</h2>
        <div class="kpi" style="font-size:16px" id="topPage">—</div>
        <div class="hint" id="topPageHint">Where most attention is going.</div>
      </div>

      <div class="card span6">
        <h2>Traffic trend (range)</h2>
        <div class="sparkWrap">
          <svg viewBox="0 0 300 86" preserveAspectRatio="none">
            <polyline id="spark" fill="none" stroke="currentColor" stroke-width="3" points=""></polyline>
          </svg>
          <div class="muted" id="sparkLabel">Loading…</div>
        </div>
      </div>

      <div class="card span6">
        <h2>Quick insights</h2>
        <div class="row" style="margin-top:10px;">
          <div class="mini" style="flex:1;">
            <div class="label">Device mix (range)</div>
            <div class="value" id="deviceMix">—</div>
            <div class="muted" id="deviceHint">Mobile vs Desktop visitors.</div>
          </div>
          <div class="mini" style="flex:1;">
            <div class="label">Top pages today</div>
            <div class="value" id="topToday">—</div>
            <div class="muted">The pages people are viewing today.</div>
          </div>
        </div>
      </div>

      <div class="card span8">
        <h2>
          Latest report
          <span class="status"><span class="dot"></span><span id="statusText">Ready</span></span>
        </h2>
        <div id="latestMeta" class="muted"></div>
        <div id="latestReport" class="latest">Loading…</div>
      </div>

      <div class="card span4">
        <h2>Report history <span class="pill" id="countPill">0</span></h2>
        <div id="history"></div>
      </div>

    </div>
  </div>

<script>
  // IMPORTANT: no backticks, no \${} inside this script (prevents server template issues)
  var base = location.origin;
  var token = new URLSearchParams(location.search).get("token");
  var rangeSel = document.getElementById("rangeSel");

  function esc(s){
    return String(s || "").replace(/[&<>"']/g, function(m){
      return ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" })[m];
    });
  }

  function prettyPage(path){
    if(!path) return "Unknown";
    if(path === "/") return "Homepage";
    var p = String(path).split("?")[0];
    p = p.replace(/^\\/+/, "");
    if(!p) return "Homepage";
    p = p.replace(/[-_]/g, " ");
    p = p.replace(/\\b\\w/g, function(c){ return c.toUpperCase(); });
    return p;
  }

  function timeAgo(iso){
    if(!iso) return "";
    var t = new Date(iso).getTime();
    var diff = Date.now() - t;
    var mins = Math.floor(diff/60000);
    if(mins < 1) return "just now";
    if(mins < 60) return mins + " min ago";
    var hrs = Math.floor(mins/60);
    if(hrs < 24) return hrs + " hr ago";
    var days = Math.floor(hrs/24);
    return days + " day" + (days===1?"":"s") + " ago";
  }

  function setMood(text){
    document.getElementById("moodPill").textContent = text;
  }

  function setStatus(text, isErr){
    var el = document.getElementById("statusText");
    el.textContent = text;
    el.className = isErr ? "err" : "";
  }

  function rangeLabel(days){
    if(days === 1) return "1 day";
    if(days === 7) return "1 week";
    if(days === 30) return "1 month";
    if(days === 365) return "1 year";
    if(days === 730) return "2 years";
    if(days === 1825) return "5 years";
    return days + " days";
  }

  function buildAssistantBrief(m){
    var days = m.days || 7;
    var label = rangeLabel(days);

    var today = m.visits_today || 0;
    var total = m.visits_range || 0;
    var avg = days > 0 ? (total / days) : 0;

    var trendLine = "Not enough history yet to call a strong trend.";
    var mood = "Neutral";

    // estimate vs average: today compared to average day in range
    var pct = avg > 0 ? Math.round(((today - avg) / avg) * 100) : null;
    if(pct !== null){
      if(pct >= 25){ trendLine = "Today is up about " + pct + "% vs your average day (" + label + ")."; mood = "📈 Up"; }
      else if(pct <= -25){ trendLine = "Today is down about " + Math.abs(pct) + "% vs your average day (" + label + ")."; mood = "📉 Down"; }
      else { trendLine = "Traffic is steady vs your average day (" + label + ")."; mood = "✅ Stable"; }
    }

    var tp = m.top_page ? prettyPage(m.top_page.page_type) : null;
    var tv = m.top_page ? (m.top_page.views || 0) : 0;

    var mobile = m.device_mix ? (m.device_mix.mobile || 0) : 0;
    var desktop = m.device_mix ? (m.device_mix.desktop || 0) : 0;
    var deviceMajor = (mobile > desktop) ? "mobile" : (desktop > mobile) ? "desktop" : "mixed";

    var advice = [];

    if(today === 0 && total === 0){
      advice.push("Seed demo data (or open your site incognito) to generate real activity.");
      advice.push("Make sure the tracker snippet is in the <head> or near the top of <body>.");
      advice.push("Next: track a high-value action (button click or form submit).");
      return { mood: "⚠️ No data yet", text:
        "What happened: No visits recorded yet (" + label + ").\\n\\n" +
        "Trend: " + trendLine + "\\n\\n" +
        "What it means: Tracking is ready, but we need traffic to generate insights.\\n\\n" +
        "What to do next:\\n- " + advice.join("\\n- ")
      };
    }

    if(deviceMajor === "mobile") advice.push("Most visitors are on mobile — make your main button big and near the top.");
    if(deviceMajor === "desktop") advice.push("Most visitors are on desktop — add a clear CTA and proof section above the fold.");
    if(tp) advice.push("Your hottest page is " + tp + " — add a clear next step there (Book a demo / Get a quote).");
    advice.push("Track a lead action next so we measure leads, not just visits.");

    var happened = "Today you had " + today + " visits. In the last " + label + ", you had " + total + " total visits.";
    if(tp) happened += " Most attention is on " + tp + " (" + tv + " views).";

    return { mood: mood, text:
      "What happened: " + happened + "\\n\\n" +
      "Trend: " + trendLine + "\\n\\n" +
      "What it means: Visitors are showing intent on specific pages — now we turn that into leads.\\n\\n" +
      "What to do next:\\n- " + advice.slice(0,3).join("\\n- ")
    };
  }

  function drawSpark(trend){
    // trend: [{day, visits}...]
    var values = (trend || []).map(function(x){ return x.visits || 0; });
    var max = 1;
    for(var i=0;i<values.length;i++){ if(values[i] > max) max = values[i]; }

    var w = 300, h = 86, pad = 8;
    var pts = [];
    for(var j=0;j<values.length;j++){
      var x = (values.length === 1) ? w/2 : (j * (w/(values.length-1)));
      var y = h - pad - (values[j] / max) * (h - pad*2);
      pts.push(x.toFixed(1) + "," + y.toFixed(1));
    }
    document.getElementById("spark").setAttribute("points", pts.join(" "));
    document.getElementById("sparkLabel").textContent = "Daily visits: " + values.join(" • ");
  }

  async function loadMetrics(){
    var days = parseInt(rangeSel.value, 10) || 7;

    var url = base + "/metrics?token=" + encodeURIComponent(token) + "&days=" + encodeURIComponent(String(days));
    var r = await fetch(url);
    var data = await r.json();

    if(!data.ok){
      setMood("Error");
      document.getElementById("assistantBrief").textContent = data.error || "Failed to load metrics";
      return null;
    }

    document.getElementById("todayNote").textContent = rangeLabel(days);
    document.getElementById("visitsToday").textContent = data.visits_today;
    document.getElementById("visitsRange").textContent = data.visits_range;
    document.getElementById("rangeHint").textContent = "Total visits in " + rangeLabel(days) + ".";

    if(data.last_event){
      var evt = (data.last_event.event_name === "page_view") ? "Viewed" : data.last_event.event_name;
      var page = prettyPage(data.last_event.page_type);
      var when = timeAgo(data.last_event.created_at);
      var device = data.last_event.device ? data.last_event.device : "unknown";
      document.getElementById("lastActivity").textContent = evt + " " + page + " • " + when;
      document.getElementById("lastActivityHint").textContent = "Device: " + device;
    } else {
      document.getElementById("lastActivity").textContent = "No activity yet";
      document.getElementById("lastActivityHint").textContent = "Once your site gets visits, this will update.";
    }

    if(data.top_page){
      var tp = prettyPage(data.top_page.page_type);
      document.getElementById("topPage").textContent = tp;
      document.getElementById("topPageHint").textContent = data.top_page.views + " views in " + rangeLabel(days);
    } else {
      document.getElementById("topPage").textContent = "Not enough data";
      document.getElementById("topPageHint").textContent = "We’ll show the most visited page once visits come in.";
    }

    var mob = data.device_mix && data.device_mix.mobile ? data.device_mix.mobile : 0;
    var desk = data.device_mix && data.device_mix.desktop ? data.device_mix.desktop : 0;
    var total = mob + desk;
    var mobPct = total ? Math.round((mob/total)*100) : 0;
    var deskPct = total ? Math.round((desk/total)*100) : 0;
    document.getElementById("deviceMix").textContent = mobPct + "% mobile • " + deskPct + "% desktop";

    if(data.top_pages_today && data.top_pages_today.length){
      var list = data.top_pages_today.map(function(p){
        return prettyPage(p.page_type) + " (" + p.views + ")";
      }).join(", ");
      document.getElementById("topToday").textContent = list;
    } else {
      document.getElementById("topToday").textContent = "No visits yet today";
    }

    var brief = buildAssistantBrief(data);
    setMood(brief.mood);
    document.getElementById("assistantBrief").textContent = brief.text;

    drawSpark(data.trend || []);
    return data;
  }

  async function loadReports(){
    setStatus("Loading…", false);

    var latestMeta = document.getElementById("latestMeta");
    var latestBox = document.getElementById("latestReport");

    var r1 = await fetch(base + "/reports/latest?token=" + encodeURIComponent(token));
    var d1 = await r1.json();

    if(!d1.ok){
      latestMeta.textContent = "";
      latestBox.textContent = d1.error || "No report found yet.";
    } else {
      var dt = new Date(d1.report.report_date);
      latestMeta.textContent = dt.toDateString();
      latestBox.textContent = d1.report.report_text;
    }

    var r2 = await fetch(base + "/reports?limit=20&token=" + encodeURIComponent(token));
    var d2 = await r2.json();
    var hist = document.getElementById("history");
    var pill = document.getElementById("countPill");
    hist.innerHTML = "";

    if(!d2.ok){
      pill.textContent = "0";
      hist.innerHTML = '<div class="historyItem"><div class="err">' + esc(d2.error || "No history") + '</div></div>';
    } else {
      pill.textContent = d2.reports.length;
      hist.innerHTML = d2.reports.map(function(rep){
        var dd = new Date(rep.report_date);
        return (
          '<div class="historyItem">' +
            '<div class="date">' + dd.toDateString() + '</div>' +
            '<div class="preview">' + esc(rep.preview || "") + '...</div>' +
          '</div>'
        );
      }).join("");
    }

    setStatus("Ready", false);
  }

  async function refreshAll(){
    await loadMetrics();
    await loadReports();
  }

  document.getElementById("refreshBtn").addEventListener("click", function(){
    refreshAll();
  });

  rangeSel.addEventListener("change", function(){
    refreshAll();
  });

  refreshAll();
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});
// ----------------------------
// Billing: update a site's plan (called by your .app site)
// POST /billing/update-plan
// Headers: x-webhook-secret: <BILLING_WEBHOOK_SECRET>
// Body: { site_id: "...", plan: "starter" | "pro" | "full_ai" }
// ----------------------------
app.post("/billing/update-plan", async (req, res) => {
  try {
    const secret = req.headers["x-webhook-secret"];
    if (!process.env.BILLING_WEBHOOK_SECRET) {
      return res.status(500).json({ ok: false, error: "Missing BILLING_WEBHOOK_SECRET on server" });
    }
    if (!secret || secret !== process.env.BILLING_WEBHOOK_SECRET) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }

    const { site_id, plan } = req.body || {};
    const allowed = new Set(["starter", "pro", "full_ai"]);

    if (!site_id || !plan) {
      return res.status(400).json({ ok: false, error: "site_id and plan required" });
    }
    if (!allowed.has(plan)) {
      return res.status(400).json({ ok: false, error: "Invalid plan. Use starter, pro, or full_ai" });
    }

    const r = await pool.query(
      `UPDATE sites
       SET plan = $2
       WHERE site_id = $1
       RETURNING site_id, plan`,
      [site_id, plan]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "site_id not found" });
    }

    res.json({ ok: true, updated: r.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Start server (keep LAST)
----------------------------*/
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
