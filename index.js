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
app.get("/metrics", async (req, res) => {
  try {
    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });
    }

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

    // Total visits last 7 days + daily trend
    const trendRes = await pool.query(
      `
      SELECT d::date AS day, COALESCE(COUNT(e.*),0)::int AS visits
      FROM generate_series(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, INTERVAL '1 day') d
      LEFT JOIN events_raw e
        ON e.site_id = $1
       AND e.event_name = 'page_view'
       AND e.created_at::date = d::date
      GROUP BY d
      ORDER BY d
      `,
      [site_id]
    );

    const visits_7d = trendRes.rows.reduce((sum, r) => sum + (r.visits || 0), 0);

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

    // Top page (page_view) last 7 days
    const topPageRes = await pool.query(
      `
      SELECT page_type, COUNT(*)::int AS views
      FROM events_raw
      WHERE site_id = $1
        AND event_name = 'page_view'
        AND created_at >= NOW() - INTERVAL '7 days'
        AND page_type IS NOT NULL
      GROUP BY page_type
      ORDER BY views DESC
      LIMIT 1
      `,
      [site_id]
    );

    // Device mix (page_view) last 7 days
    const deviceRes = await pool.query(
      `
      SELECT
        SUM(CASE WHEN device = 'mobile' THEN 1 ELSE 0 END)::int AS mobile,
        SUM(CASE WHEN device = 'desktop' THEN 1 ELSE 0 END)::int AS desktop
      FROM events_raw
      WHERE site_id = $1
        AND event_name = 'page_view'
        AND created_at >= NOW() - INTERVAL '7 days'
      `,
      [site_id]
    );

    // Pages visited today (to make it feel more “assistant”)
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
      visits_today: todayRes.rows[0]?.visits_today || 0,
      visits_7d,
      trend_7d: trendRes.rows, // [{day, visits}, ... 7 items]
      last_event: lastEventRes.rows[0] || null,
      top_page_7d: topPageRes.rows[0] || null,
      device_mix_7d: deviceRes.rows[0] || { mobile: 0, desktop: 0 },
      top_pages_today: todayTopRes.rows || []
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
      font-weight:700;
    }
    .btn:hover{border-color: rgba(96,165,250,.5)}
    .btn:active{transform: translateY(1px)}
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
      font-weight:800;
      display:flex; align-items:center; justify-content:space-between;
      gap:10px;
    }
    .bigTitle{
      font-size:18px;
      font-weight:900;
      margin:0;
      color: var(--text);
    }
    .status{
      display:flex; align-items:center; gap:8px;
      font-size:12px; color:var(--muted);
    }
    .dot{
      width:8px; height:8px; border-radius:50%;
      background: var(--accent2);
      box-shadow: 0 0 0 6px rgba(52,211,153,.12);
    }
    .err{color: var(--danger); font-weight:700}
    .muted{color:var(--muted); font-size:12px}
    .kpi{
      font-size:26px;
      font-weight:900;
      letter-spacing:.2px;
      margin-top:8px;
    }
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
    .mini .label{font-size:12px; color:var(--muted); font-weight:800;}
    .mini .value{font-size:14px; font-weight:900;}
    .sparkWrap{
      background: rgba(15,23,42,.55);
      border:1px solid var(--border);
      border-radius: 14px;
      padding:12px;
    }
    svg{width:100%; height:70px; display:block;}
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
    .historyItem .date{font-weight:900; font-size:12px}
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
        <button class="btn" onclick="refreshAll()">Refresh</button>
      </div>
    </div>

    <div class="grid">

      <!-- Assistant Brief (big) -->
      <div class="card span12">
        <h2>
          Assistant Brief
          <span class="pill" id="moodPill">Loading…</span>
        </h2>
        <div id="assistantBrief" class="assistantBox">Loading…</div>
      </div>

      <!-- KPIs -->
      <div class="card span3">
        <h2>Visits today <span class="pill" id="todayNote">—</span></h2>
        <div class="kpi" id="visitsToday">0</div>
        <div class="hint" id="todayHint">How many people visited today.</div>
      </div>

      <div class="card span3">
        <h2>Visits (7 days)</h2>
        <div class="kpi" id="visits7d">0</div>
        <div class="hint" id="trendHint">Compared to your 7-day average.</div>
      </div>

      <div class="card span3">
        <h2>Latest activity</h2>
        <div class="kpi" style="font-size:16px" id="lastActivity">—</div>
        <div class="hint" id="lastActivityHint">Most recent interaction we recorded.</div>
      </div>

      <div class="card span3">
        <h2>Most popular page (7d)</h2>
        <div class="kpi" style="font-size:16px" id="topPage">—</div>
        <div class="hint" id="topPageHint">Where most attention is going.</div>
      </div>

      <!-- Trend chart -->
      <div class="card span6">
        <h2>7-day traffic trend</h2>
        <div class="sparkWrap">
          <svg viewBox="0 0 300 70" preserveAspectRatio="none">
            <polyline id="spark" fill="none" stroke="currentColor" stroke-width="3" points=""></polyline>
          </svg>
          <div class="muted" id="sparkLabel">Loading…</div>
        </div>
      </div>

      <!-- Device mix + Today pages -->
      <div class="card span6">
        <h2>Quick insights</h2>
        <div class="row" style="margin-top:10px;">
          <div class="mini" style="flex:1;">
            <div class="label">Device mix (7d)</div>
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

      <!-- Reports (keep your report features) -->
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
  const base = location.origin;
  const token = new URLSearchParams(location.search).get("token");

  function esc(s){
    return String(s || "").replace(/[&<>"']/g, function(m){
      return ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" })[m];
    });
  }

  function prettyPage(path){
    if(!path) return "Unknown";
    if(path === "/") return "Homepage";
    if(path.indexOf("file:") === 0 || path.indexOf("C:\\\\") === 0) return "Test page";
    // turn "/pricing" into "Pricing"
    var p = path.split("?")[0];
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
    var el = document.getElementById("moodPill");
    el.textContent = text;
  }

  function setStatus(text, isErr){
    var el = document.getElementById("statusText");
    el.textContent = text;
    el.className = isErr ? "err" : "";
  }

  function buildAssistantBrief(m){
    var today = m.visits_today || 0;
    var last7 = m.visits_7d || 0;
    var avg7 = last7 / 7;
    var pct = avg7 > 0 ? Math.round(((today - avg7) / avg7) * 100) : null;

    var trendLine = "Not enough history yet to call a strong trend.";
    var mood = "Neutral";

    if(pct !== null){
      if(pct >= 25){ trendLine = "Traffic is up about " + pct + "% vs your 7-day average."; mood = "📈 Up"; }
      else if(pct <= -25){ trendLine = "Traffic is down about " + Math.abs(pct) + "% vs your 7-day average."; mood = "📉 Down"; }
      else { trendLine = "Traffic is steady vs your 7-day average."; mood = "✅ Stable"; }
    }

    var topPage = m.top_page_7d && m.top_page_7d.page_type ? prettyPage(m.top_page_7d.page_type) : null;
    var topViews = m.top_page_7d && m.top_page_7d.views ? m.top_page_7d.views : 0;

    var mobile = (m.device_mix_7d && m.device_mix_7d.mobile) ? m.device_mix_7d.mobile : 0;
    var desktop = (m.device_mix_7d && m.device_mix_7d.desktop) ? m.device_mix_7d.desktop : 0;

    var deviceMajor = (mobile > desktop) ? "mobile" : (desktop > mobile) ? "desktop" : "mixed";

    var advice = [];

    if(today === 0 && last7 === 0){
      advice.push("Open your site yourself (incognito) to confirm visits are being recorded.");
      advice.push("Make sure the tracker snippet is in the <head> or near the top of <body>.");
      advice.push("Next: track one high-value action (button click or form submit).");
      return { mood: "⚠️ No data yet", text:
        "What happened: No visits have been recorded yet.\\n\\n" +
        "Trend: " + trendLine + "\\n\\n" +
        "What it means: Tracking is installed, but we have no traffic data to analyze yet.\\n\\n" +
        "What to do next:\\n- " + advice.join("\\n- ")
      };
    }

    if(deviceMajor === "mobile") advice.push("Most visitors are on mobile — make your main button big and near the top.");
    if(deviceMajor === "desktop") advice.push("Most visitors are on desktop — add a clear CTA and a short proof section near the top.");
    if(topPage) advice.push("Your hottest page is " + topPage + " — add a clear next step on that page (Book a call / Get a quote).");
    advice.push("Track a lead action next (button click or form submit) so we measure leads, not just visits.");

    var happened = "Today you had " + today + " visits.";
    if(topPage) happened += " Most attention is on " + topPage + " (" + topViews + " views in 7 days).";

    return { mood: mood, text:
      "What happened: " + happened + "\\n\\n" +
      "Trend: " + trendLine + "\\n\\n" +
      "What it means: Your visitors are showing intent on specific pages. Let’s convert that interest into leads.\\n\\n" +
      "What to do next:\\n- " + advice.slice(0,3).join("\\n- ")
    };
  }

  function drawSpark(trend){
    // trend: [{day, visits}...]
    var pts = [];
    var values = (trend || []).map(function(x){ return x.visits || 0; });
    var max = Math.max.apply(null, values.concat([1]));
    var w = 300, h = 70, pad = 6;

    for(var i=0;i<values.length;i++){
      var x = (values.length === 1) ? w/2 : (i * (w/(values.length-1)));
      var y = h - pad - (values[i] / max) * (h - pad*2);
      pts.push(x.toFixed(1) + "," + y.toFixed(1));
    }
    document.getElementById("spark").setAttribute("points", pts.join(" "));
    document.getElementById("sparkLabel").textContent = "Daily visits: " + values.join(" • ");
  }

  async function loadMetrics(){
    var r = await fetch(base + "/metrics?token=" + encodeURIComponent(token));
    var data = await r.json();
    if(!data.ok){
      setMood("Error");
      document.getElementById("assistantBrief").textContent = data.error || "Failed to load metrics";
      return null;
    }

    // KPIs
    document.getElementById("visitsToday").textContent = data.visits_today;
    document.getElementById("visits7d").textContent = data.visits_7d;

    // Last activity
    if(data.last_event){
      var evt = data.last_event.event_name === "page_view" ? "Viewed" : data.last_event.event_name;
      var page = prettyPage(data.last_event.page_type);
      var when = timeAgo(data.last_event.created_at);
      var device = data.last_event.device ? data.last_event.device : "unknown";
      document.getElementById("lastActivity").textContent = evt + " " + page + " • " + when;
      document.getElementById("lastActivityHint").textContent = "Device: " + device;
    } else {
      document.getElementById("lastActivity").textContent = "No activity yet";
      document.getElementById("lastActivityHint").textContent = "Once your site gets visits, this will update.";
    }

    // Top page
    if(data.top_page_7d){
      var tp = prettyPage(data.top_page_7d.page_type);
      document.getElementById("topPage").textContent = tp;
      document.getElementById("topPageHint").textContent = data.top_page_7d.views + " views in last 7 days";
    } else {
      document.getElementById("topPage").textContent = "Not enough data";
      document.getElementById("topPageHint").textContent = "We’ll show the most visited page once visits come in.";
    }

    // Device mix
    var mob = data.device_mix_7d && data.device_mix_7d.mobile ? data.device_mix_7d.mobile : 0;
    var desk = data.device_mix_7d && data.device_mix_7d.desktop ? data.device_mix_7d.desktop : 0;
    var total = mob + desk;
    var mobPct = total ? Math.round((mob/total)*100) : 0;
    var deskPct = total ? Math.round((desk/total)*100) : 0;
    document.getElementById("deviceMix").textContent = mobPct + "% mobile • " + deskPct + "% desktop";

    // Top pages today
    if(data.top_pages_today && data.top_pages_today.length){
      var list = data.top_pages_today.map(function(p){
        return prettyPage(p.page_type) + " (" + p.views + ")";
      }).join(", ");
      document.getElementById("topToday").textContent = list;
    } else {
      document.getElementById("topToday").textContent = "No visits yet today";
    }

    // Assistant brief
    var brief = buildAssistantBrief(data);
    setMood(brief.mood);
    document.getElementById("assistantBrief").textContent = brief.text;

    // Sparkline
    drawSpark(data.trend_7d || []);

    return data;
  }

  async function loadReports(){
    // latest report
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

    // history
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

  refreshAll();
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});


// DEMO DATA SEEDER (DEV ONLY)
// POST /demo/seed?token=...  body: { days: 7, events_per_day: 40 }
app.post("/demo/seed", async (req, res) => {
  try {
    // Safety: only allow if you explicitly enable it
    if (process.env.ENABLE_DEMO_SEED !== "true") {
      return res.status(403).json({ ok: false, error: "Seeder disabled. Set ENABLE_DEMO_SEED=true" });
    }

    const token = req.query.token || req.body?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) {
      return res.status(401).json({ ok: false, error: "Unauthorized. Provide ?token=..." });
    }

    const days = Math.max(1, Math.min(parseInt(req.body?.days || "7", 10), 30));
    const eventsPerDay = Math.max(5, Math.min(parseInt(req.body?.events_per_day || "40", 10), 300));

    const pages = ["/", "/pricing", "/services", "/about", "/contact", "/blog", "/faq", "/checkout"];
    const devices = ["mobile", "desktop"];

    // Insert fake events with timestamps spread across each day
    // Uses parameterized queries to stay safe
    let inserted = 0;

    for (let d = 0; d < days; d++) {
      // dayStart is d days ago at 00:00
      const dayStart = new Date();
      dayStart.setHours(0, 0, 0, 0);
      dayStart.setDate(dayStart.getDate() - d);

      for (let i = 0; i < eventsPerDay; i++) {
        // random seconds within the day
        const seconds = Math.floor(Math.random() * 86400);
        const ts = new Date(dayStart.getTime() + seconds * 1000);

        // weighted pages (pricing/home more common)
        const r = Math.random();
        const page =
          r < 0.30 ? "/" :
          r < 0.55 ? "/pricing" :
          r < 0.70 ? "/services" :
          r < 0.80 ? "/contact" :
          pages[Math.floor(Math.random() * pages.length)];

        // weighted devices (mobile slightly more common)
        const device = Math.random() < 0.62 ? "mobile" : "desktop";

        await pool.query(
          `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
           VALUES ($1, 'page_view', $2, $3, $4)`,
          [site_id, page, device, ts.toISOString()]
        );

        inserted++;
      }
    }

    res.json({ ok: true, site_id, days, events_per_day: eventsPerDay, inserted });
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
