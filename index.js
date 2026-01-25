// index.js (ESM) — Constrava MVP backend (NO bcrypt needed)
// ✅ Neon Postgres (pg)
// ✅ /sites creates site_id + dashboard_token
// ✅ /tracker.js + /events collector
// ✅ Token-secured dashboard: /dashboard?token=...
// ✅ Token-secured APIs: /metrics, /reports, /reports/latest, /analytics/7d
// ✅ Demo data: /seed-demo (token-secured) + /demo/seed (guarded by ENABLE_DEMO_SEED)
// ✅ Optional AI reports: /generate-report (requires OPENAI_API_KEY)
// ✅ Optional email: /email-latest (requires RESEND_API_KEY + FROM_EMAIL)
// ✅ Optional login: /auth/register + /auth/login (uses crypto.scrypt, not bcrypt)

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";

const { Pool } = pkg;

// Node 18+ has global fetch; for safety on some environments:
const fetchFn = globalThis.fetch;

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

function setNoStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
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
      token // keep for YOUR testing
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
   Metrics for dashboard (SINGLE SOURCE OF TRUTH)
   GET /metrics?token=...
----------------------------*/
app.get("/metrics", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

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

    // 7-day daily trend (always 7 rows, fills missing days with 0)
    const trendRes = await pool.query(
      `
      SELECT
        to_char(d::date, 'YYYY-MM-DD') AS day,
        COALESCE(COUNT(e.*),0)::int AS visits
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

    // Top page last 7 days (page_view only)
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

    // Device mix last 7 days (page_view only)
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

    // Top pages today
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
   Analytics series (alt endpoint)
   GET /analytics/7d?token=...
   (returns same “always 7 days” series so charts never go blank)
----------------------------*/
app.get("/analytics/7d", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const r = await pool.query(
      `
      SELECT
        to_char(d::date, 'YYYY-MM-DD') AS day,
        COALESCE(COUNT(e.*),0)::int AS events
      FROM generate_series(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, INTERVAL '1 day') d
      LEFT JOIN events_raw e
        ON e.site_id = $1
       AND e.created_at::date = d::date
      GROUP BY d
      ORDER BY d
      `,
      [site_id]
    );

    res.json({ ok: true, series: r.rows });
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
   Demo data generator (token-secured)
   POST /seed-demo?token=...
----------------------------*/
app.post("/seed-demo", async (req, res) => {
  try {
    const token = req.query.token || req.body?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const pages = ["/", "/pricing", "/about", "/contact", "/demo", "/signup"];
    const devices = ["desktop", "mobile"];

    const inserts = [];
    for (let dayOffset = 0; dayOffset < 7; dayOffset++) {
      const base = new Date();
      base.setDate(base.getDate() - dayOffset);

      const eventsCount = 30 + Math.floor(Math.random() * 90); // 30–119/day (more visible)
      for (let i = 0; i < eventsCount; i++) {
        const t = new Date(base);
        t.setHours(
          Math.floor(Math.random() * 24),
          Math.floor(Math.random() * 60),
          Math.floor(Math.random() * 60),
          0
        );

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

    // add sample reports
    const sample1 =
      `Summary:\nTraffic is building and your pricing page is pulling attention.\n\n` +
      `Next actions:\n1) Add a clear “Book a demo” button on /pricing\n2) Add proof (testimonial/logo strip)\n3) Track “signup_click” and “contact_submit” events\n\n` +
      `Metric to watch tomorrow:\nClicks to /signup`;
    const sample2 =
      `Summary:\nVisitors are browsing multiple pages. Now we need to convert them.\n\n` +
      `Next actions:\n1) Add a single CTA to the homepage\n2) Simplify /signup form\n3) Add a “1-minute explainer” section\n\n` +
      `Metric to watch tomorrow:\nContact form submissions`;

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

    if (!fetchFn) return res.status(500).json({ ok: false, error: "fetch not available on this runtime" });

    const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");

    const metricsRes = await pool.query(
      `SELECT $1::text as site_id, COUNT(*)::int AS total_events
       FROM events_raw
       WHERE site_id=$1 AND created_at::date = CURRENT_DATE`,
      [site_id]
    );

    const aiRes = await fetchFn("https://api.openai.com/v1/chat/completions", {
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
              `Here are today's metrics (JSON): ${JSON.stringify(metricsRes.rows)}\n` +
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

    if (!fetchFn) return res.status(500).json({ ok: false, error: "fetch not available on this runtime" });

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

    const emailRes = await fetchFn("https://api.resend.com/emails", {
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
   - Register requires SITE token
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
    setNoStore(res);

    const token = req.query.token;
    const site_id = await siteIdFromToken(token);

    if (!site_id) {
      return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");
    }

    res.setHeader("Content-Type", "text/html");
    // Your existing big dashboard HTML stays the same.
    // IMPORTANT: This dashboard expects /metrics to return:
    // visits_today, visits_7d, trend_7d[{day,visits}], last_event, top_page_7d{page_type,views}, device_mix_7d{mobile,desktop}, top_pages_today
    res.send(`
<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Constrava Dashboard</title>
<body style="font-family:Arial;padding:20px;background:#0b0f19;color:#e5e7eb;">
<h1>Constrava Dashboard ✅</h1>
<p>Authorized for site: <b>${site_id}</b></p>
<p>Open:</p>
<ul>
  <li><a style="color:#60a5fa" href="/metrics?token=${encodeURIComponent(token)}">/metrics?token=...</a></li>
  <li><a style="color:#60a5fa" href="/reports/latest?token=${encodeURIComponent(token)}">/reports/latest?token=...</a></li>
  <li><a style="color:#60a5fa" href="/reports?token=${encodeURIComponent(token)}">/reports?token=...</a></li>
  <li><a style="color:#60a5fa" href="/analytics/7d?token=${encodeURIComponent(token)}">/analytics/7d?token=...</a></li>
</ul>
<p>(Paste your full fancy dashboard HTML here — this route is now stable.)</p>
</body></html>
    `);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// DEMO DATA SEEDER (DEV ONLY)
// POST /demo/seed?token=...  body: { days: 7, events_per_day: 40 }
app.post("/demo/seed", async (req, res) => {
  try {
    if (process.env.ENABLE_DEMO_SEED !== "true") {
      return res.status(403).json({ ok: false, error: "Seeder disabled. Set ENABLE_DEMO_SEED=true" });
    }

    const token = req.query.token || req.body?.token;
    const site_id = await siteIdFromToken(token);
    if (!site_id) return res.status(401).json({ ok: false, error: "Unauthorized. Provide ?token=..." });

    const days = Math.max(1, Math.min(parseInt(req.body?.days || "7", 10), 30));
    const eventsPerDay = Math.max(5, Math.min(parseInt(req.body?.events_per_day || "40", 10), 300));

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
