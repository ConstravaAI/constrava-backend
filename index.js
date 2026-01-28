// index.js (ESM) — Constrava MVP backend (clean + fixed)
// ✅ Neon Postgres (pg)
// ✅ /sites creates site_id + dashboard_token
// ✅ /tracker.js + /events collector
// ✅ Token-secured dashboard: /dashboard?token=...
// ✅ Token-secured APIs: /metrics, /reports, /reports/latest
// ✅ Demo data: /demo/seed (token-secured, ENABLE_DEMO_SEED=true)
// ✅ Optional AI reports: /generate-report (requires OPENAI_API_KEY)
// ✅ Optional email: /email-latest (requires RESEND_API_KEY + FROM_EMAIL)
// ✅ Site login: /auth/site-login (site_id + token)
// ✅ Storefront: /storefront (demo activation)
// ✅ Demo activation: /demo/activate-plan (NO secret)
// ✅ Billing webhook: /billing/update-plan (requires BILLING_WEBHOOK_SECRET)

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Clamp + map day options (dashboard dropdown options)
function normalizeDays(input) {
  const n = parseInt(String(input || "7"), 10);
  const allowed = new Set([1, 7, 30, 365, 730, 1825]);
  return allowed.has(n) ? n : 7;
}

function normalizeSiteId(raw) {
  return String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "");
}

function validateSiteId(site_id) {
  // 4–24 chars, starts with letter, only lowercase letters/numbers/hyphen
  if (!site_id) return "site_id is required";
  if (site_id.length < 4 || site_id.length > 24) return "site_id must be 4–24 characters";
  if (!/^[a-z][a-z0-9-]*$/.test(site_id)) {
    return "site_id must start with a letter and use only lowercase, numbers, and hyphens";
  }
  if (site_id.includes("--")) return "site_id cannot contain double hyphens";
  if (site_id.endsWith("-")) return "site_id cannot end with a hyphen";
  return null;
}

function validateCustomToken(token) {
  // Strong rules if they set their own token
  if (!token) return "access token is required";
  if (token.length < 20) return "access token must be at least 20 characters";
  if (!/[a-z]/.test(token)) return "access token must include a lowercase letter";
  if (!/[A-Z]/.test(token)) return "access token must include an uppercase letter";
  if (!/[0-9]/.test(token)) return "access token must include a number";
  if (!/[^A-Za-z0-9]/.test(token)) return "access token must include a symbol";
  return null;
}

// token -> site record (includes plan)
async function getSiteByToken(token) {
  if (!token) return null;
  const r = await pool.query(
    `SELECT site_id, site_name, owner_email, dashboard_token, plan
     FROM sites
     WHERE dashboard_token=$1
     LIMIT 1`,
    [token]
  );
  return r.rows[0] || null;
}

// plan gate
function requirePlan(site, allowedPlans) {
  const plan = site?.plan || "unpaid";
  if (allowedPlans.includes(plan)) return { ok: true };
  return {
    ok: false,
    status: 403,
    error: `This feature requires plan: ${allowedPlans.join(" or ")}. Your plan: ${plan}.`
  };
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
      plan TEXT NOT NULL DEFAULT 'unpaid',
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

app.get("/debug/site", async (req, res) => {
  const token = req.query.token;
  const site = await getSiteByToken(token);
  res.json({ ok: true, site });
});

/* ---------------------------
   Onboarding: create a site
   POST /sites { site_id, site_name, owner_email, custom_token? }
----------------------------*/
app.post("/sites", async (req, res) => {
  try {
    const { site_id: rawSiteId, site_name, owner_email, custom_token } = req.body || {};

    if (!rawSiteId || !site_name || !owner_email) {
      return res.status(400).json({
        ok: false,
        error: "site_id, site_name, and owner_email are required"
      });
    }

    const site_id = normalizeSiteId(rawSiteId);
    const siteIdErr = validateSiteId(site_id);
    if (siteIdErr) return res.status(400).json({ ok: false, error: siteIdErr });

    // Token: generate by default; allow custom if strong
    let token = crypto.randomUUID();
    if (custom_token) {
      const tokErr = validateCustomToken(custom_token);
      if (tokErr) return res.status(400).json({ ok: false, error: tokErr });
      token = custom_token;
    }

    await pool.query(
      `INSERT INTO sites (site_id, site_name, owner_email, dashboard_token, plan)
       VALUES ($1,$2,$3,$4,'unpaid')`,
      [site_id, site_name, owner_email, token]
    );

    const base = publicBaseUrl(req);

    res.json({
      ok: true,
      site_id,
      install_snippet: `<script src="${base}/tracker.js" data-site-id="${site_id}"></script>`,
      client_dashboard_url: `${base}/dashboard?token=${encodeURIComponent(token)}`,
      access_token: token
    });
  } catch (err) {
    const msg = String(err.message || "");

    if (msg.toLowerCase().includes("duplicate") || msg.toLowerCase().includes("unique")) {
      return res.status(409).json({ ok: false, error: "That site_id is already taken. Choose another." });
    }

    res.status(500).json({ ok: false, error: msg });
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
----------------------------*/
app.get("/metrics", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const site_id = site.site_id;
    const days = normalizeDays(req.query.days);
    const startDate = `${days - 1} days`;

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
      trend: trendRes.rows.map((r) => ({ day: String(r.day), visits: r.visits })),
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
   Reports: list + latest
----------------------------*/
app.get("/reports", async (req, res) => {
  try {
    setNoStore(res);

    const site = await getSiteByToken(req.query.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);

    const r = await pool.query(
      `SELECT site_id, report_date, created_at, LEFT(report_text, 240) AS preview
       FROM daily_reports
       WHERE site_id=$1
       ORDER BY report_date DESC, created_at DESC
       LIMIT $2`,
      [site.site_id, limit]
    );

    res.json({ ok: true, reports: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/reports/latest", async (req, res) => {
  try {
    setNoStore(res);

    const site = await getSiteByToken(req.query.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const r = await pool.query(
      `SELECT site_id, report_date, report_text, created_at
       FROM daily_reports
       WHERE site_id=$1
       ORDER BY report_date DESC, created_at DESC
       LIMIT 1`,
      [site.site_id]
    );

    if (r.rows.length === 0) return res.status(404).json({ ok: false, error: "No report found" });
    res.json({ ok: true, report: r.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Demo data seeder
   POST /demo/seed?token=...
----------------------------*/
app.post("/demo/seed", async (req, res) => {
  try {
    if (process.env.ENABLE_DEMO_SEED !== "true") {
      return res.status(403).json({ ok: false, error: "Seeder disabled. Set ENABLE_DEMO_SEED=true" });
    }

    const site = await getSiteByToken(req.query.token || req.body?.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Provide ?token=..." });

    const site_id = site.site_id;
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

    const sample1 =
      "Summary:\nTraffic is concentrating on Pricing and Services, which suggests purchase intent.\n\n" +
      "Trend:\nVisitors are exploring multiple pages, but your next step is to capture leads.\n\n" +
      "Next steps:\n1) Add a clear primary CTA on Pricing\n2) Add proof (logos/testimonials)\n3) Track a lead event\n\n" +
      "Metric to watch:\nClicks to your main CTA";

    const sample2 =
      "Summary:\nYou’re getting steady visits and people are repeatedly checking Pricing.\n\n" +
      "Trend:\nInterest is consistent — improving conversion copy should raise leads.\n\n" +
      "Next steps:\n1) Put your strongest offer at the top of Pricing\n2) Add a simple 3-step “what happens next”\n3) Shorten forms + speed up pages\n\n" +
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
   Optional: AI report generator (FULL AI only)
   POST /generate-report?token=...
----------------------------*/
app.post("/generate-report", async (req, res) => {
  try {
    const site = await getSiteByToken(req.query.token || req.body?.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const gate = requirePlan(site, ["full_ai"]);
    if (!gate.ok) return res.status(gate.status).json({ ok: false, error: gate.error });

    const site_id = site.site_id;
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
              "Here are metrics for the last 7 days (JSON): " +
              JSON.stringify(metrics) +
              "\nWrite:\n1) What happened\n2) Trend + what it means\n3) 3 next steps\n4) One metric to watch"
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
       ON CONFLICT (site_id, report_date)
       DO UPDATE SET report_text = EXCLUDED.report_text
       RETURNING site_id, report_date, report_text, created_at`,
      [site_id, reportText]
    );

    res.json({ ok: true, report: saved.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Optional: Email latest report (PRO + FULL AI)
   POST /email-latest { token, to_email }
----------------------------*/
app.post("/email-latest", async (req, res) => {
  try {
    const { token, to_email } = req.body || {};
    if (!to_email) return res.status(400).json({ ok: false, error: "to_email required" });

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Invalid token" });

    const gate = requirePlan(site, ["pro", "full_ai"]);
    if (!gate.ok) return res.status(gate.status).json({ ok: false, error: gate.error });

    const r = await pool.query(
      `SELECT report_text, report_date
       FROM daily_reports
       WHERE site_id=$1
       ORDER BY report_date DESC, created_at DESC
       LIMIT 1`,
      [site.site_id]
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
        subject: `Daily Report (${site.site_id})`,
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
   Site login (site_id + token)
   POST /auth/site-login { site_id, token }
----------------------------*/
app.post("/auth/site-login", async (req, res) => {
  try {
    const { site_id: rawSiteId, token } = req.body || {};
    const site_id = normalizeSiteId(rawSiteId);

    if (!site_id || !token) {
      return res.status(400).json({ ok: false, error: "site_id and token required" });
    }

    const r = await pool.query(
      `SELECT site_id, dashboard_token, plan
       FROM sites
       WHERE site_id=$1
       LIMIT 1`,
      [site_id]
    );

    if (r.rows.length === 0) return res.status(401).json({ ok: false, error: "Invalid login" });

    const site = r.rows[0];
    if (site.dashboard_token !== token) return res.status(401).json({ ok: false, error: "Invalid login" });

    const base = process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com";
    res.json({
      ok: true,
      site_id: site.site_id,
      plan: site.plan,
      dashboard_url: `${base}/dashboard?token=${encodeURIComponent(token)}`,
      storefront_url: `${base}/storefront?token=${encodeURIComponent(token)}`
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

/* ---------------------------
   Storefront (token-based demo)
   GET /storefront?token=...
----------------------------*/
app.get("/storefront", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site = await getSiteByToken(token);
    if (!site) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

    const site_id = site.site_id;
    const plan = site.plan || "unpaid";

    // If already activated, go dashboard
    if (plan !== "unpaid") {
      return res.redirect("/dashboard?token=" + encodeURIComponent(token));
    }

    res.setHeader("Content-Type", "text/html");

    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Constrava — Storefront</title>
  <style>
    :root{
      --bg:#0b0f19; --text:#e5e7eb; --muted:#9ca3af;
      --border:rgba(255,255,255,.08); --shadow: 0 10px 30px rgba(0,0,0,.35);
      --radius:16px; --accent:#60a5fa; --accent2:#34d399; --danger:#fb7185;
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
    .wrap{max-width:1180px;margin:0 auto;padding:26px 18px 60px;}
    .topbar{
      display:flex;align-items:center;justify-content:space-between;gap:14px;
      padding:18px 18px;background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
      border:1px solid var(--border);border-radius: var(--radius);box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    .brand{display:flex;align-items:center;gap:12px;}
    .logo{
      width:40px;height:40px;border-radius:12px;
      background: linear-gradient(135deg, rgba(96,165,250,.9), rgba(52,211,153,.85));
      box-shadow: 0 10px 25px rgba(96,165,250,.25);
    }
    h1{font-size:18px;margin:0;}
    .sub{font-size:12px;color:var(--muted);margin-top:2px;}
    .pill{
      font-size:12px;color: var(--muted);border:1px solid var(--border);padding:6px 10px;border-radius:999px;
      background: rgba(15,23,42,.6);display:inline-flex;align-items:center;gap:6px;
    }
    .grid{margin-top:18px;display:grid;grid-template-columns:repeat(12,1fr);gap:16px;}
    .span12{grid-column:1/-1;}
    .span4{grid-column:span 4;}
    @media (max-width: 1000px){
      .span4{grid-column:1/-1;}
      .topbar{flex-direction:column;align-items:flex-start;}
    }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);border-radius: var(--radius);box-shadow: var(--shadow);padding:16px;
    }
    .card h2{
      margin:0 0 6px 0;font-size:14px;font-weight:950;letter-spacing:.2px;
      display:flex;justify-content:space-between;align-items:center;gap:10px;
    }
    .muted{color:var(--muted);font-size:12px;line-height:1.45;}
    .price{font-size:30px;font-weight:1000;margin-top:12px;}
    .list{margin:12px 0 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:10px;}
    .list li{padding:10px 10px;border-radius:12px;border:1px solid var(--border);background: rgba(15,23,42,.55);font-size:13px;line-height:1.35;}
    .btn{
      width:100%;margin-top:14px;padding:12px 14px;border-radius:12px;border:1px solid var(--border);
      background: rgba(96,165,250,.14);color: var(--text);cursor:pointer;font-weight:950;
    }
    .btn:hover{border-color: rgba(96,165,250,.5)}
    .btnGreen{background: rgba(52,211,153,.14);}
    .btnGreen:hover{border-color: rgba(52,211,153,.5)}
    .note{margin-top:16px;padding:12px;border-radius:14px;border:1px solid var(--border);background: rgba(15,23,42,.55);}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
    .tiny{font-size:12px;color:var(--muted)}
    .ok{color: var(--accent2);font-weight:900}
    .err{color: var(--danger);font-weight:900}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava Storefront</h1>
          <div class="sub">Pick a plan to activate your dashboard — you can switch anytime.</div>
        </div>
      </div>

      <div class="row">
        <span class="pill">Site: <b>${site_id}</b></span>
        <span class="pill">Current plan: <b>${plan}</b></span>
      </div>
    </div>

    <div class="grid">
      <div class="card span12">
        <h2>Activation <span class="pill">Demo mode</span></h2>
        <div class="muted">
          Clicking “Activate” will update your plan instantly (no Stripe yet).
          Later we’ll swap the activation call to Stripe webhooks.
        </div>
        <div class="note" style="margin-top:12px;">
          <div class="row">
            <div class="tiny">Status:</div>
            <div id="status" class="tiny">Idle</div>
          </div>
        </div>
      </div>

      <div class="card span4">
        <h2>Starter <span class="pill">Essentials</span></h2>
        <div class="muted">Basic tracking + quick insights.</div>
        <div class="price">$29<span class="tiny">/mo</span></div>
        <ul class="list">
          <li>Visits today + trend chart</li>
          <li>Top pages + device mix</li>
          <li>Demo report history view</li>
        </ul>
        <button class="btn" id="btnStarter">Activate Starter</button>
      </div>

      <div class="card span4">
        <h2>Pro <span class="pill">Reports</span></h2>
        <div class="muted">Reporting + email sending.</div>
        <div class="price">$79<span class="tiny">/mo</span></div>
        <ul class="list">
          <li>Everything in Starter</li>
          <li>Email latest report (manual trigger)</li>
          <li>Longer report history</li>
        </ul>
        <button class="btn btnGreen" id="btnPro">Activate Pro</button>
      </div>

      <div class="card span4">
        <h2>Full AI <span class="pill">GPT</span></h2>
        <div class="muted">Generate AI summaries + next steps.</div>
        <div class="price">$199<span class="tiny">/mo</span></div>
        <ul class="list">
          <li>Everything in Pro</li>
          <li>Generate AI report (manual trigger)</li>
          <li>Best for “assistant” experience</li>
        </ul>
        <button class="btn btnGreen" id="btnAI">Activate Full AI</button>
      </div>
    </div>
  </div>

<script>
  var token = new URLSearchParams(location.search).get("token");
  var statusEl = document.getElementById("status");

  function setStatus(t, isErr){
    statusEl.textContent = t;
    statusEl.className = "tiny " + (isErr ? "err" : "ok");
  }

  async function activate(plan){
    try{
      statusEl.className = "tiny";
      statusEl.textContent = "Activating " + plan + "…";

      const r = await fetch("/demo/activate-plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token, plan: plan })
      });

      const data = await r.json();
      if(!data.ok){
        setStatus(data.error || "Activation failed", true);
        return;
      }

      setStatus("Activated: " + data.updated.plan + " ✅ Redirecting…", false);
      setTimeout(function(){
        location.href = "/dashboard?token=" + encodeURIComponent(token);
      }, 700);
    }catch(e){
      setStatus("Activation error: " + (e && e.message ? e.message : "unknown"), true);
    }
  }

  document.getElementById("btnStarter").addEventListener("click", function(){ activate("starter"); });
  document.getElementById("btnPro").addEventListener("click", function(){ activate("pro"); });
  document.getElementById("btnAI").addEventListener("click", function(){ activate("full_ai"); });
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/* ---------------------------
   DEMO: activate a plan from the storefront (NO secret)
   POST /demo/activate-plan
   Body: { token, plan }
----------------------------*/
app.post("/demo/activate-plan", async (req, res) => {
  try {
    const { token, plan } = req.body || {};
    const allowed = new Set(["starter", "pro", "full_ai"]);

    if (!token) return res.status(400).json({ ok: false, error: "token required" });
    if (!plan || !allowed.has(plan)) {
      return res.status(400).json({ ok: false, error: "Invalid plan. Use starter, pro, or full_ai" });
    }

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const r = await pool.query(
      `UPDATE sites SET plan=$2 WHERE site_id=$1 RETURNING site_id, plan`,
      [site.site_id, plan]
    );

    res.json({ ok: true, updated: r.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------
   Dashboard UI (token-based)
   GET /dashboard?token=...
----------------------------*/
app.get("/dashboard", async (req, res) => {
  try {
    setNoStore(res);

    const token = req.query.token;
    const site = await getSiteByToken(token);
    if (!site) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

    const site_id = site.site_id;
    const plan = site.plan || "unpaid";

    // If unpaid, send them to storefront
    if (plan === "unpaid") {
      return res.redirect(`/storefront?token=${encodeURIComponent(token)}`);
    }

    res.setHeader("Content-Type", "text/html");

    // Minimal dashboard UI (works now). You can paste your fancy UI later.
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Constrava Dashboard</title>
  <style>
    body{margin:0;font-family:system-ui;background:#0b0f19;color:#e5e7eb}
    .wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
    .top{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;
      border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:16px;background:rgba(255,255,255,.04)}
    .pill{border:1px solid rgba(255,255,255,.12);border-radius:999px;padding:6px 10px;color:#9ca3af;font-size:12px}
    .btn{padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(96,165,250,.14);color:#e5e7eb;cursor:pointer;font-weight:800}
    .grid{margin-top:14px;display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
    .card{grid-column:span 6;border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:16px;background:rgba(255,255,255,.04)}
    @media (max-width:900px){.card{grid-column:1/-1}}
    .kpi{font-size:34px;font-weight:950;margin-top:10px}
    .muted{color:#9ca3af;font-size:13px;line-height:1.45}
    select{padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(15,23,42,.6);color:#e5e7eb;font-weight:900}
    pre{white-space:pre-wrap;background:rgba(15,23,42,.6);padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);overflow:auto}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <div style="font-weight:950;">Constrava Dashboard</div>
        <div class="muted">Plan: <b>${plan}</b> • Site: <b>${site_id}</b></div>
      </div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <span class="pill">token-auth</span>
        <select id="rangeSel">
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
      <div class="card">
        <div class="muted">Visits today</div>
        <div class="kpi" id="visitsToday">—</div>
        <div class="muted" id="rangeLabel"></div>
      </div>

      <div class="card">
        <div class="muted">Top page (range)</div>
        <div class="kpi" style="font-size:22px" id="topPage">—</div>
        <div class="muted" id="deviceMix">—</div>
      </div>

      <div class="card" style="grid-column:1/-1">
        <div class="muted">Debug (metrics payload)</div>
        <pre id="payload">Loading…</pre>
      </div>
    </div>
  </div>

<script>
  const token = new URLSearchParams(location.search).get("token");
  const sel = document.getElementById("rangeSel");
  const refreshBtn = document.getElementById("refreshBtn");

  async function load(){
    const days = sel.value;
    const r = await fetch("/metrics?token=" + encodeURIComponent(token) + "&days=" + encodeURIComponent(days));
    const data = await r.json();

    document.getElementById("payload").textContent = JSON.stringify(data, null, 2);

    if(!data.ok) return;

    document.getElementById("visitsToday").textContent = data.visits_today ?? 0;
    document.getElementById("rangeLabel").textContent = "Visits in last " + data.days + " days: " + (data.visits_range ?? 0);

    const top = data.top_page && data.top_page.page_type ? (data.top_page.page_type + " (" + data.top_page.views + ")") : "—";
    document.getElementById("topPage").textContent = top;

    const dm = data.device_mix || {mobile:0, desktop:0};
    document.getElementById("deviceMix").textContent = "Device mix: mobile " + (dm.mobile||0) + " • desktop " + (dm.desktop||0);
  }

  refreshBtn.addEventListener("click", load);
  sel.addEventListener("change", load);
  load();
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

/* ---------------------------
   Billing webhook: update plan (Stripe later)
   POST /billing/update-plan
   Headers: x-webhook-secret: BILLING_WEBHOOK_SECRET
   Body: { site_id, plan }
----------------------------*/
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
      `UPDATE sites SET plan = $2 WHERE site_id = $1 RETURNING site_id, plan`,
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
   Start server
----------------------------*/
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
