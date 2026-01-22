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
import bcrypt from "bcrypt";
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
</head>
<body style="font-family:Arial; padding:20px;">
  <h1>Constrava Dashboard ✅</h1>
  <p>Authorized for site: <b>${site_id}</b></p>
  <p>Now open:</p>
  <ul>
    <li><a href="/reports/latest?token=${token}">/reports/latest?token=...</a></li>
    <li><a href="/reports?token=${token}">/reports?token=...</a></li>
  </ul>
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
