// index.js (ESM) — Constrava MVP+ backend (dashboard + storefront + auth + charts + AI UI + optional scheduler)
//
// ✅ Neon Postgres (pg)
// ✅ /sites creates site_id + dashboard_token (token = "site access token")
// ✅ tracker: /tracker.js + /events collector
// ✅ token-secured dashboard + APIs
// ✅ storefront route + demo plan activation (Stripe later)
// ✅ user accounts: /auth/register, /auth/login (cookie sessions)
// ✅ dashboard graphs (SVG) + reports UI + AI generate button
// ✅ optional in-process daily scheduler (NOT real cron) + manual job trigger
//
// ✅ DEMO/CLIENT “FUN” FEATURES ADDED (the “everything” pack)
// ✅ Live traffic endpoint: GET /live?token=...&since=ISO
// ✅ Demo event firing: POST /demo/fire-event { token, event_name, page_type, device }
// ✅ Shareable demo links: POST /demo/link { token } -> { url } and GET /d/:code redirects to dashboard
// ✅ Action plan AI endpoint (full_ai only): POST /generate-action-plan?token=...
// ✅ Enhanced metrics: conversions + top pages (10) + share % + conversion rate
// ✅ Demo seeder can also seed leads/purchases/cta_click (optional rates)
//
// ENV REQUIRED:
// - DATABASE_URL
//
// OPTIONAL ENV:
// - PUBLIC_BASE_URL (recommended)
// - PUBLIC_EVENTS_URL (if tracker collector differs)
// - ENABLE_DEMO_SEED=true  (allow /demo/seed)
// - ENABLE_DEMO_ACTIVATE=true (allow plan activation via /demo/activate-plan)
// - OPENAI_API_KEY (+ optional OPENAI_MODEL)
// - RESEND_API_KEY + FROM_EMAIL (email sending)
// - ENABLE_SCHEDULER=true (in-process scheduler; not reliable like real cron)
// - BILLING_WEBHOOK_SECRET (reserved for Stripe later)

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) console.error("Missing DATABASE_URL env var");
const pool = new Pool({ connectionString: DATABASE_URL });

/* ---------------------------
   Small helpers
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
  if (!site_id) return "site_id is required";
  if (site_id.length < 4 || site_id.length > 24) return "site_id must be 4–24 characters";
  if (!/^[a-z][a-z0-9-]*$/.test(site_id))
    return "site_id must start with a letter and use only lowercase, numbers, and hyphens";
  if (site_id.includes("--")) return "site_id cannot contain double hyphens";
  if (site_id.endsWith("-")) return "site_id cannot end with a hyphen";
  return null;
}

function validateCustomToken(token) {
  if (!token) return "access token is required";
  if (token.length < 20) return "access token must be at least 20 characters";
  if (!/[a-z]/.test(token)) return "access token must include a lowercase letter";
  if (!/[A-Z]/.test(token)) return "access token must include an uppercase letter";
  if (!/[0-9]/.test(token)) return "access token must include a number";
  if (!/[^A-Za-z0-9]/.test(token)) return "access token must include a symbol";
  return null;
}

// password hashing (no bcrypt)
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, "hex");
  const hash = Buffer.from(hashHex, "hex");
  const test = crypto.scryptSync(String(password), salt, 64);
  return crypto.timingSafeEqual(hash, test);
}

function safeEmail(x) {
  return String(x || "").trim().toLowerCase();
}

function planGate(site, allowedPlans) {
  const plan = site?.plan || "unpaid";
  if (allowedPlans.includes(plan)) return { ok: true };
  return {
    ok: false,
    status: 403,
    error: `This feature requires plan: ${allowedPlans.join(" or ")}. Your plan: ${plan}.`
  };
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function clamp01(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(1, x));
}

/* ---------------------------
   DB helpers
----------------------------*/
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

async function getSiteById(site_id) {
  const r = await pool.query(
    `SELECT site_id, site_name, owner_email, dashboard_token, plan
     FROM sites
     WHERE site_id=$1
     LIMIT 1`,
    [site_id]
  );
  return r.rows[0] || null;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map((s) => s.trim());
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx > 0) {
      const k = p.slice(0, idx);
      const v = p.slice(idx + 1);
      if (k === name) return decodeURIComponent(v);
    }
  }
  return null;
}

function setCookie(res, name, value, opts = {}) {
  const {
    httpOnly = true,
    sameSite = "Lax",
    secure = false,
    path = "/",
    maxAgeSeconds = 60 * 60 * 24 * 14 // 14 days
  } = opts;

  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `SameSite=${sameSite}`,
    `Max-Age=${maxAgeSeconds}`
  ];
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax`);
}

async function getSession(req) {
  const sid = getCookie(req, "constrava_session");
  if (!sid) return null;

  const r = await pool.query(
    `SELECT s.session_id, s.user_id, s.expires_at, u.email, u.site_id
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.session_id=$1
     LIMIT 1`,
    [sid]
  );

  const row = r.rows[0];
  if (!row) return null;

  const expires = new Date(row.expires_at).getTime();
  if (!Number.isFinite(expires) || expires < Date.now()) return null;

  return row;
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
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
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

  // ✅ shareable demo links
  await pool.query(`
    CREATE TABLE IF NOT EXISTS demo_links (
      code TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("✅ Tables ready");
}
ensureTables().catch((e) => console.error("ensureTables failed:", e.message));

/* ---------------------------
   Basic routes
----------------------------*/
app.get("/", (req, res) => res.send("Backend is running ✅"));

app.get(
  "/db-test",
  asyncHandler(async (req, res) => {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  })
);

app.get(
  "/debug/site",
  asyncHandler(async (req, res) => {
    const token = req.query.token;
    const site = await getSiteByToken(token);
    res.json({ ok: true, site });
  })
);

/* ---------------------------
   Auth (real user accounts)
----------------------------*/
app.post(
  "/auth/register",
  asyncHandler(async (req, res) => {
    const { site_id: rawSiteId, email, password, token } = req.body || {};
    const site_id = normalizeSiteId(rawSiteId);

    if (!site_id || !email || !password || !token) {
      return res
        .status(400)
        .json({ ok: false, error: "site_id, email, password, and token are required" });
    }

    // Must prove they own the site via access token
    const site = await getSiteById(site_id);
    if (!site) return res.status(404).json({ ok: false, error: "site_id not found" });
    if (site.dashboard_token !== token)
      return res.status(401).json({ ok: false, error: "Invalid site token" });

    const e = safeEmail(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))
      return res.status(400).json({ ok: false, error: "Invalid email" });
    if (String(password).length < 8)
      return res.status(400).json({ ok: false, error: "Password must be at least 8 characters" });

    const { salt, hash } = hashPassword(password);

    try {
      const r = await pool.query(
        `INSERT INTO users (site_id, email, password_salt, password_hash)
       VALUES ($1,$2,$3,$4)
       RETURNING id, email, site_id`,
        [site_id, e, salt, hash]
      );
      res.json({ ok: true, user: r.rows[0] });
    } catch (err) {
      const msg = String(err.message || "");
      if (msg.toLowerCase().includes("unique")) {
        return res.status(409).json({ ok: false, error: "Email already registered" });
      }
      res.status(500).json({ ok: false, error: msg });
    }
  })
);

app.post(
  "/auth/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    const e = safeEmail(email);

    if (!e || !password) return res.status(400).json({ ok: false, error: "email and password required" });

    const r = await pool.query(
      `SELECT id, site_id, email, password_salt, password_hash
     FROM users
     WHERE email=$1
     LIMIT 1`,
      [e]
    );
    if (r.rows.length === 0) return res.status(401).json({ ok: false, error: "Invalid login" });

    const u = r.rows[0];
    if (!verifyPassword(password, u.password_salt, u.password_hash)) {
      return res.status(401).json({ ok: false, error: "Invalid login" });
    }

    const session_id = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 14 days

    await pool.query(`INSERT INTO sessions (session_id, user_id, expires_at) VALUES ($1,$2,$3)`, [
      session_id,
      u.id,
      expiresAt.toISOString()
    ]);

    setCookie(res, "constrava_session", session_id, {
      httpOnly: true,
      sameSite: "Lax",
      secure: String(process.env.COOKIE_SECURE || "false") === "true"
    });

    const site = await getSiteById(u.site_id);

    res.json({
      ok: true,
      user: { email: u.email, site_id: u.site_id },
      site: { site_id: site?.site_id, plan: site?.plan || "unpaid" },
      hint: "You are logged in (cookie). Dashboard still requires ?token=... for now."
    });
  })
);

app.post(
  "/auth/logout",
  asyncHandler(async (req, res) => {
    const sid = getCookie(req, "constrava_session");
    if (sid) {
      await pool.query(`DELETE FROM sessions WHERE session_id=$1`, [sid]);
    }
    clearCookie(res, "constrava_session");
    res.json({ ok: true });
  })
);

app.get(
  "/me",
  asyncHandler(async (req, res) => {
    const sess = await getSession(req);
    if (!sess) return res.json({ ok: true, logged_in: false });
    res.json({
      ok: true,
      logged_in: true,
      user: { email: sess.email, site_id: sess.site_id },
      expires_at: sess.expires_at
    });
  })
);

/* ---------------------------
   Onboarding: create a site
   POST /sites { site_id, site_name, owner_email, custom_token? }
----------------------------*/
app.post(
  "/sites",
  asyncHandler(async (req, res) => {
    const { site_id: rawSiteId, site_name, owner_email, custom_token } = req.body || {};

    if (!rawSiteId || !site_name || !owner_email) {
      return res.status(400).json({ ok: false, error: "site_id, site_name, and owner_email are required" });
    }

    const site_id = normalizeSiteId(rawSiteId);
    const siteIdErr = validateSiteId(site_id);
    if (siteIdErr) return res.status(400).json({ ok: false, error: siteIdErr });

    let token = crypto.randomUUID();
    if (custom_token) {
      const tokErr = validateCustomToken(custom_token);
      if (tokErr) return res.status(400).json({ ok: false, error: tokErr });
      token = custom_token;
    }

    try {
      await pool.query(
        `INSERT INTO sites (site_id, site_name, owner_email, dashboard_token, plan)
       VALUES ($1,$2,$3,$4,'unpaid')`,
        [site_id, String(site_name).trim(), safeEmail(owner_email), token]
      );
    } catch (err) {
      const msg = String(err.message || "");
      if (msg.toLowerCase().includes("duplicate") || msg.toLowerCase().includes("unique")) {
        return res.status(409).json({ ok: false, error: "That site_id is already taken. Choose another." });
      }
      throw err;
    }

    const base = publicBaseUrl(req);

    res.json({
      ok: true,
      site_id,
      access_token: token,
      install_snippet: `<script src="${base}/tracker.js" data-site-id="${site_id}"></script>`,
      client_dashboard_url: `${base}/dashboard?token=${encodeURIComponent(token)}`
    });
  })
);

/* ---------------------------
   Tracker script
   GET /tracker.js
----------------------------*/
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");
  const endpoint = (process.env.PUBLIC_EVENTS_URL || "https://constrava-backend.onrender.com") + "/events";

  // very small, safe snippet: page_view only
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
app.post(
  "/events",
  asyncHandler(async (req, res) => {
    const { site_id, event_name, page_type, device } = req.body || {};
    if (!site_id || !event_name) {
      return res.status(400).json({ ok: false, error: "site_id and event_name required" });
    }

    const site = await pool.query("SELECT 1 FROM sites WHERE site_id=$1", [site_id]);
    if (site.rows.length === 0) return res.status(403).json({ ok: false, error: "Invalid site_id" });

    await pool.query(
      `INSERT INTO events_raw (site_id, event_name, page_type, device)
     VALUES ($1,$2,$3,$4)`,
      [site_id, String(event_name), page_type || null, device || null]
    );

    res.json({ ok: true });
  })
);

/* ---------------------------
   DEMO: fire events (page_view / lead / purchase / cta_click)
   POST /demo/fire-event { token, event_name, page_type?, device? }
----------------------------*/
app.post(
  "/demo/fire-event",
  asyncHandler(async (req, res) => {
    const { token, event_name, page_type, device } = req.body || {};
    if (!token) return res.status(400).json({ ok: false, error: "token required" });
    if (!event_name) return res.status(400).json({ ok: false, error: "event_name required" });

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const allowed = new Set(["page_view", "lead", "purchase", "cta_click"]);
    if (!allowed.has(event_name)) {
      return res.status(400).json({ ok: false, error: "Invalid event_name. Use page_view, lead, purchase, cta_click" });
    }

    await pool.query(
      `INSERT INTO events_raw (site_id, event_name, page_type, device)
       VALUES ($1,$2,$3,$4)`,
      [site.site_id, event_name, page_type || "/", device || "desktop"]
    );

    res.json({ ok: true });
  })
);

/* ---------------------------
   LIVE: new page_views since timestamp
   GET /live?token=...&since=ISO
----------------------------*/
app.get(
  "/live",
  asyncHandler(async (req, res) => {
    setNoStore(res);

    const token = req.query.token;
    const since = req.query.since; // ISO
    if (!token) return res.status(400).json({ ok: false, error: "token required" });

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const sinceDate = since ? new Date(String(since)) : null;
    if (since && isNaN(sinceDate.getTime())) {
      return res.status(400).json({ ok: false, error: "Invalid since timestamp" });
    }

    const params = [site.site_id];
    let whereSince = "";
    if (sinceDate) {
      params.push(sinceDate.toISOString());
      whereSince = ` AND created_at > $2`;
    }

    const newViewsRes = await pool.query(
      `
      SELECT COUNT(*)::int AS new_page_views
      FROM events_raw
      WHERE site_id=$1
        AND event_name='page_view'
        ${whereSince}
      `,
      params
    );

    const lastEventRes = await pool.query(
      `
      SELECT event_name, page_type, device, created_at
      FROM events_raw
      WHERE site_id=$1
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [site.site_id]
    );

    res.json({
      ok: true,
      site_id: site.site_id,
      since: sinceDate ? sinceDate.toISOString() : null,
      new_page_views: newViewsRes.rows[0]?.new_page_views || 0,
      last_event: lastEventRes.rows[0] || null,
      now: new Date().toISOString()
    });
  })
);

/* ---------------------------
   DEMO: shareable link
   POST /demo/link { token } -> { url }
   GET /d/:code -> redirect to /dashboard?token=...
----------------------------*/
app.post(
  "/demo/link",
  asyncHandler(async (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ ok: false, error: "token required" });

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const code = crypto.randomBytes(4).toString("hex"); // short
    await pool.query(`INSERT INTO demo_links (code, token) VALUES ($1,$2)`, [code, token]);

    const base = process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com";
    res.json({ ok: true, code, url: `${base}/d/${code}` });
  })
);

app.get(
  "/d/:code",
  asyncHandler(async (req, res) => {
    setNoStore(res);
    const code = String(req.params.code || "").trim();
    const r = await pool.query(`SELECT token FROM demo_links WHERE code=$1 LIMIT 1`, [code]);
    if (r.rows.length === 0) return res.status(404).send("Demo link not found");
    const token = r.rows[0].token;
    return res.redirect("/dashboard?token=" + encodeURIComponent(token));
  })
);

/* ---------------------------
   Metrics (token-secured)
   GET /metrics?token=...&days=7
   ✅ includes conversions + top pages (10) + share % + conversion rate
----------------------------*/
app.get(
  "/metrics",
  asyncHandler(async (req, res) => {
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

    const topPagesRes = await pool.query(
      `
    SELECT page_type, COUNT(*)::int AS views
    FROM events_raw
    WHERE site_id = $1
      AND event_name = 'page_view'
      AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
      AND page_type IS NOT NULL
    GROUP BY page_type
    ORDER BY views DESC
    LIMIT 5
    `,
      [site_id, days]
    );

    const topPagesRangeRes = await pool.query(
      `
    SELECT page_type, COUNT(*)::int AS views
    FROM events_raw
    WHERE site_id = $1
      AND event_name = 'page_view'
      AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
      AND page_type IS NOT NULL
    GROUP BY page_type
    ORDER BY views DESC
    LIMIT 10
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

    const goalsRangeRes = await pool.query(
      `
    SELECT
      SUM(CASE WHEN event_name='lead' THEN 1 ELSE 0 END)::int AS leads,
      SUM(CASE WHEN event_name='purchase' THEN 1 ELSE 0 END)::int AS purchases,
      SUM(CASE WHEN event_name='cta_click' THEN 1 ELSE 0 END)::int AS cta_clicks
    FROM events_raw
    WHERE site_id=$1
      AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
    `,
      [site_id, days]
    );

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

    const leads = goalsRangeRes.rows[0]?.leads || 0;
    const purchases = goalsRangeRes.rows[0]?.purchases || 0;
    const cta_clicks = goalsRangeRes.rows[0]?.cta_clicks || 0;

    const conversion_rate = visits_range ? Number((leads / visits_range).toFixed(4)) : 0;
    const purchase_rate = visits_range ? Number((purchases / visits_range).toFixed(4)) : 0;

    const totalRangeViews = topPagesRangeRes.rows.reduce((s, r) => s + (r.views || 0), 0);
    const top_pages_range = topPagesRangeRes.rows.map((r) => ({
      page_type: r.page_type,
      views: r.views,
      share: totalRangeViews ? Math.round((r.views / totalRangeViews) * 100) : 0
    }));

    res.json({
      ok: true,
      site_id,
      plan: site.plan || "unpaid",
      days,
      visits_today: todayRes.rows[0]?.visits_today || 0,
      visits_range,
      trend: trendRes.rows.map((r) => ({ day: String(r.day), visits: r.visits })),

      // original
      top_pages: topPagesRes.rows || [],
      device_mix: deviceRes.rows[0] || { mobile: 0, desktop: 0 },
      last_event: lastEventRes.rows[0] || null,

      // new goodies
      leads,
      purchases,
      cta_clicks,
      conversion_rate, // leads / visits_range
      purchase_rate, // purchases / visits_range
      top_pages_range
    });
  })
);

/* ---------------------------
   Reports: list + latest
----------------------------*/
app.get(
  "/reports",
  asyncHandler(async (req, res) => {
    setNoStore(res);

    const site = await getSiteByToken(req.query.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);

    const r = await pool.query(
      `SELECT site_id, report_date, created_at, LEFT(report_text, 260) AS preview
     FROM daily_reports
     WHERE site_id=$1
     ORDER BY report_date DESC, created_at DESC
     LIMIT $2`,
      [site.site_id, limit]
    );

    res.json({ ok: true, reports: r.rows });
  })
);

app.get(
  "/reports/latest",
  asyncHandler(async (req, res) => {
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
  })
);

/* ---------------------------
   Demo data seeder
   POST /demo/seed?token=...
   Body options:
   - days (default 7)
   - events_per_day (default 40, max 500)
   - lead_rate (0..1) default 0.02
   - purchase_rate (0..1) default 0.004
   - cta_rate (0..1) default 0.06
----------------------------*/
app.post(
  "/demo/seed",
  asyncHandler(async (req, res) => {
    if (process.env.ENABLE_DEMO_SEED !== "true") {
      return res.status(403).json({ ok: false, error: "Seeder disabled. Set ENABLE_DEMO_SEED=true" });
    }

    const site = await getSiteByToken(req.query.token || req.body?.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Provide ?token=..." });

    const site_id = site.site_id;
    const days = Math.max(1, Math.min(parseInt(req.body?.days || "7", 10), 3650));
    const eventsPerDay = Math.max(5, Math.min(parseInt(req.body?.events_per_day || "40", 10), 500));

    const leadRate = clamp01(req.body?.lead_rate ?? 0.02);
    const purchaseRate = clamp01(req.body?.purchase_rate ?? 0.004);
    const ctaRate = clamp01(req.body?.cta_rate ?? 0.06);

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
          r < 0.30
            ? "/"
            : r < 0.55
              ? "/pricing"
              : r < 0.70
                ? "/services"
                : r < 0.80
                  ? "/contact"
                  : pages[Math.floor(Math.random() * pages.length)];

        const device = Math.random() < 0.62 ? "mobile" : "desktop";

        await pool.query(
          `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
         VALUES ($1, 'page_view', $2, $3, $4)`,
          [site_id, page, device, ts.toISOString()]
        );
        inserted++;

        // optional extra events
        const roll = Math.random();
        if (roll < purchaseRate) {
          await pool.query(
            `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
             VALUES ($1, 'purchase', $2, $3, $4)`,
            [site_id, "/checkout", device, ts.toISOString()]
          );
          inserted++;
        } else if (roll < purchaseRate + leadRate) {
          await pool.query(
            `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
             VALUES ($1, 'lead', $2, $3, $4)`,
            [site_id, "/contact", device, ts.toISOString()]
          );
          inserted++;
        } else if (roll < purchaseRate + leadRate + ctaRate) {
          await pool.query(
            `INSERT INTO events_raw (site_id, event_name, page_type, device, created_at)
             VALUES ($1, 'cta_click', $2, $3, $4)`,
            [site_id, page, device, ts.toISOString()]
          );
          inserted++;
        }
      }
    }

    // seed 2 reports
    const sample1 =
      "Summary:\nTraffic is concentrating on Pricing and Services.\n\n" +
      "Trend:\nVisitors are exploring multiple pages.\n\n" +
      "Next steps:\n1) Add a clear primary CTA on Pricing\n2) Add proof (logos/testimonials)\n3) Track a lead event\n\n" +
      "Metric to watch:\nPricing → Contact rate";

    const sample2 =
      "Summary:\nYou’re getting steady visits and people are checking Pricing.\n\n" +
      "Trend:\nInterest is consistent — conversion work likely helps.\n\n" +
      "Next steps:\n1) Strongest offer at top of Pricing\n2) Add a 3-step “what happens next”\n3) Shorten forms + speed up pages\n\n" +
      "Metric to watch:\nCTA clicks";

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

    res.json({
      ok: true,
      site_id,
      days,
      events_per_day: eventsPerDay,
      lead_rate: leadRate,
      purchase_rate: purchaseRate,
      cta_rate: ctaRate,
      inserted
    });
  })
);

/* ---------------------------
   AI report generator (FULL AI only)
   POST /generate-report?token=...
----------------------------*/
app.post(
  "/generate-report",
  asyncHandler(async (req, res) => {
    const site = await getSiteByToken(req.query.token || req.body?.token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const gate = planGate(site, ["full_ai"]);
    if (!gate.ok) return res.status(gate.status).json({ ok: false, error: gate.error });

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
      [site.site_id]
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
          {
            role: "system",
            content: "You are a helpful business analytics assistant. Be plain-English, actionable, and concise."
          },
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
      [site.site_id, reportText]
    );

    res.json({ ok: true, report: saved.rows[0] });
  })
);

/* ---------------------------
   AI action plan (FULL AI only)
   POST /generate-action-plan?token=...
   - richer “wow” output and saves as today's report
----------------------------*/
app.post(
  "/generate-action-plan",
  asyncHandler(async (req, res) => {
    setNoStore(res);

    const token = req.query.token || req.body?.token;
    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

    const gate = planGate(site, ["full_ai"]);
    if (!gate.ok) return res.status(gate.status).json({ ok: false, error: gate.error });

    const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");
    const days = 30;

    const trendRes = await pool.query(
      `
      SELECT created_at::date AS day, COUNT(*)::int AS visits
      FROM events_raw
      WHERE site_id=$1
        AND event_name='page_view'
        AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
      GROUP BY 1
      ORDER BY 1
      `,
      [site.site_id, days]
    );

    const topPagesRes = await pool.query(
      `
      SELECT page_type, COUNT(*)::int AS views
      FROM events_raw
      WHERE site_id=$1
        AND event_name='page_view'
        AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
        AND page_type IS NOT NULL
      GROUP BY 1
      ORDER BY views DESC
      LIMIT 10
      `,
      [site.site_id, days]
    );

    const goalsRes = await pool.query(
      `
      SELECT
        SUM(CASE WHEN event_name='lead' THEN 1 ELSE 0 END)::int AS leads,
        SUM(CASE WHEN event_name='purchase' THEN 1 ELSE 0 END)::int AS purchases,
        SUM(CASE WHEN event_name='cta_click' THEN 1 ELSE 0 END)::int AS cta_clicks
      FROM events_raw
      WHERE site_id=$1
        AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
      `,
      [site.site_id, days]
    );

    const payload = {
      site_id: site.site_id,
      window_days: days,
      trend: trendRes.rows,
      top_pages: topPagesRes.rows,
      goals: goalsRes.rows[0] || { leads: 0, purchases: 0, cta_clicks: 0 }
    };

    const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o",
        messages: [
          { role: "system", content: "You are an analytics + conversion expert. Be plain-English, specific, and actionable." },
          {
            role: "user",
            content:
              "Analyze this site data JSON and write a short action plan.\n\n" +
              JSON.stringify(payload) +
              "\n\nFormat:\n1) What's happening (3 bullets)\n2) Biggest opportunity\n3) 5-step action plan\n4) One KPI to watch\n5) A one-sentence executive summary"
          }
        ]
      })
    });

    const aiData = await aiRes.json();
    const text = aiData?.choices?.[0]?.message?.content;
    if (!text) return res.status(500).json({ ok: false, error: "AI response missing" });

    const saved = await pool.query(
      `INSERT INTO daily_reports (site_id, report_date, report_text)
       VALUES ($1, CURRENT_DATE, $2)
       ON CONFLICT (site_id, report_date)
       DO UPDATE SET report_text = EXCLUDED.report_text
       RETURNING site_id, report_date, report_text, created_at`,
      [site.site_id, text]
    );

    res.json({ ok: true, report: saved.rows[0] });
  })
);

/* ---------------------------
   Email latest report (PRO + FULL AI)
   POST /email-latest { token, to_email }
----------------------------*/
app.post(
  "/email-latest",
  asyncHandler(async (req, res) => {
    const { token, to_email } = req.body || {};
    if (!to_email) return res.status(400).json({ ok: false, error: "to_email required" });

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Invalid token" });

    const gate = planGate(site, ["pro", "full_ai"]);
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
        to: [String(to_email).trim()],
        subject: `Constrava Daily Report (${site.site_id})`,
        html: `<pre style="white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;">${r.rows[0].report_text}</pre>`
      })
    });

    const emailData = await emailRes.json();
    res.json({ ok: true, resend: emailData });
  })
);

/* ---------------------------
   Storefront (no Stripe yet)
   GET  /storefront?token=...
----------------------------*/
app.get(
  "/storefront",
  asyncHandler(async (req, res) => {
    setNoStore(res);

    const token = req.query.token;
    const site = await getSiteByToken(token);
    if (!site) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

    const site_id = site.site_id;
    const plan = site.plan || "unpaid";

    res.setHeader("Content-Type", "text/html");

    res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Constrava — Plans</title>
<style>
  :root{
    --bg:#0b0f19; --panel:#111827; --panel2:#0f172a; --text:#e5e7eb; --muted:#9ca3af;
    --border:rgba(255,255,255,.10); --accent:#60a5fa; --accent2:#34d399; --danger:#fb7185;
    --shadow:0 10px 30px rgba(0,0,0,.35); --radius:16px;
  }
  *{box-sizing:border-box}
  body{
    margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    background: radial-gradient(1200px 800px at 20% -10%, rgba(96,165,250,.22), transparent 60%),
                radial-gradient(900px 600px at 90% 0%, rgba(52,211,153,.16), transparent 55%),
                var(--bg);
    color:var(--text);
  }
  .wrap{max-width:1100px;margin:0 auto;padding:26px 18px 70px;}
  .topbar{
    display:flex;align-items:center;justify-content:space-between;gap:14px;padding:18px;
    border:1px solid var(--border); border-radius: var(--radius);
    background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
    box-shadow: var(--shadow);
  }
  .brand{display:flex;align-items:center;gap:12px;}
  .logo{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg, rgba(96,165,250,.9), rgba(52,211,153,.85));}
  h1{font-size:18px;margin:0;}
  .sub{font-size:12px;color:var(--muted);margin-top:2px;}
  .pill{font-size:12px;color:var(--muted);border:1px solid var(--border);padding:6px 10px;border-radius:999px;background: rgba(15,23,42,.6);}
  .grid{margin-top:18px;display:grid;grid-template-columns:repeat(12,1fr);gap:16px;}
  .card{
    grid-column: span 4; padding:16px; border-radius: var(--radius);
    border:1px solid var(--border); background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
    box-shadow: var(--shadow);
  }
  @media (max-width: 980px){ .card{grid-column: 1 / -1;} .topbar{flex-direction:column; align-items:flex-start;} }
  .name{font-weight:950;margin:0}
  .price{margin-top:10px;font-size:28px;font-weight:1000;}
  .muted{color:var(--muted);font-size:12px;line-height:1.5}
  ul{margin:12px 0 0 0;padding:0 0 0 18px;line-height:1.6}
  .btn{
    width:100%; margin-top:14px; padding:12px 14px;
    border-radius:12px; border:1px solid var(--border);
    background: rgba(96,165,250,.14); color:var(--text);
    cursor:pointer; font-weight:950;
  }
  .btn:hover{border-color: rgba(96,165,250,.5)}
  .btnGreen{background: rgba(52,211,153,.14)}
  .btnGreen:hover{border-color: rgba(52,211,153,.5)}
  .note{
    margin-top:16px; padding:12px; border-radius: 14px; border:1px dashed rgba(255,255,255,.16);
    background: rgba(15,23,42,.35); color: var(--muted); font-size:13px; line-height:1.55;
  }
</style>
</head>
<body>
<!-- Report Modal -->
<div id="reportModal" style="display:none; position:fixed; inset:0; z-index:9999;">
  <div id="reportBackdrop" style="position:absolute; inset:0; background:rgba(0,0,0,.6);"></div>

  <div style="
    position:relative;
    max-width: 920px;
    margin: 6vh auto;
    padding: 0 14px;
  ">
    <div style="
      background: rgba(15,23,42,.92);
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 18px;
      box-shadow: 0 20px 60px rgba(0,0,0,.55);
      overflow:hidden;
    ">
      <div style="
        display:flex; justify-content:space-between; align-items:center;
        padding: 14px 14px;
        border-bottom: 1px solid rgba(255,255,255,.10);
        background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
      ">
        <div>
          <div style="font-weight:950; font-size:14px;">Report</div>
          <div id="reportModalMeta" style="font-size:12px; color: rgba(255,255,255,.65); margin-top:2px;">—</div>
        </div>
        <button id="closeReportModal" class="btn" style="background: rgba(251,113,133,.12);">
          Close
        </button>
      </div>

      <div style="padding: 14px;">
        <div id="reportModalBody" style="
          white-space: pre-wrap;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Courier New', monospace;
          font-size: 13px;
          line-height: 1.55;
          background: rgba(15,23,42,.65);
          border: 1px solid rgba(255,255,255,.10);
          border-radius: 14px;
          padding: 12px;
          max-height: 62vh;
          overflow:auto;
        ">Loading…</div>

        <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
          <button id="copyReportBtn" class="btn">Copy</button>
          <button id="downloadReportBtn" class="btn">Download .txt</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>Constrava Plans</h1>
        <div class="sub">Activate your dashboard. Stripe comes later — this is the working infrastructure.</div>
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <span class="pill">Site: <b>${site_id}</b></span>
      <span class="pill">Current plan: <b>${plan}</b></span>
      <span class="pill">Token login: <b>enabled</b></span>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3 class="name">Starter</h3>
      <div class="price">$29 <span class="muted">/mo</span></div>
      <div class="muted">Tracking + charts + insights.</div>
      <ul>
        <li>Dashboard charts</li>
        <li>Top pages + device mix</li>
        <li>Reports list</li>
      </ul>
      <button class="btn" onclick="activate('starter')">Activate Starter</button>
    </div>

    <div class="card">
      <h3 class="name">Pro</h3>
      <div class="price">$79 <span class="muted">/mo</span></div>
      <div class="muted">Reporting workflow + email sending.</div>
      <ul>
        <li>Everything in Starter</li>
        <li>Email latest report</li>
        <li>Scheduler-ready</li>
      </ul>
      <button class="btn btnGreen" onclick="activate('pro')">Activate Pro</button>
    </div>

    <div class="card">
      <h3 class="name">Full AI</h3>
      <div class="price">$199 <span class="muted">/mo</span></div>
      <div class="muted">AI summaries + next steps + action plans.</div>
      <ul>
        <li>Everything in Pro</li>
        <li>Generate AI report</li>
        <li>Generate AI action plan</li>
      </ul>
      <button class="btn btnGreen" onclick="activate('full_ai')">Activate Full AI</button>
    </div>
  </div>

  <div class="note">
    <b>Note:</b> These buttons call a demo activation endpoint. Later, Stripe will call the real webhook after payment.
  </div>

  <div class="note" id="status">Status: idle</div>
</div>

<script>
  const token = new URLSearchParams(location.search).get("token");
  const statusEl = document.getElementById("status");

  async function activate(plan){
    try{
      statusEl.textContent = "Status: activating " + plan + "...";
      const r = await fetch("/demo/activate-plan", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ token, plan })
      });
      const data = await r.json();
      if(!data.ok){
        statusEl.textContent = "Status: " + (data.error || "activation failed");
        return;
      }
      statusEl.textContent = "Status: activated ✅ redirecting...";
      setTimeout(() => location.href = "/dashboard?token=" + encodeURIComponent(token), 600);
    }catch(e){
      statusEl.textContent = "Status: error " + (e && e.message ? e.message : "unknown");
    }
  }
</script>
</body>
</html>`);
  })
);

/* ---------------------------
   DEMO: activate a plan (NO secret)
   POST /demo/activate-plan  { token, plan }
----------------------------*/
app.post(
  "/demo/activate-plan",
  asyncHandler(async (req, res) => {
    if (process.env.ENABLE_DEMO_ACTIVATE === "false") {
      return res.status(403).json({ ok: false, error: "Demo activation disabled" });
    }

    const { token, plan } = req.body || {};
    const allowed = new Set(["starter", "pro", "full_ai"]);

    if (!token) return res.status(400).json({ ok: false, error: "token required" });
    if (!plan || !allowed.has(plan)) return res.status(400).json({ ok: false, error: "Invalid plan" });

    const site = await getSiteByToken(token);
    if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const r = await pool.query(`UPDATE sites SET plan=$2 WHERE site_id=$1 RETURNING site_id, plan`, [
      site.site_id,
      plan
    ]);

    res.json({ ok: true, updated: r.rows[0] });
  })
);

/* ---------------------------
   Dashboard UI
   GET /dashboard?token=...
   - unpaid users redirect to /storefront
   - charts rendered with SVG
   - AI report button if full_ai
   ✅ Demo panel + live traffic + share link + action plan
----------------------------*/
app.get(
  "/dashboard",
  asyncHandler(async (req, res) => {
    setNoStore(res);

    const token = req.query.token;
    const site = await getSiteByToken(token);
    if (!site) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

    const site_id = site.site_id;
    const plan = site.plan || "unpaid";

    if (plan === "unpaid") {
      return res.redirect(`/storefront?token=${encodeURIComponent(token)}`);
    }

    res.setHeader("Content-Type", "text/html");
// --- Report Modal helpers ---
let LAST_REPORT = null;

function openReportModal(report){
  // report: { report_text, report_date, created_at }
  LAST_REPORT = report || null;

  const modal = document.getElementById("reportModal");
  const meta = document.getElementById("reportModalMeta");
  const body = document.getElementById("reportModalBody");

  if(!modal || !meta || !body) return;

  meta.textContent = report
    ? ("Date: " + (report.report_date || "—") + " • " + (report.created_at || ""))
    : "—";

  body.textContent = report?.report_text || "No report found.";
  modal.style.display = "block";
}

function closeReportModal(){
  const modal = document.getElementById("reportModal");
  if(modal) modal.style.display = "none";
}

// close handlers
document.getElementById("closeReportModal")?.addEventListener("click", closeReportModal);
document.getElementById("reportBackdrop")?.addEventListener("click", closeReportModal);
document.addEventListener("keydown", (e) => {
  if(e.key === "Escape") closeReportModal();
});

// copy + download
document.getElementById("copyReportBtn")?.addEventListener("click", async () => {
  if(!LAST_REPORT?.report_text) return;
  try{
    await navigator.clipboard.writeText(LAST_REPORT.report_text);
    alert("Copied ✅");
  }catch(e){
    alert("Copy failed");
  }
});

document.getElementById("downloadReportBtn")?.addEventListener("click", () => {
  if(!LAST_REPORT?.report_text) return;
  const filename = "constrava_report_" + (LAST_REPORT.report_date || "latest") + ".txt";
  const blob = new Blob([LAST_REPORT.report_text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

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
    font-weight:900;
  }
  .btn:hover{border-color: rgba(96,165,250,.5)}
  .btnGreen{background: rgba(52,211,153,.14);}
  .btnGreen:hover{border-color: rgba(52,211,153,.5)}
  select{
    border-radius:12px;
    border:1px solid var(--border);
    background: rgba(15,23,42,.6);
    color: var(--text);
    padding:10px 12px;
    font-weight:900;
    outline:none;
  }
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
  @media (max-width: 1000px){
    .span8,.span6,.span4{grid-column: 1 / -1;}
    .topbar{flex-direction:column; align-items:flex-start;}
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
    font-weight:950;
    display:flex; align-items:center; justify-content:space-between;
    gap:10px;
  }
  .kpi{font-size:28px; font-weight:1000; letter-spacing:.2px; margin-top:8px;}
  .muted{color:var(--muted); font-size:12px; line-height:1.45;}
  .row{display:flex; gap:12px; align-items:center; justify-content:space-between; flex-wrap:wrap;}
  .mini{
    background: rgba(15,23,42,.55);
    border:1px solid var(--border);
    border-radius: 14px;
    padding:12px;
    flex:1;
    min-width: 160px;
  }
  .mini .label{font-size:12px; color:var(--muted); font-weight:900;}
  .mini .value{font-size:14px; font-weight:1000; margin-top:4px;}
  .chartBox{
    background: rgba(15,23,42,.55);
    border:1px solid var(--border);
    border-radius: 14px;
    padding:12px;
  }
  svg{width:100%; height:140px; display:block;}
  .bar svg{height:170px;}
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
    min-height: 200px;
  }
  .listItem{
    padding:10px 10px;
    border-radius: 12px;
    border:1px solid var(--border);
    background: rgba(15,23,42,.55);
    margin-top:10px;
  }
  .linkBtn{
    padding:10px 14px;
    border-radius:12px;
    border:1px solid var(--border);
    background: rgba(15,23,42,.55);
    color: var(--text);
    cursor:pointer;
    font-weight:900;
    text-decoration:none;
    display:inline-flex;
    align-items:center;
    gap:8px;
  }
  .linkBtn:hover{border-color: rgba(255,255,255,.18)}
  .err{color: var(--danger); font-weight:950}
  .ok{color: var(--accent2); font-weight:950}
</style>
</head>

<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>Constrava Dashboard</h1>
        <div class="sub">Plan: <b>${plan}</b> • Site: <b>${site_id}</b></div>
      </div>
    </div>

    <div class="controls">
      <select id="rangeSel" title="Time range">
        <option value="1">1 day</option>
        <option value="7" selected>1 week</option>
        <option value="30">1 month</option>
        <option value="365">1 year</option>
        <option value="730">2 years</option>
        <option value="1825">5 years</option>
      </select>

      <button class="btn" id="refreshBtn">Refresh</button>
      <a class="linkBtn" href="/storefront?token=${encodeURIComponent(token)}">Plans</a>

      <button class="btn btnGreen" id="aiBtn" style="display:none;">Generate AI report</button>
      <button class="btn btnGreen" id="aiPlanBtn" style="display:none;">AI action plan</button>
    </div>
  </div>

  <!-- ✅ Demo panel -->
  <div class="grid">
    <div class="card span12">
      <h2>Demo Controls <span class="pill">Play with it</span></h2>

      <div class="row" style="gap:10px;">
        <button class="btn" id="btnSimView">Simulate Page View</button>
        <button class="btn" id="btnSimLead">Simulate Lead</button>
        <button class="btn" id="btnSimPurchase">Simulate Purchase</button>
        <button class="btn" id="btnSimCta">Simulate CTA Click</button>

        <button class="btn" id="btnShare">Copy Share Link</button>

        <label class="pill" style="display:flex; align-items:center; gap:8px;">
          <input type="checkbox" id="liveToggle" />
          Live traffic
        </label>
      </div>

      <div class="muted" id="demoStatus" style="margin-top:10px;">Tip: turn on Live traffic and click Simulate Lead.</div>
    </div>

    <div class="card span4">
      <h2>Visits today</h2>
      <div class="kpi" id="kpiToday">—</div>
      <div class="muted">Real-time from your installed tracker.</div>
    </div>

    <div class="card span4">
      <h2>Visits in range</h2>
      <div class="kpi" id="kpiRange">—</div>
      <div class="muted">Total page views in selected range.</div>
    </div>

    <div class="card span4">
      <h2>Conversions</h2>
      <div class="row">
        <div class="mini">
          <div class="label">Leads</div>
          <div class="value" id="leadsKpi">—</div>
        </div>
        <div class="mini">
          <div class="label">Purchases</div>
          <div class="value" id="purchasesKpi">—</div>
        </div>
        <div class="mini">
          <div class="label">Lead rate</div>
          <div class="value" id="leadRateKpi">—</div>
        </div>
      </div>
      <div class="muted" style="margin-top:10px;">Uses demo “lead/purchase” events.</div>
    </div>

    <div class="card span8">
      <h2>Trend</h2>
      <div class="chartBox">
        <svg id="spark" viewBox="0 0 600 140" preserveAspectRatio="none"></svg>
      </div>
      <div class="muted" id="trendHint" style="margin-top:10px">—</div>
    </div>

    <div class="card span4 bar">
      <h2>Top pages</h2>
      <div class="chartBox">
        <svg id="bars" viewBox="0 0 600 170" preserveAspectRatio="none"></svg>
      </div>
      <div class="muted">Top 5 paths in range.</div>
    </div>

    <div class="card span6">
      <h2>Latest report</h2>
      <div class="latest" id="latestReport">Loading…</div>
      <div class="muted" id="reportMeta" style="margin-top:10px">—</div>
    </div>

    <div class="card span6">
      <h2>Report history</h2>
      <div id="history">Loading…</div>
      <div class="muted" style="margin-top:10px">
        Tip: Seed demo data with <span class="pill">POST /demo/seed?token=YOUR_TOKEN</span>
      </div>
    </div>
  </div>
</div>

<script>
  const TOKEN = ${JSON.stringify(String(token || ""))};
  const PLAN  = ${JSON.stringify(String(plan || ""))};

  const rangeSel = document.getElementById("rangeSel");
  const refreshBtn = document.getElementById("refreshBtn");
  const aiBtn = document.getElementById("aiBtn");
  const aiPlanBtn = document.getElementById("aiPlanBtn");

  const demoStatus = document.getElementById("demoStatus");
  function setDemoStatus(t){ if(demoStatus) demoStatus.textContent = t; }

  function el(id){ return document.getElementById(id); }
  function pct(n){ return (Math.round(n*100)/100).toFixed(0) + "%"; }
  function rate(n){ return (Math.round(n*10000)/100).toFixed(2) + "%"; } // 0.1234 -> 12.34%

  if (PLAN === "full_ai") {
    aiBtn.style.display = "inline-block";
    aiPlanBtn.style.display = "inline-block";
  }

  function svgClear(svg){ while(svg.firstChild) svg.removeChild(svg.firstChild); }

  function drawSpark(svg, series){
    svgClear(svg);
    const W=600,H=140,p=12;
    const max = Math.max(1, ...series.map(s => Number(s.visits||0)));
    const min = 0;

    const g = document.createElementNS("http://www.w3.org/2000/svg","path");
    g.setAttribute("d", \`M \${p} \${H-p} L \${W-p} \${H-p}\`);
    g.setAttribute("stroke","rgba(255,255,255,.10)");
    g.setAttribute("fill","none");
    svg.appendChild(g);

    const step = (W - 2*p) / Math.max(1, series.length - 1);
    let d = "";
    series.forEach((s,i)=>{
      const x = p + i*step;
      const y = (H-p) - ((Number(s.visits||0) - min) / (max-min || 1)) * (H-2*p);
      d += (i===0 ? "M":"L") + x.toFixed(2) + " " + y.toFixed(2) + " ";
    });

    const path = document.createElementNS("http://www.w3.org/2000/svg","path");
    path.setAttribute("d", d.trim());
    path.setAttribute("stroke","rgba(96,165,250,.95)");
    path.setAttribute("stroke-width","3");
    path.setAttribute("fill","none");
    path.setAttribute("stroke-linecap","round");
    path.setAttribute("stroke-linejoin","round");
    svg.appendChild(path);

    series.forEach((s,i)=>{
      const x = p + i*step;
      const y = (H-p) - ((Number(s.visits||0) - min) / (max-min || 1)) * (H-2*p);
      const c = document.createElementNS("http://www.w3.org/2000/svg","circle");
      c.setAttribute("cx", x);
      c.setAttribute("cy", y);
      c.setAttribute("r", 4);
      c.setAttribute("fill", "rgba(52,211,153,.95)");
      c.setAttribute("opacity", "0.9");
      svg.appendChild(c);
    });
  }

  function drawBars(svg, items){
    svgClear(svg);
    const W=600,H=170,p=14;
    const max = Math.max(1, ...items.map(i => Number(i.views||0)));
    const barW = (W - 2*p) / Math.max(1, items.length);

    items.forEach((it, idx)=>{
      const v = Number(it.views||0);
      const h = ((v / max) * (H - 2*p));
      const x = p + idx * barW + 6;
      const y = (H - p) - h;

      const r = document.createElementNS("http://www.w3.org/2000/svg","rect");
      r.setAttribute("x", x);
      r.setAttribute("y", y);
      r.setAttribute("width", Math.max(8, barW - 12));
      r.setAttribute("height", h);
      r.setAttribute("rx", 8);
      r.setAttribute("fill", "rgba(96,165,250,.45)");
      r.setAttribute("stroke", "rgba(96,165,250,.9)");
      r.setAttribute("stroke-width", "1");
      svg.appendChild(r);

      const t = document.createElementNS("http://www.w3.org/2000/svg","text");
      t.setAttribute("x", x);
      t.setAttribute("y", H - 4);
      t.setAttribute("fill", "rgba(229,231,235,.85)");
      t.setAttribute("font-size", "11");
      t.textContent = (it.page_type || "").slice(0, 10) || "/";
      svg.appendChild(t);
    });
  }

  async function loadReports(){
    try{
      const r = await fetch("/reports/latest?token=" + encodeURIComponent(TOKEN));
      const j = await r.json();
      if(!j.ok){ el("latestReport").textContent = j.error || "No report"; return; }
      el("latestReport").textContent = j.report.report_text || "";
      LAST_REPORT = j.report;
      el("reportMeta").textContent = "Latest: " + j.report.report_date + " • " + (j.report.created_at || "");
    }catch(e){
      el("latestReport").textContent = "Error loading report";
    }
document.getElementById("latestReport")?.addEventListener("click", () => {
  if(LAST_REPORT) openReportModal(LAST_REPORT);
});

    try{
      const r2 = await fetch("/reports?token=" + encodeURIComponent(TOKEN) + "&limit=10");
      const j2 = await r2.json();
      if(!j2.ok){ el("history").innerHTML = "<div class='err'>"+(j2.error||"Error")+"</div>"; return; }
      if(!j2.reports || !j2.reports.length){ el("history").innerHTML = "<div class='muted'>No reports yet.</div>"; return; }
      el("history").innerHTML = j2.reports.map(x => (
        "<div class='listItem'>" +
          "<div style='font-weight:950;font-size:12px;'>"+ x.report_date +"</div>" +
          "<div style='margin-top:6px;font-size:13px;opacity:.95;white-space:pre-wrap;'>"+ (x.preview || "") +"</div>" +
        "</div>"
      )).join("");
    }catch(e){
      el("history").innerHTML = "<div class='err'>Error loading history</div>";
    }
  }

  async function refresh(){
    const days = rangeSel.value;

    el("kpiToday").textContent = "—";
    el("kpiRange").textContent = "—";
    el("leadsKpi").textContent = "—";
    el("purchasesKpi").textContent = "—";
    el("leadRateKpi").textContent = "—";
    el("trendHint").textContent = "Loading…";

    const r = await fetch("/metrics?token=" + encodeURIComponent(TOKEN) + "&days=" + encodeURIComponent(days));
    const j = await r.json();

    if(!j.ok){
      el("trendHint").innerHTML = "<span class='err'>" + (j.error || "Error") + "</span>";
      return;
    }

    el("kpiToday").textContent = j.visits_today;
    el("kpiRange").textContent = j.visits_range;

    el("leadsKpi").textContent = j.leads ?? 0;
    el("purchasesKpi").textContent = j.purchases ?? 0;
    el("leadRateKpi").textContent = rate(j.conversion_rate || 0);

    const trend = j.trend || [];
    drawSpark(el("spark"), trend);

    const last = trend.length ? trend[trend.length-1].visits : 0;
    const prev = trend.length > 1 ? trend[trend.length-2].visits : last;
    const diff = last - prev;
    const sign = diff === 0 ? "flat" : (diff > 0 ? "up" : "down");
    el("trendHint").textContent = "Last day: " + last + " • Change vs previous day: " + diff + " (" + sign + ")";

    drawBars(el("bars"), j.top_pages || []);
    await loadReports();
    if (LAST_REPORT) openReportModal(LAST_REPORT);
  }

  refreshBtn.addEventListener("click", refresh);
  rangeSel.addEventListener("change", refresh);

  aiBtn.addEventListener("click", async () => {
    aiBtn.disabled = true;
    aiBtn.textContent = "Generating…";
    try{
      const r = await fetch("/generate-report?token=" + encodeURIComponent(TOKEN), { method: "POST" });
      const j = await r.json();
      if(!j.ok){
        alert(j.error || "AI report failed");
      } else {
        await loadReports();
      }
    }catch(e){
      alert("AI error");
    } finally {
      aiBtn.disabled = false;
      aiBtn.textContent = "Generate AI report";
    }
  });

  aiPlanBtn.addEventListener("click", async () => {
    aiPlanBtn.disabled = true;
    aiPlanBtn.textContent = "Planning…";
    try{
      const r = await fetch("/generate-action-plan?token=" + encodeURIComponent(TOKEN), { method: "POST" });
      const j = await r.json();
      if(!j.ok){
        alert(j.error || "AI action plan failed");
      } else {
        await loadReports();
      }
    }catch(e){
      alert("AI error");
    } finally {
      aiPlanBtn.disabled = false;
      aiPlanBtn.textContent = "AI action plan";
    }
  });

  // Demo buttons
  async function fire(eventName){
    setDemoStatus("Sending " + eventName + "…");
    const r = await fetch("/demo/fire-event", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ token: TOKEN, event_name: eventName, page_type: location.pathname, device: "desktop" })
    });
    const d = await r.json();
    if(!d.ok){ setDemoStatus("Error: " + (d.error || "unknown")); return; }
    setDemoStatus("✅ Fired " + eventName + ". Refreshing…");
    setTimeout(() => { refresh(); }, 450);
  }

  document.getElementById("btnSimView")?.addEventListener("click", () => fire("page_view"));
  document.getElementById("btnSimLead")?.addEventListener("click", () => fire("lead"));
  document.getElementById("btnSimPurchase")?.addEventListener("click", () => fire("purchase"));
  document.getElementById("btnSimCta")?.addEventListener("click", () => fire("cta_click"));

  document.getElementById("btnShare")?.addEventListener("click", async () => {
    setDemoStatus("Creating share link…");
    const r = await fetch("/demo/link", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ token: TOKEN })
    });
    const d = await r.json();
    if(!d.ok){ setDemoStatus("Error: " + (d.error || "unknown")); return; }
    try{
      await navigator.clipboard.writeText(d.url);
      setDemoStatus("✅ Copied: " + d.url);
    }catch(e){
      setDemoStatus("Share link: " + d.url);
    }
  });

  // Live traffic toggle
  let liveTimer = null;
  let liveSince = new Date().toISOString();

  async function liveTick(){
    try{
      const r = await fetch("/live?token=" + encodeURIComponent(TOKEN) + "&since=" + encodeURIComponent(liveSince));
      const d = await r.json();
      if(d.ok){
        liveSince = d.now || new Date().toISOString();
        if(d.new_page_views > 0){
          setDemoStatus("📈 Live: +" + d.new_page_views + " new views. Refreshing…");
          setTimeout(()=> refresh(), 450);
        } else {
          setDemoStatus("Live traffic: listening…");
        }
      }
    }catch(e){
      setDemoStatus("Live traffic: error");
    }
  }

  document.getElementById("liveToggle")?.addEventListener("change", (e) => {
    if(e.target.checked){
      setDemoStatus("Live traffic: ON");
      liveSince = new Date().toISOString();
      liveTimer = setInterval(liveTick, 2500);
    } else {
      setDemoStatus("Live traffic: OFF");
      if(liveTimer) clearInterval(liveTimer);
      liveTimer = null;
    }
  });

  refresh();
</script>
</body>
</html>`);
  })
);

/* ---------------------------
   “Daily job” utilities
----------------------------*/
async function generateNonAiDailyReport(site_id) {
  const metricsRes = await pool.query(
    `
    SELECT
      COUNT(*)::int AS total_events,
      SUM(CASE WHEN event_name='page_view' THEN 1 ELSE 0 END)::int AS page_views,
      SUM(CASE WHEN event_name='lead' THEN 1 ELSE 0 END)::int AS leads,
      SUM(CASE WHEN event_name='purchase' THEN 1 ELSE 0 END)::int AS purchases
    FROM events_raw
    WHERE site_id=$1 AND created_at >= NOW() - INTERVAL '1 day'
    `,
    [site_id]
  );

  const m = metricsRes.rows[0] || { total_events: 0, page_views: 0, leads: 0, purchases: 0 };

  const topRes = await pool.query(
    `
    SELECT page_type, COUNT(*)::int AS views
    FROM events_raw
    WHERE site_id=$1 AND event_name='page_view' AND created_at >= NOW() - INTERVAL '7 days'
    GROUP BY page_type
    ORDER BY views DESC
    LIMIT 3
    `,
    [site_id]
  );

  const lines = [];
  lines.push("Summary:");
  lines.push(`In the last 24 hours you recorded ${m.page_views || 0} page views.`);
  lines.push(`Leads: ${m.leads || 0} • Purchases: ${m.purchases || 0}`);
  lines.push("");
  lines.push("Top pages (7d):");
  if (!topRes.rows.length) lines.push("- (no data yet)");
  for (const r of topRes.rows) lines.push(`- ${r.page_type || "/"}: ${r.views}`);
  lines.push("");
  lines.push("Next steps:");
  lines.push("1) Put your strongest CTA on the top page");
  lines.push("2) Add a lead capture (form / booking / email)");
  lines.push("3) Track a conversion event next");
  lines.push("");
  lines.push("Metric to watch:");
  lines.push("Lead rate (leads / visits)");

  return lines.join("\n");
}

async function runDailyForAllSites() {
  const sites = await pool.query(`SELECT site_id, plan FROM sites`);
  let made = 0;

  for (const s of sites.rows) {
    const plan = s.plan || "unpaid";
    if (plan !== "pro" && plan !== "full_ai") continue;

    const txt = await generateNonAiDailyReport(s.site_id);

    await pool.query(
      `INSERT INTO daily_reports (site_id, report_date, report_text)
       VALUES ($1, CURRENT_DATE, $2)
       ON CONFLICT (site_id, report_date)
       DO UPDATE SET report_text = EXCLUDED.report_text`,
      [s.site_id, txt]
    );
    made++;
  }

  return { ok: true, updated_sites: made };
}

// Manual trigger (admin-ish). You can protect this later with a secret.
app.post(
  "/jobs/run-daily",
  asyncHandler(async (req, res) => {
    const result = await runDailyForAllSites();
    res.json(result);
  })
);

// Optional scheduler (in-process; not reliable like real cron)
if (process.env.ENABLE_SCHEDULER === "true") {
  console.log("⏱️ In-process scheduler enabled (not a real cron).");

  runDailyForAllSites().catch(() => {});

  setInterval(() => {
    runDailyForAllSites().catch(() => {});
  }, 6 * 60 * 60 * 1000);
}

/* ---------------------------
   PUBLIC Storefront (NO token)
   GET /store
----------------------------*/
app.get("/store", (req, res) => {
  try {
    setNoStore(res);
    res.setHeader("Content-Type", "text/html");

    const base = publicBaseUrl(req);

    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Constrava — Store</title>
  <style>
    :root{
      --bg:#0b0f19;
      --panel: rgba(255,255,255,.06);
      --panel2: rgba(15,23,42,.60);
      --text:#e5e7eb;
      --muted:#9ca3af;
      --border:rgba(255,255,255,.12);
      --accent:#60a5fa;
      --accent2:#34d399;
      --danger:#fb7185;
      --shadow: 0 14px 40px rgba(0,0,0,.35);
      --radius:18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background:
        radial-gradient(1100px 720px at 20% -10%, rgba(96,165,250,.25), transparent 60%),
        radial-gradient(900px 620px at 90% 0%, rgba(52,211,153,.18), transparent 55%),
        var(--bg);
      color:var(--text);
    }
    .wrap{max-width:1100px;margin:0 auto;padding:28px 18px 70px;}
    .top{
      display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
      padding:18px 18px;
      border:1px solid var(--border);
      background: linear-gradient(180deg, rgba(255,255,255,.07), rgba(255,255,255,.02));
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    .brand{display:flex;align-items:center;gap:12px;}
    .logo{
      width:44px;height:44px;border-radius:14px;
      background: linear-gradient(135deg, rgba(96,165,250,.95), rgba(52,211,153,.88));
      box-shadow: 0 12px 26px rgba(96,165,250,.22);
    }
    h1{margin:0;font-size:18px;}
    .sub{margin-top:3px;font-size:12px;color:var(--muted);}
    .pill{
      font-size:12px;color:var(--muted);
      border:1px solid var(--border);
      padding:7px 10px;border-radius:999px;
      background: rgba(15,23,42,.55);
      white-space:nowrap;
    }
    .hero{margin-top:18px;display:grid;grid-template-columns: 1.2fr .8fr;gap:16px;}
    @media (max-width: 980px){ .hero{grid-template-columns:1fr;} }
    .card{
      border:1px solid var(--border);
      border-radius: var(--radius);
      background: var(--panel);
      box-shadow: var(--shadow);
      padding:16px;
    }
    .heroTitle{font-size:30px;font-weight:1000;letter-spacing:.2px;margin:0;}
    .heroText{margin-top:10px;color:var(--muted);line-height:1.55;max-width:70ch;}
    .grid{margin-top:16px;display:grid;grid-template-columns:repeat(12,1fr);gap:16px;}
    .span8{grid-column: span 8;}
    .span4{grid-column: span 4;}
    @media (max-width: 980px){ .span8,.span4{grid-column: 1 / -1;} }
    label{display:block;font-size:12px;color:var(--muted);font-weight:900;margin:10px 0 6px;}
    input{
      width:100%;
      border-radius:14px;
      border:1px solid var(--border);
      background: rgba(15,23,42,.60);
      color: var(--text);
      padding:12px 12px;
      outline:none;
      font-weight:800;
    }
    input:focus{border-color: rgba(96,165,250,.55)}
    .row{display:flex;gap:12px;flex-wrap:wrap;}
    .row > div{flex:1; min-width: 240px;}
    .btn{
      width:100%;
      margin-top:14px;
      padding:12px 14px;
      border-radius: 14px;
      border:1px solid var(--border);
      background: rgba(96,165,250,.16);
      color: var(--text);
      font-weight:1000;
      cursor:pointer;
    }
    .btn:hover{border-color: rgba(96,165,250,.65)}
    .muted{color:var(--muted);font-size:12px;line-height:1.55;}
    .plan{
      border:1px solid var(--border);
      border-radius: var(--radius);
      background: rgba(15,23,42,.35);
      padding:14px;
    }
    .plan h3{margin:0;font-size:14px;font-weight:1000;}
    .price{margin-top:8px;font-size:26px;font-weight:1000;}
    ul{margin:10px 0 0 0;padding:0 0 0 18px;line-height:1.6;}
    .note{
      margin-top:12px;
      border:1px dashed rgba(255,255,255,.18);
      border-radius: var(--radius);
      padding:12px;
      background: rgba(15,23,42,.30);
      color: var(--muted);
      font-size:12px;
      line-height:1.55;
    }
    .out{
      margin-top:12px;
      border:1px solid var(--border);
      border-radius: var(--radius);
      background: rgba(15,23,42,.55);
      padding:14px;
      display:none;
    }
    pre{
      margin:10px 0 0 0;
      white-space:pre-wrap;
      word-break:break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
      font-size:12px;
      color: var(--text);
    }
    .ok{color: var(--accent2); font-weight:1000}
    .err{color: var(--danger); font-weight:1000}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava</h1>
          <div class="sub">Tracking + plain-English insights for small business sites</div>
        </div>
      </div>
      <div class="pill">Backend: <b>${base}</b></div>
    </div>

    <div class="hero">
      <div class="card">
        <h2 class="heroTitle">Create your site in 60 seconds</h2>
        <div class="heroText">
          This page is public. Anyone can create a site and instantly get:
          <b>dashboard link</b>, <b>access token</b>, and <b>tracking snippet</b>.
        </div>

        <div class="note">
          <b>Security note:</b> Your access token is basically your password. If you choose your own token,
          make it strong and don’t share it.
        </div>
      </div>

      <div class="card">
        <div class="plan">
          <h3>Starter</h3>
          <div class="price">$29 <span class="muted">/mo</span></div>
          <ul>
            <li>Dashboard + visits</li>
            <li>Trends + top pages</li>
            <li>Conversions panel (demo)</li>
          </ul>
        </div>
        <div class="plan" style="margin-top:12px;">
          <h3>Pro</h3>
          <div class="price">$79 <span class="muted">/mo</span></div>
          <ul>
            <li>Email latest report</li>
            <li>More reporting workflow</li>
          </ul>
        </div>
        <div class="plan" style="margin-top:12px;">
          <h3>Full AI</h3>
          <div class="price">$199 <span class="muted">/mo</span></div>
          <ul>
            <li>AI “next steps” reports</li>
            <li>AI action plans</li>
          </ul>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card span8">
        <h2 style="margin:0;font-size:16px;font-weight:1000;">Create a site</h2>
        <div class="muted" style="margin-top:6px;">
          Choose your own <b>site_id</b> (your “username”). Optionally set your own token, or leave it blank to auto-generate.
        </div>

        <form id="createForm">
          <div class="row">
            <div>
              <label for="site_id">site_id (username)</label>
              <input id="site_id" name="site_id" placeholder="example: my-business" required />
              <div class="muted">Lowercase letters, numbers, hyphens. 4–24 chars.</div>
            </div>
            <div>
              <label for="site_name">site_name</label>
              <input id="site_name" name="site_name" placeholder="My Business" required />
            </div>
          </div>

          <div class="row">
            <div>
              <label for="owner_email">owner_email</label>
              <input id="owner_email" name="owner_email" placeholder="you@domain.com" required />
            </div>
            <div>
              <label for="custom_token">custom token (optional)</label>
              <input id="custom_token" name="custom_token" placeholder="Leave blank to auto-generate" />
              <div class="muted">If you set one, it must be strong (20+ chars, mixed types).</div>
            </div>
          </div>

          <button class="btn" type="submit">Create site →</button>

          <div id="msg" class="muted" style="margin-top:10px;"></div>

          <div id="out" class="out">
            <div id="outStatus" class="ok">Created ✅</div>
            <div class="muted" style="margin-top:6px;">Save these:</div>
            <pre id="outPre"></pre>
          </div>
        </form>
      </div>

      <div class="card span4">
        <h2 style="margin:0;font-size:16px;font-weight:1000;">Next steps after you create</h2>
        <div class="muted" style="margin-top:10px;line-height:1.6;">
          1) Copy the <b>tracking snippet</b> into your website.<br/>
          2) Visit the <b>dashboard link</b>.<br/>
          3) If your plan is <b>unpaid</b>, you’ll be redirected to activate.
        </div>

        <div class="note" style="margin-top:12px;">
          <b>Tip:</b> If you want demo data, call:<br/>
          <span class="pill">POST /demo/seed?token=YOUR_TOKEN</span>
        </div>
      </div>
    </div>
  </div>

<script>
  const base = ${JSON.stringify(base)};
  const form = document.getElementById("createForm");
  const msg = document.getElementById("msg");
  const out = document.getElementById("out");
  const outPre = document.getElementById("outPre");
  const outStatus = document.getElementById("outStatus");

  function setMsg(text, isErr){
    msg.innerHTML = isErr ? "<span class='err'>" + text + "</span>" : "<span class='ok'>" + text + "</span>";
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    out.style.display = "none";
    setMsg("Creating site...", false);

    const payload = {
      site_id: document.getElementById("site_id").value,
      site_name: document.getElementById("site_name").value,
      owner_email: document.getElementById("owner_email").value,
      custom_token: document.getElementById("custom_token").value || undefined
    };

    try{
      const r = await fetch(base + "/sites", {
        method: "POST",
        headers: { "Content-Type":"application/json" },
        body: JSON.stringify(payload)
      });

      const data = await r.json().catch(() => ({}));
      if(!r.ok || !data.ok){
        setMsg(data.error || ("Create failed (" + r.status + ")"), true);
        return;
      }

      setMsg("Created ✅ Scroll down for your links.", false);

      const dashboard = data.client_dashboard_url || (base + "/dashboard?token=" + encodeURIComponent(data.access_token));
      const storefront = base + "/storefront?token=" + encodeURIComponent(data.access_token);

      outStatus.textContent = "Created ✅ Save this info:";
      outPre.textContent =
        "site_id: " + data.site_id + "\\n" +
        "access_token: " + data.access_token + "\\n" +
        "dashboard_url: " + dashboard + "\\n" +
        "activation_storefront_url: " + storefront + "\\n\\n" +
        "install_snippet:\\n" + data.install_snippet;

      out.style.display = "block";
    }catch(err){
      setMsg("Network error: " + (err && err.message ? err.message : "unknown"), true);
    }
  });
</script>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(String(err.message || err));
  }
});

/* ---------------------------
   Errors
----------------------------*/
app.use((err, req, res, next) => {
  console.error("ERROR:", err && err.stack ? err.stack : err);
  res.status(500).json({ ok: false, error: String(err.message || err) });
});

/* ---------------------------
   Start server
----------------------------*/
app.listen(PORT, () => {
  console.log(`🚀 Constrava running on port ${PORT}`);
});
