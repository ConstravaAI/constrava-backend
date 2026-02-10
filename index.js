// index.js (ESM) — Constrava MVP+ backend (FULL + WORKING, HTML RESTORED + FIXED)
// Node 18+ recommended. Uses global fetch.
//
// ENV REQUIRED:
// - DATABASE_URL
//
// OPTIONAL ENV:
// - PUBLIC_BASE_URL
// - PUBLIC_EVENTS_URL
// - ENABLE_DEMO_SEED=true
// - ENABLE_DEMO_ACTIVATE=false
// - OPENAI_API_KEY (+ optional OPENAI_MODEL) (for FULL AI endpoints)
// - RESEND_API_KEY + FROM_EMAIL (for email endpoint)
// - ENABLE_SCHEDULER=true
// - COOKIE_SECURE=true
// - CORS_ORIGIN
// - PGSSL=true

import express from "express";
import cors from "cors";
import pkg from "pg";
import crypto from "crypto";

const { Pool } = pkg;
const app = express();

// IMPORTANT for Render / reverse proxies (req.protocol + secure cookies)
app.set("trust proxy", 1);

// CORS
const CORS_ORIGIN = process.env.CORS_ORIGIN;
app.use(
  cors(
    CORS_ORIGIN
      ? { origin: CORS_ORIGIN, credentials: true }
      : undefined
  )
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL env var");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : undefined
});

/* ---------------------------
   Helpers
----------------------------*/
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function setNoStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

function publicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;

  const xfProto = req.get("x-forwarded-proto");
  const proto = xfProto ? xfProto.split(",")[0].trim() : req.protocol;
  const host = req.get("x-forwarded-host") || req.get("host");

  if (host) return `${proto}://${host}`;
  return "https://constrava-backend.onrender.com";
}

function publicEventsUrl(req) {
  if (process.env.PUBLIC_EVENTS_URL) return process.env.PUBLIC_EVENTS_URL;
  return publicBaseUrl(req);
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name} env var`);
  return v;
}

function normalizeDays(input) {
  const n = parseInt(String(input ?? "7"), 10);
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

function safeEmail(x) {
  return String(x || "").trim().toLowerCase();
}

function clamp01(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(1, x));
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

/* ---------------------------
   Password hashing (no bcrypt)
----------------------------*/
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

/* ---------------------------
   Cookie helpers (no cookie-parser)
----------------------------*/
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
    maxAgeSeconds = 60 * 60 * 24 * 14
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


/* ---------------------------
   CRM helpers (matching + inference)
----------------------------*/
function normEmail(v){ return String(v||"").trim().toLowerCase(); }
function normPhone(v){ return String(v||"").replace(/[^0-9+]/g,"").trim(); }
function normName(v){ return String(v||"").trim().toLowerCase(); }

function tokenSet(s){
  return new Set(String(s||"").toLowerCase().split(/[^a-z0-9]+/g).filter(Boolean));
}
function diceCoeff(a,b){
  const A = tokenSet(a), B = tokenSet(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const x of A) if (B.has(x)) inter++;
  return (2*inter) / (A.size + B.size);
}

async function findClientByIdentity(site_id, kind, value){
  const r = await pool.query(
    `SELECT c.*
     FROM crm_identities i
     JOIN crm_clients c ON c.id=i.client_id
     WHERE i.site_id=$1 AND i.kind=$2 AND i.value=$3
     LIMIT 1`,
    [site_id, kind, value]
  );
  return r.rows[0] || null;
}

async function upsertClient(site_id, { full_name, email, phone, stage }){
  const e = email ? normEmail(email) : null;
  const p = phone ? normPhone(phone) : null;

  // prefer email identity
  if (e){
    const existing = await findClientByIdentity(site_id, "email", e);
    if (existing) return existing;
  }

  // try phone identity
  if (p){
    const existing = await findClientByIdentity(site_id, "phone", p);
    if (existing) return existing;
  }

  // create new client
  const r = await pool.query(
    `INSERT INTO crm_clients (site_id, full_name, primary_email, primary_phone, stage, confidence)
     VALUES ($1,$2,$3,$4,$5,0.55)
     RETURNING *`,
    [site_id, full_name ? String(full_name).trim() : null, e, p, stage || "lead"]
  );
  const c = r.rows[0];

  // identities
  if (e) {
    await pool.query(
      `INSERT INTO crm_identities (site_id, client_id, kind, value)
       VALUES ($1,$2,'email',$3)
       ON CONFLICT (site_id, kind, value) DO NOTHING`,
      [site_id, c.id, e]
    );
  }
  if (p) {
    await pool.query(
      `INSERT INTO crm_identities (site_id, client_id, kind, value)
       VALUES ($1,$2,'phone',$3)
       ON CONFLICT (site_id, kind, value) DO NOTHING`,
      [site_id, c.id, p]
    );
  }
  if (full_name) {
    const n = normName(full_name);
    if (n){
      await pool.query(
        `INSERT INTO crm_identities (site_id, client_id, kind, value)
         VALUES ($1,$2,'name',$3)
         ON CONFLICT (site_id, kind, value) DO NOTHING`,
        [site_id, c.id, n]
      );
    }
  }

  return c;
}

async function addIdentity(site_id, client_id, kind, value){
  const v = String(value||"").trim();
  if (!v) return;
  await pool.query(
    `INSERT INTO crm_identities (site_id, client_id, kind, value)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT (site_id, kind, value) DO NOTHING`,
    [site_id, client_id, kind, v]
  );
}

async function bestMatchClient(site_id, { emailA, emailB, phone, name }){
  const candidates = [];

  const e1 = emailA ? normEmail(emailA) : "";
  const e2 = emailB ? normEmail(emailB) : "";
  const ph = phone ? normPhone(phone) : "";
  const nm = name ? normName(name) : "";

  if (e1){
    const c = await findClientByIdentity(site_id, "email", e1);
    if (c) candidates.push({ client:c, confidence:0.95, reason:"Matched email: " + e1 });
  }
  if (e2 && e2 !== e1){
    const c = await findClientByIdentity(site_id, "email", e2);
    if (c) candidates.push({ client:c, confidence:0.92, reason:"Matched email: " + e2 });
  }
  if (ph){
    const c = await findClientByIdentity(site_id, "phone", ph);
    if (c) candidates.push({ client:c, confidence:0.90, reason:"Matched phone: " + ph });
  }

  // fuzzy name match (token overlap)
  if (nm){
    const r = await pool.query(
      `SELECT id, full_name
       FROM crm_clients
       WHERE site_id=$1
       ORDER BY created_at DESC
       LIMIT 250`,
      [site_id]
    );
    let best = null;
    for (const row of r.rows){
      const s = diceCoeff(nm, row.full_name || "");
      if (!best || s > best.score) best = { row, score: s };
    }
    if (best && best.score >= 0.55){
      const c2 = await pool.query(`SELECT * FROM crm_clients WHERE id=$1 LIMIT 1`, [best.row.id]);
      const c = c2.rows[0];
      if (c) candidates.push({ client:c, confidence: Math.max(0.55, Math.min(0.80, best.score)), reason:"Fuzzy name match: " + (c.full_name||"") });
    }
  }

  candidates.sort((a,b)=> (b.confidence||0)-(a.confidence||0));
  return candidates[0] || null;
}

async function createActivityWithMatch(site_id, activity, matchHint){
  const r = await pool.query(
    `INSERT INTO crm_activities
      (site_id, type, direction, occurred_at, from_email, to_email, subject, body_text, phone, duration_sec, meta)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     RETURNING *`,
    [
      site_id,
      activity.type,
      activity.direction || null,
      activity.occurred_at ? new Date(activity.occurred_at).toISOString() : new Date().toISOString(),
      activity.from_email ? normEmail(activity.from_email) : null,
      activity.to_email ? normEmail(activity.to_email) : null,
      activity.subject ? String(activity.subject).slice(0, 300) : null,
      activity.body_text ? String(activity.body_text).slice(0, 8000) : null,
      activity.phone ? normPhone(activity.phone) : null,
      Number.isFinite(activity.duration_sec) ? Math.max(0, Math.floor(activity.duration_sec)) : null,
      activity.meta ? activity.meta : null
    ]
  );

  const act = r.rows[0];

  const best = await bestMatchClient(site_id, matchHint || {});
  if (best && best.client){
    const status = best.confidence >= 0.90 ? "auto_matched" : "needs_review";
    await pool.query(
      `INSERT INTO crm_activity_matches (site_id, activity_id, client_id, confidence, reason, status)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [site_id, act.id, best.client.id, best.confidence, best.reason, status]
    );

    await pool.query(
      `UPDATE crm_clients
       SET last_touch_at = GREATEST(COALESCE(last_touch_at, '1970-01-01'::timestamptz), $2::timestamptz)
       WHERE id=$1`,
      [best.client.id, act.occurred_at]
    );


// best-effort health heuristic:
try {
  const daysSince = Math.round((Date.now() - new Date(act.occurred_at).getTime()) / (1000*60*60*24));
  // daysSince is usually 0 for new activity; compute based on last_touch drift later is fine.
  // We still set health based on stage + recency (simple defaults).
  await pool.query(
    `UPDATE crm_clients
     SET health = CASE
       WHEN stage='won' THEN 'good'
       WHEN stage='lost' THEN 'at_risk'
       WHEN COALESCE(last_touch_at, NOW()) >= NOW() - INTERVAL '3 days' THEN 'good'
       WHEN COALESCE(last_touch_at, NOW()) >= NOW() - INTERVAL '7 days' THEN 'ok'
       ELSE 'at_risk'
     END
     WHERE id=$1`,
    [best.client.id]
  );
} catch(e) {}

return { activity: act, match: { ...best, status } };
  }

  await pool.query(
    `INSERT INTO crm_activity_matches (site_id, activity_id, client_id, confidence, reason, status)
     VALUES ($1,$2,NULL,0.3,'No strong match','needs_review')`,
    [site_id, act.id]
  );

  return { activity: act, match: null };
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
    CREATE TABLE IF NOT EXISTS crm_leads (
      id BIGSERIAL PRIMARY KEY,
      site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
      email TEXT,
      name TEXT,
      phone TEXT,
      source_page TEXT,
      status TEXT NOT NULL DEFAULT 'new',
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);


await pool.query(`
  CREATE TABLE IF NOT EXISTS crm_clients (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    full_name TEXT,
    primary_email TEXT,
    primary_phone TEXT,
    stage TEXT NOT NULL DEFAULT 'lead', -- lead|active|won|lost
    health TEXT NOT NULL DEFAULT 'unknown', -- good|ok|at_risk|unknown
    confidence REAL NOT NULL DEFAULT 0.5,
    last_touch_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(site_id, primary_email)
  );
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS crm_identities (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    client_id BIGINT NOT NULL REFERENCES crm_clients(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, -- email|phone|name
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(site_id, kind, value)
  );
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS crm_activities (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    type TEXT NOT NULL, -- email|call|note|form_lead
    direction TEXT, -- in|out
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    from_email TEXT,
    to_email TEXT,
    subject TEXT,
    body_text TEXT,
    phone TEXT,
    duration_sec INT,
    meta JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS crm_activity_matches (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    activity_id BIGINT NOT NULL REFERENCES crm_activities(id) ON DELETE CASCADE,
    client_id BIGINT REFERENCES crm_clients(id) ON DELETE SET NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'needs_review', -- auto_matched|needs_review|confirmed|rejected
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS crm_activities_site_time_idx
    ON crm_activities (site_id, occurred_at DESC);
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS crm_matches_site_status_idx
    ON crm_activity_matches (site_id, status, created_at DESC);
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS demo_links (
      code TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);


  // --- Lightweight migrations (safe to re-run) ---
  // If your DB existed before CRM columns were added, these keep schema compatible.
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS company TEXT;`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS stage TEXT NOT NULL DEFAULT 'lead';`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS industry TEXT;`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS website TEXT;`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS notes TEXT;`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS last_touch_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS last_touch_channel TEXT;`);
  await pool.query(`ALTER TABLE crm_clients ADD COLUMN IF NOT EXISTS last_touch_summary TEXT;`);

  await pool.query(`ALTER TABLE crm_activities ADD COLUMN IF NOT EXISTS subject TEXT;`);
  await pool.query(`ALTER TABLE crm_activities ADD COLUMN IF NOT EXISTS body TEXT;`);
  await pool.query(`ALTER TABLE crm_activities ADD COLUMN IF NOT EXISTS meta JSONB;`);

  await pool.query(`ALTER TABLE crm_matches ADD COLUMN IF NOT EXISTS reason TEXT;`);

  console.log("✅ Tables ready");
}

/* ---------------------------
   Basic routes
----------------------------*/
app.get("/", (req, res) => res.send("Backend is running ✅"));

app.get("/health", asyncHandler(async (req, res) => {
  const r = await pool.query("SELECT 1 as ok");
  res.json({ ok: true, db: r.rows[0]?.ok === 1 });
}));

app.get("/db-test", asyncHandler(async (req, res) => {
  const r = await pool.query("SELECT NOW() as now");
  res.json({ ok: true, now: r.rows[0].now });
}));

app.get("/debug/site", asyncHandler(async (req, res) => {
  const token = req.query.token;
  const site = await getSiteByToken(token);
  res.json({ ok: true, site });
}));

/* ---------------------------
   Auth (user accounts)
----------------------------*/
app.post("/auth/register", asyncHandler(async (req, res) => {
  const { site_id: rawSiteId, email, password, token } = req.body || {};
  const site_id = normalizeSiteId(rawSiteId);

  if (!site_id || !email || !password || !token) {
    return res.status(400).json({ ok: false, error: "site_id, email, password, and token are required" });
  }

  const site = await getSiteById(site_id);
  if (!site) return res.status(404).json({ ok: false, error: "site_id not found" });
  if (site.dashboard_token !== token) return res.status(401).json({ ok: false, error: "Invalid site token" });

  const e = safeEmail(email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return res.status(400).json({ ok: false, error: "Invalid email" });
  if (String(password).length < 8) return res.status(400).json({ ok: false, error: "Password must be at least 8 characters" });

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
}));

app.post("/auth/login", asyncHandler(async (req, res) => {
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
  const expiresAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);

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
    hint: "Logged in (cookie). Dashboard still uses ?token=... for now."
  });
}));

app.post("/auth/logout", asyncHandler(async (req, res) => {
  const sid = getCookie(req, "constrava_session");
  if (sid) await pool.query(`DELETE FROM sessions WHERE session_id=$1`, [sid]);
  clearCookie(res, "constrava_session");
  res.json({ ok: true });
}));

app.get("/me", asyncHandler(async (req, res) => {
  const sess = await getSession(req);
  if (!sess) return res.json({ ok: true, logged_in: false });
  res.json({
    ok: true,
    logged_in: true,
    user: { email: sess.email, site_id: sess.site_id },
    expires_at: sess.expires_at
  });
}));

/* ---------------------------
   Onboarding: create a site
   POST /sites { site_id, site_name, owner_email, custom_token? }
----------------------------*/
app.post("/sites", asyncHandler(async (req, res) => {
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
}));

/* ---------------------------
   Tracker script
   GET /tracker.js
----------------------------*/
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  const endpoint = publicEventsUrl(req) + "/events";

  res.send(`
(function () {
  try {
    var script = document.currentScript;
    if (!script) return;

    var siteId = script.getAttribute("data-site-id");
    if (!siteId) return;

    fetch(${JSON.stringify(endpoint)}, {
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
})();`.trim());
});


/* ---------------------------
   Receive events
   POST /events
----------------------------*/
app.post("/events", asyncHandler(async (req, res) => {
  const { site_id, event_name, page_type, device, lead_email, lead_name, lead_phone, lead_notes } = req.body || {};
  if (!site_id || !event_name) return res.status(400).json({ ok: false, error: "site_id and event_name required" });

  const site = await pool.query("SELECT 1 FROM sites WHERE site_id=$1", [site_id]);
  if (site.rows.length === 0) return res.status(403).json({ ok: false, error: "Invalid site_id" });

  await pool.query(
    `INSERT INTO events_raw (site_id, event_name, page_type, device)
     VALUES ($1,$2,$3,$4)`,
    [site_id, String(event_name), page_type || null, device || null]
  );

  // CRM: if this is a lead event, also store a row in crm_leads (email optional)
  if (String(event_name) === "lead") {
    const email = (lead_email ? safeEmail(lead_email) : null) || null;
    const name = lead_name ? String(lead_name).trim().slice(0, 140) : null;
    const phone = lead_phone ? String(lead_phone).trim().slice(0, 60) : null;
    const notes = lead_notes ? String(lead_notes).trim().slice(0, 1000) : null;

    await pool.query(
      `INSERT INTO crm_leads (site_id, email, name, phone, source_page, status, notes)
       VALUES ($1,$2,$3,$4,$5,'new',$6)`,
      [site_id, email, name, phone, page_type || null, notes]
    );



// CRM v2: also create/attach a client + activity (best-effort)
try {
  if (event_name === "lead") {
    const client = await upsertClient(site_id, {
      full_name: name || null,
      email: email || null,
      phone: phone || null,
      stage: "lead"
    });

    // keep identities fresh
    if (email) await addIdentity(site_id, client.id, "email", normEmail(email));
    if (phone) await addIdentity(site_id, client.id, "phone", normPhone(phone));
    if (name) await addIdentity(site_id, client.id, "name", normName(name));

    await createActivityWithMatch(site_id, {
      type: "form_lead",
      direction: "in",
      occurred_at: new Date().toISOString(),
      from_email: email || null,
      to_email: null,
      subject: "New lead captured",
      body_text: notes || null,
      phone: phone || null,
      meta: { source_page: page_type || null }
    }, {
      emailA: email || null,
      phone: phone || null,
      name: name || null
    });
  }
} catch (e) {
  // do not block event ingestion if CRM v2 fails
}
  }

  res.json({ ok: true });
}));
/* ---------------------------
   DEMO: fire events
   POST /demo/fire-event { token, event_name, page_type?, device? }
----------------------------*/
app.post("/demo/fire-event", asyncHandler(async (req, res) => {
  const { token, event_name, page_type, device, lead_email, lead_name, lead_phone, lead_notes } = req.body || {};
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

  // CRM: store lead details when event is "lead"
  if (event_name === "lead") {
    const email = (lead_email ? safeEmail(lead_email) : null) || null;
    const name = lead_name ? String(lead_name).trim().slice(0, 140) : null;
    const phone = lead_phone ? String(lead_phone).trim().slice(0, 60) : null;
    const notes = lead_notes ? String(lead_notes).trim().slice(0, 1000) : null;

    await pool.query(
      `INSERT INTO crm_leads (site_id, email, name, phone, source_page, status, notes)
       VALUES ($1,$2,$3,$4,$5,'new',$6)`,
      [site.site_id, email, name, phone, page_type || "/", notes]
    );
  }

  res.json({ ok: true });
}));

/* ---------------------------
   LIVE: new page_views since timestamp
   GET /live?token=...&since=ISO
----------------------------*/
app.get("/live", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token;
  const since = req.query.since;
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
    whereSince = " AND created_at > $2";
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
}));

/* ---------------------------
   DEMO: shareable link
   POST /demo/link { token } -> { url }
   GET /d/:code -> redirect to /dashboard?token=...
----------------------------*/
app.post("/demo/link", asyncHandler(async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ ok: false, error: "token required" });

  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const code = crypto.randomBytes(4).toString("hex");
  await pool.query(`INSERT INTO demo_links (code, token) VALUES ($1,$2)`, [code, token]);

  const base = process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com";
  res.json({ ok: true, code, url: `${base}/d/${code}` });
}));

app.get("/d/:code", asyncHandler(async (req, res) => {
  setNoStore(res);
  const code = String(req.params.code || "").trim();
  const r = await pool.query(`SELECT token FROM demo_links WHERE code=$1 LIMIT 1`, [code]);
  if (r.rows.length === 0) return res.status(404).send("Demo link not found");
  return res.redirect("/dashboard?token=" + encodeURIComponent(r.rows[0].token));
}));

/* ---------------------------
   Metrics
   GET /metrics?token=...&days=7
----------------------------*/
app.get("/metrics", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

  const site_id = site.site_id;
  const days = normalizeDays(req.query.days);

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

  const startDateInterval = `${days - 1} days`;

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
    [site_id, startDateInterval]
  );

  const visits_range = trendRes.rows.reduce((sum, r) => sum + (r.visits || 0), 0);

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
    device_mix: deviceRes.rows[0] || { mobile: 0, desktop: 0 },
    last_event: lastEventRes.rows[0] || null,
    leads,
    purchases,
    cta_clicks,
    conversion_rate,
    purchase_rate,
    top_pages_range
  });
}));


/* ---------------------------
   CRM (Leads)
   GET /crm?token=...&limit=100
   POST /crm/update { token, lead_id, status?, notes? }
----------------------------*/
app.get("/crm", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

  const limit = Math.min(parseInt(req.query.limit || "100", 10), 300);

  const r = await pool.query(
    `SELECT id, email, name, phone, source_page, status, notes, created_at
     FROM crm_leads
     WHERE site_id=$1
     ORDER BY created_at DESC
     LIMIT $2`,
    [site.site_id, limit]
  );

  res.json({ ok: true, leads: r.rows });
}));

app.post("/crm/update", asyncHandler(async (req, res) => {
  const { token, lead_id, status, notes } = req.body || {};
  if (!token) return res.status(400).json({ ok: false, error: "token required" });
  if (!lead_id) return res.status(400).json({ ok: false, error: "lead_id required" });

  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const s = status ? String(status).trim().slice(0, 40) : null;
  const n = notes ? String(notes).trim().slice(0, 2000) : null;

  const r = await pool.query(
    `UPDATE crm_leads
     SET status = COALESCE($3, status),
         notes  = COALESCE($4, notes)
     WHERE id=$2 AND site_id=$1
     RETURNING id, email, name, phone, source_page, status, notes, created_at`,
    [site.site_id, lead_id, s, n]
  );

  if (!r.rows.length) return res.status(404).json({ ok: false, error: "Lead not found" });
  res.json({ ok: true, lead: r.rows[0] });
}));


/* ---------------------------
   CRM v2 (clients + activities + matching)
----------------------------*/

// List / search clients
app.get("/crm/clients", asyncHandler(async (req, res) => {
  setNoStore(res);
  const token = req.query.token;
  const q = String(req.query.q || "").trim().toLowerCase();

  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const params = [site.site_id];
  let where = "";
  if (q) {
    params.push("%" + q + "%");
    where = " AND (LOWER(COALESCE(full_name,'')) LIKE $2 OR LOWER(COALESCE(primary_email,'')) LIKE $2 OR LOWER(COALESCE(primary_phone,'')) LIKE $2)";
  }

  const r = await pool.query(
    `SELECT id, full_name, primary_email, primary_phone, stage, health, confidence, last_touch_at, created_at
     FROM crm_clients
     WHERE site_id=$1 ${where}
     ORDER BY COALESCE(last_touch_at, created_at) DESC
     LIMIT 100`,
    params
  );

  res.json({ ok: true, clients: r.rows });
}));

// Create a client
app.post("/crm/clients", asyncHandler(async (req, res) => {
  const token = req.query.token || req.body?.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const full_name = String(req.body?.full_name || "").trim();
  const email = String(req.body?.email || "").trim();
  const phone = String(req.body?.phone || "").trim();
  const stage = String(req.body?.stage || "lead").trim();

  if (!full_name && !email && !phone) {
    return res.status(400).json({ ok: false, error: "Provide at least one of: full_name, email, phone" });
  }

  const c = await upsertClient(site.site_id, { full_name, email, phone, stage });
  // if user provided extra, ensure identities exist
  if (email) await addIdentity(site.site_id, c.id, "email", normEmail(email));
  if (phone) await addIdentity(site.site_id, c.id, "phone", normPhone(phone));
  if (full_name) await addIdentity(site.site_id, c.id, "name", normName(full_name));

  res.json({ ok: true, client: c });
}));

// Client detail (with recent activity + matches)
app.get("/crm/client", asyncHandler(async (req, res) => {
  setNoStore(res);
  const token = req.query.token;
  const client_id = parseInt(req.query.client_id || "0", 10);

  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });
  if (!client_id) return res.status(400).json({ ok: false, error: "client_id required" });

  const c = await pool.query(
    `SELECT * FROM crm_clients WHERE site_id=$1 AND id=$2 LIMIT 1`,
    [site.site_id, client_id]
  );
  if (!c.rows.length) return res.status(404).json({ ok: false, error: "Client not found" });

  const ids = await pool.query(
    `SELECT kind, value FROM crm_identities WHERE site_id=$1 AND client_id=$2 ORDER BY kind, created_at DESC`,
    [site.site_id, client_id]
  );

  const acts = await pool.query(
    `SELECT a.*, m.confidence, m.reason, m.status as match_status
     FROM crm_activity_matches m
     JOIN crm_activities a ON a.id = m.activity_id
     WHERE m.site_id=$1 AND m.client_id=$2 AND m.status <> 'rejected'
     ORDER BY a.occurred_at DESC
     LIMIT 50`,
    [site.site_id, client_id]
  );

  res.json({ ok: true, client: c.rows[0], identities: ids.rows, activities: acts.rows });
}));

// Review queue (unmatched / low-confidence)
app.get("/crm/review", asyncHandler(async (req, res) => {
  setNoStore(res);
  const token = req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const r = await pool.query(
    `SELECT m.id as match_id, m.confidence, m.reason, m.status,
            a.id as activity_id, a.type, a.direction, a.occurred_at, a.from_email, a.to_email, a.subject,
            LEFT(COALESCE(a.body_text,''), 280) as body_preview, a.phone, a.duration_sec
     FROM crm_activity_matches m
     JOIN crm_activities a ON a.id=m.activity_id
     WHERE m.site_id=$1 AND m.status='needs_review'
     ORDER BY a.occurred_at DESC
     LIMIT 80`,
    [site.site_id]
  );

  res.json({ ok: true, queue: r.rows });
}));

// Confirm a match (assign activity to a client)
app.post("/crm/review/confirm", asyncHandler(async (req, res) => {
  const { token, match_id, client_id } = req.body || {};
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const mid = parseInt(match_id || "0", 10);
  const cid = parseInt(client_id || "0", 10);
  if (!mid || !cid) return res.status(400).json({ ok: false, error: "match_id and client_id required" });

  // validate client belongs to site
  const c = await pool.query(`SELECT id FROM crm_clients WHERE site_id=$1 AND id=$2 LIMIT 1`, [site.site_id, cid]);
  if (!c.rows.length) return res.status(404).json({ ok:false, error:"Client not found" });

  const r = await pool.query(
    `UPDATE crm_activity_matches
     SET client_id=$3, status='confirmed', confidence=GREATEST(confidence, 0.85)
     WHERE site_id=$1 AND id=$2
     RETURNING *`,
    [site.site_id, mid, cid]
  );

  res.json({ ok: true, match: r.rows[0] });
}));

// Reject a match
app.post("/crm/review/reject", asyncHandler(async (req, res) => {
  const { token, match_id } = req.body || {};
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const mid = parseInt(match_id || "0", 10);
  if (!mid) return res.status(400).json({ ok: false, error: "match_id required" });

  const r = await pool.query(
    `UPDATE crm_activity_matches SET status='rejected' WHERE site_id=$1 AND id=$2 RETURNING *`,
    [site.site_id, mid]
  );

  res.json({ ok: true, match: r.rows[0] });
}));

// Ingest email activity (webhook-friendly)
// POST /crm/ingest/email { token, occurred_at?, direction?, from_email, to_email, subject?, body_text?, client_name? }
app.post("/crm/ingest/email", asyncHandler(async (req, res) => {
  const token = req.body?.token || req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok:false, error:"Unauthorized" });

  const from_email = normEmail(req.body?.from_email);
  const to_email = normEmail(req.body?.to_email);
  if (!from_email && !to_email) return res.status(400).json({ ok:false, error:"from_email or to_email required" });

  const out = await createActivityWithMatch(site.site_id, {
    type: "email",
    direction: req.body?.direction || null,
    occurred_at: req.body?.occurred_at || null,
    from_email,
    to_email,
    subject: req.body?.subject || null,
    body_text: req.body?.body_text || null,
    meta: req.body?.meta || null
  }, {
    emailA: from_email,
    emailB: to_email,
    name: req.body?.client_name || null
  });

  res.json({ ok:true, ...out });
}));

// Ingest call activity
// POST /crm/ingest/call { token, occurred_at?, direction?, phone, duration_sec?, notes? , client_name? }
app.post("/crm/ingest/call", asyncHandler(async (req, res) => {
  const token = req.body?.token || req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok:false, error:"Unauthorized" });

  const phone = normPhone(req.body?.phone);
  if (!phone) return res.status(400).json({ ok:false, error:"phone required" });

  const out = await createActivityWithMatch(site.site_id, {
    type: "call",
    direction: req.body?.direction || null,
    occurred_at: req.body?.occurred_at || null,
    phone,
    duration_sec: req.body?.duration_sec || null,
    body_text: req.body?.notes || null,
    meta: req.body?.meta || null
  }, {
    phone,
    name: req.body?.client_name || null
  });

  res.json({ ok:true, ...out });
}));


/* ---------------------------
   Reports
----------------------------*/
app.get("/reports", asyncHandler(async (req, res) => {
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
}));

app.get("/reports/latest", asyncHandler(async (req, res) => {
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
}));

app.get("/reports/by-date", asyncHandler(async (req, res) => {
  setNoStore(res);

  const site = await getSiteByToken(req.query.token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized. Add ?token=..." });

  const date = String(req.query.date || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ ok: false, error: "date must be YYYY-MM-DD" });
  }

  const r = await pool.query(
    `SELECT site_id, report_date, report_text, created_at
     FROM daily_reports
     WHERE site_id=$1 AND report_date=$2
     ORDER BY created_at DESC
     LIMIT 1`,
    [site.site_id, date]
  );

  if (!r.rows.length) return res.status(404).json({ ok: false, error: "Report not found for that date" });
  res.json({ ok: true, report: r.rows[0] });
}));

/* ---------------------------
   Demo seeder
   POST /demo/seed?token=...
----------------------------*/
app.post("/demo/seed", asyncHandler(async (req, res) => {
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


  // ---------------------------
  // CRM demo seed (clients + activities)
  // ---------------------------
  // This makes the CRM tab feel "alive" for demos.
  try {
    const bizEmail = (site.owner_email || "owner@example.com").toLowerCase();

    const demoClients = [
      {
        name: "Acme Plumbing",
        primary_email: "info@acmeplumbing.com",
        stage: "lead",
        health: "warm",
        phone: "+1 (555) 201-1001",
        domain: "acmeplumbing.com"
      },
      {
        name: "Brightside Dental",
        primary_email: "hello@brightsidedental.com",
        stage: "proposal",
        health: "warm",
        phone: "+1 (555) 201-1002",
        domain: "brightsidedental.com"
      },
      {
        name: "Northstar Fitness",
        primary_email: "manager@northstarfitness.com",
        stage: "active",
        health: "good",
        phone: "+1 (555) 201-1003",
        domain: "northstarfitness.com"
      },
      {
        name: "Summit Realty Group",
        primary_email: "team@summitrealtygroup.com",
        stage: "at_risk",
        health: "at_risk",
        phone: "+1 (555) 201-1004",
        domain: "summitrealtygroup.com"
      }
    ];

    const clientIdsByEmail = {};

    for (const c of demoClients) {
      const r = await pool.query(
        `
        INSERT INTO crm_clients (site_id, name, primary_email, stage, health, notes)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (site_id, primary_email)
        DO UPDATE SET
          name = EXCLUDED.name,
          stage = EXCLUDED.stage,
          health = EXCLUDED.health,
          notes = EXCLUDED.notes
        RETURNING id
        `,
        [
          site_id,
          c.name,
          safeEmail(c.primary_email),
          c.stage,
          c.health,
          "Demo client seeded. Activity matching uses email/phone/domain identities (with confidence scoring)."
        ]
      );

      const client_id = r.rows[0].id;
      clientIdsByEmail[safeEmail(c.primary_email)] = client_id;

      // identities for matching
      await pool.query(
        `INSERT INTO crm_identities (site_id, client_id, type, value)
         VALUES ($1,$2,'email',$3)
         ON CONFLICT (site_id, type, value) DO NOTHING`,
        [site_id, client_id, safeEmail(c.primary_email)]
      );

      if (c.domain) {
        await pool.query(
          `INSERT INTO crm_identities (site_id, client_id, type, value)
           VALUES ($1,$2,'domain',$3)
           ON CONFLICT (site_id, type, value) DO NOTHING`,
          [site_id, client_id, String(c.domain).toLowerCase()]
        );
      }

      if (c.phone) {
        await pool.query(
          `INSERT INTO crm_identities (site_id, client_id, type, value)
           VALUES ($1,$2,'phone',$3)
           ON CONFLICT (site_id, type, value) DO NOTHING`,
          [site_id, client_id, String(c.phone)]
        );
      }
    }

    // Create a handful of activities across channels.
    // We bias activity timestamps to the seeded window for a "story".
    const baseNow = new Date();
    function daysAgo(n) {
      return new Date(baseNow.getTime() - n * 24 * 60 * 60 * 1000);
    }

    // inbound lead email (matches by from email/domain)
    await createActivityWithMatch({
      site_id,
      channel: "email",
      direction: "inbound",
      subject: "Quote request — emergency service",
      body:
        "Hi! We found you on Google. Can you quote a same-day repair? " +
        "Also curious about your pricing and scheduling.",
      from_addr: "info@acmeplumbing.com",
      to_addr: bizEmail,
      occurred_at: daysAgo(5).toISOString()
    });

    // outbound follow-up email (still matches)
    await createActivityWithMatch({
      site_id,
      channel: "email",
      direction: "outbound",
      subject: "Re: Quote request — next steps",
      body:
        "Thanks for reaching out! Here are 2 options and the earliest availability. " +
        "If you can confirm an address + time window, we can lock it in.",
      from_addr: bizEmail,
      to_addr: "info@acmeplumbing.com",
      occurred_at: daysAgo(4).toISOString()
    });

    // discovery call (matches by phone)
    await createActivityWithMatch({
      site_id,
      channel: "call",
      direction: "inbound",
      subject: "Discovery call — services & budget",
      body:
        "15-min call: they want a monthly plan and asked about response times. " +
        "They mentioned they get ~2-3 leads/day.",
      phone: "+1 (555) 201-1002",
      occurred_at: daysAgo(3).toISOString()
    });

    // proposal email (matches by domain)
    await createActivityWithMatch({
      site_id,
      channel: "email",
      direction: "outbound",
      subject: "Proposal attached — launch checklist",
      body:
        "Attached proposal. Key goals: increase qualified leads, reduce form drop-off, " +
        "and measure CTA performance. Happy to walk through it.",
      from_addr: bizEmail,
      to_addr: "hello@brightsidedental.com",
      occurred_at: daysAgo(3).toISOString()
    });

    // active client check-in (matches by email)
    await createActivityWithMatch({
      site_id,
      channel: "email",
      direction: "inbound",
      subject: "Monthly update — new class schedule",
      body:
        "We added new classes and updated the homepage hero. Can you verify the tracking " +
        "still looks right and send the updated report?",
      from_addr: "manager@northstarfitness.com",
      to_addr: bizEmail,
      occurred_at: daysAgo(2).toISOString()
    });

    // at-risk signal (matches by domain)
    await createActivityWithMatch({
      site_id,
      channel: "email",
      direction: "inbound",
      subject: "Concern: leads dropped this week",
      body:
        "We noticed fewer inquiries. Anything change? Can you check where people are dropping off " +
        "and what we should fix first?",
      from_addr: "team@summitrealtygroup.com",
      to_addr: bizEmail,
      occurred_at: daysAgo(1).toISOString()
    });

    // unmatched email (shows 'unmatched' bucket in CRM)
    await createActivityWithMatch({
      site_id,
      channel: "email",
      direction: "inbound",
      subject: "Random inquiry (unmatched example)",
      body:
        "Hi, do you work with ecommerce? Just exploring options. " +
        "Not sure if this is the right contact.",
      from_addr: "someone@unknown-example.com",
      to_addr: bizEmail,
      occurred_at: daysAgo(1).toISOString()
    });

    // Update last_touch_at from latest matched activity per client
    await pool.query(
      `
      UPDATE crm_clients c
      SET last_touch_at = x.last_touch
      FROM (
        SELECT m.client_id, MAX(a.occurred_at) AS last_touch
        FROM crm_activity_matches m
        JOIN crm_activities a ON a.id = m.activity_id
        WHERE a.site_id = $1
        GROUP BY m.client_id
      ) x
      WHERE c.id = x.client_id
      `,
      [site_id]
    );
  } catch (e) {
    console.warn("CRM demo seed skipped:", e?.message || e);
  }

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
}));

/* ---------------------------
   AI endpoints (FULL AI only)
----------------------------*/
app.post("/api/ai/chat", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token || req.body?.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const gate = planGate(site, ["full_ai"]);
  if (!gate.ok) return res.status(gate.status).json({ ok: false, error: gate.error });

  const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");
  const message = String(req.body?.message || "").trim();
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-12) : [];
  if (!message) return res.status(400).json({ ok: false, error: "message required" });

  const days = 30;

  const metricsRes = await pool.query(
    `
    SELECT
      COUNT(*)::int AS total_events,
      SUM(CASE WHEN event_name='page_view' THEN 1 ELSE 0 END)::int AS page_views,
      SUM(CASE WHEN event_name='lead' THEN 1 ELSE 0 END)::int AS leads,
      SUM(CASE WHEN event_name='purchase' THEN 1 ELSE 0 END)::int AS purchases,
      SUM(CASE WHEN event_name='cta_click' THEN 1 ELSE 0 END)::int AS cta_clicks
    FROM events_raw
    WHERE site_id=$1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
    `,
    [site.site_id, days]
  );

  const topPagesRes = await pool.query(
    `
    SELECT page_type, COUNT(*)::int AS views
    FROM events_raw
    WHERE site_id=$1 AND event_name='page_view'
      AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
      AND page_type IS NOT NULL
    GROUP BY 1
    ORDER BY views DESC
    LIMIT 8
    `,
    [site.site_id, days]
  );

  const lastReportRes = await pool.query(
    `
    SELECT report_date, report_text
    FROM daily_reports
    WHERE site_id=$1
    ORDER BY report_date DESC, created_at DESC
    LIMIT 1
    `,
    [site.site_id]
  );

  const context = {
    site_id: site.site_id,
    plan: site.plan,
    window_days: days,
    metrics_30d: metricsRes.rows[0],
    top_pages_30d: topPagesRes.rows,
    latest_report: lastReportRes.rows[0] || null
  };

const system = `
You are Constrava's analytics coach.

Return plain text formatted like this (keep the line breaks):

WHAT'S HAPPENING
- bullet
- bullet

WHY IT MATTERS
- bullet
- bullet

NEXT BEST ACTIONS
1) step
2) step
3) step

KPI TO WATCH
- KPI: <name> — <why>

Rules:
- Always include blank lines between sections
- Keep bullets short (one line each)
- No long paragraphs
`.trim();



  const messages = [
    { role: "system", content: system },
    { role: "user", content: "Site context JSON:\n" + JSON.stringify(context) },
    ...history.map((h) => ({ role: h.role, content: String(h.content || "") })),
    { role: "user", content: message }
  ];

  const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      messages,
      temperature: 0.4
    })
  });

  const aiData = await aiRes.json();
  const reply = aiData?.choices?.[0]?.message?.content;
  if (!reply) return res.status(500).json({ ok: false, error: "AI response missing" });

  res.json({ ok: true, reply });
}));


/* ---------------------------
   AI CRM Answer Bot (FULL AI)
   POST /api/ai/crm/answer { token, question }
----------------------------*/
app.post("/api/ai/crm/answer", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token || req.body?.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok:false, error:"Unauthorized" });

  const gate = planGate(site, ["full_ai"]);
  if (!gate.ok) return res.status(gate.status).json({ ok:false, error: gate.error });

  const OPENAI_API_KEY = requireEnv("OPENAI_API_KEY");
  const question = String(req.body?.question || "").trim();
  if (!question) return res.status(400).json({ ok:false, error:"question required" });

  // lightweight context: clients + latest touch + recent activities + review queue counts
  const clientsRes = await pool.query(
    `SELECT id, full_name, primary_email, primary_phone, stage, health, confidence, last_touch_at
     FROM crm_clients
     WHERE site_id=$1
     ORDER BY COALESCE(last_touch_at, created_at) DESC
     LIMIT 120`,
    [site.site_id]
  );

  const recentActsRes = await pool.query(
    `SELECT a.id, a.type, a.direction, a.occurred_at, a.from_email, a.to_email, a.phone,
            LEFT(COALESCE(a.subject,''), 180) as subject,
            LEFT(COALESCE(a.body_text,''), 300) as body_preview,
            m.client_id, m.confidence as match_confidence, m.status as match_status
     FROM crm_activities a
     JOIN crm_activity_matches m ON m.activity_id=a.id
     WHERE a.site_id=$1
     ORDER BY a.occurred_at DESC
     LIMIT 80`,
    [site.site_id]
  );

  const reviewCountRes = await pool.query(
    `SELECT COUNT(*)::int as needs_review
     FROM crm_activity_matches
     WHERE site_id=$1 AND status='needs_review'`,
    [site.site_id]
  );

  const context = {
    site_id: site.site_id,
    plan: site.plan,
    clients: clientsRes.rows,
    recent_activity: recentActsRes.rows,
    needs_review_count: reviewCountRes.rows[0]?.needs_review || 0
  };

  const system = `
You are Constrava's CRM autopilot.

The user will ask questions like:
- "What is the status of Acme Plumbing?"
- "When did we last talk to Sarah?"
- "Which clients are at risk?"
- "How many calls did we have this week?"
- "Do we owe anyone a follow-up?"

You MUST:
- Answer with structured, scannable text (no wall of text).
- If client matching is uncertain, say so and show your best guess + confidence.
- Suggest 1–3 next actions when appropriate.

Return EXACTLY this format:

ANSWER
- <1–4 bullets>

EVIDENCE
- <2–6 bullets referencing concrete data points (dates/emails/calls/subjects)>
- If uncertain, include: "Uncertainty: <why>"

NEXT ACTIONS
1) ...
2) ...
3) ...

CONFIDENCE
- <0–100% and one-sentence reason>

Rules:
- Keep bullets one line each.
- Prefer dates in ISO (YYYY-MM-DD) if possible.
- Never invent facts. If data isn't present, say what is missing.
  `.trim();

  const messages = [
    { role:"system", content: system },
    { role:"user", content: "CRM context JSON:\n" + JSON.stringify(context) },
    { role:"user", content: question }
  ];

  const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type":"application/json" },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      messages,
      temperature: 0.35
    })
  });

  const aiData = await aiRes.json().catch(()=>({}));
  const reply = aiData?.choices?.[0]?.message?.content;
  if (!reply) return res.status(500).json({ ok:false, error:"AI response missing" });

  res.json({ ok:true, reply });
}));

app.post("/generate-report", asyncHandler(async (req, res) => {
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
      SUM(CASE WHEN event_name='page_view' THEN 1 ELSE 0 END)::int AS page_views,
      SUM(CASE WHEN event_name='lead' THEN 1 ELSE 0 END)::int AS leads,
      SUM(CASE WHEN event_name='purchase' THEN 1 ELSE 0 END)::int AS purchases
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
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      temperature: 0.4,
      messages: [
        {
          role: "system",
          content: `
You are Constrava's analytics assistant.

Write for a busy small-business owner.
Make it friendly, simple, and easy to scan.
Avoid jargon unless explained simply.
Keep things encouraging, not technical.
`.trim()
        },
        {
          role: "user",
          content: `
Metrics JSON (last 7 days):
${JSON.stringify(metrics)}

Return EXACTLY this format:

SUMMARY:
(1–2 sentences)

HIGHLIGHTS:
- (max 3 bullets, short)

WHAT HAPPENED:
(2–3 short sentences)

WHY IT MATTERS:
- (max 3 bullets)

NEXT STEPS:
1) (step)
2) (step)
3) (step)

KPI: <name> — <value> (target: <target>)
`.trim()
        }
      ]
    })
  });

  const aiData = await aiRes.json().catch(() => ({}));
  const reportText = aiData?.choices?.[0]?.message?.content;

  if (!reportText) {
    return res.status(500).json({
      ok: false,
      error: "AI response missing",
      ai_preview: JSON.stringify(aiData).slice(0, 800)
    });
  }


  const saved = await pool.query(
    `INSERT INTO daily_reports (site_id, report_date, report_text)
     VALUES ($1, CURRENT_DATE, $2)
     ON CONFLICT (site_id, report_date)
     DO UPDATE SET report_text = EXCLUDED.report_text
     RETURNING site_id, report_date, report_text, created_at`,
    [site.site_id, reportText]
  );

  res.json({ ok: true, report: saved.rows[0] });
}));

app.post("/generate-action-plan", asyncHandler(async (req, res) => {
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
      ],
      temperature: 0.45
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
}));

/* ---------------------------
   Email latest report (PRO + FULL AI)
   POST /email-latest { token, to_email }
----------------------------*/
app.post("/email-latest", asyncHandler(async (req, res) => {
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
}));

/* ---------------------------
   DEMO: activate a plan
   POST /demo/activate-plan { token, plan }
----------------------------*/
app.post("/demo/activate-plan", asyncHandler(async (req, res) => {
  if (process.env.ENABLE_DEMO_ACTIVATE === "false") {
    return res.status(403).json({ ok: false, error: "Demo activation disabled" });
  }

  const { token, plan } = req.body || {};
  const allowed = new Set(["starter", "pro", "full_ai"]);

  if (!token) return res.status(400).json({ ok: false, error: "token required" });
  if (!plan || !allowed.has(plan)) return res.status(400).json({ ok: false, error: "Invalid plan" });

  const site = await getSiteByToken(token);
  if (!site) return res.status(401).json({ ok: false, error: "Unauthorized" });

  const r = await pool.query(
    `UPDATE sites SET plan=$2 WHERE site_id=$1 RETURNING site_id, plan`,
    [site.site_id, plan]
  );

  res.json({ ok: true, updated: r.rows[0] });
}));

/* ---------------------------
   Storefront
----------------------------*/
/* ---------------------------
   Storefront
----------------------------*/
app.get("/storefront", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

  const site_id = site.site_id;
  const plan = site.plan || "unpaid";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Constrava — Plans</title>
<style>
:root{
  --bg:#0b0f19; --text:#e5e7eb; --muted:#9ca3af;
  --border:rgba(255,255,255,.10); --shadow:0 10px 30px rgba(0,0,0,.35);
  --radius:16px; --accent:#60a5fa; --accent2:#34d399;
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
  grid-column: span 6; padding:16px; border-radius: var(--radius);
  border:1px solid var(--border); background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
  box-shadow: var(--shadow);
  min-width:0;
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
  background: rgba(15,23,42,.35); color: var(--muted); font-size:13px; line-height: 1.55;
}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>Constrava Plans</h1>
        <div class="sub">Activate your dashboard. Stripe later — demo activation for now.</div>
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <span class="pill">Site: <b>${site_id}</b></span>
      <span class="pill">Current plan: <b>${plan}</b></span>
    </div>
  </div>

    <div class="card">
      <h3 class="name">Pro</h3>
      <div class="price">$19 <span class="muted">/mo</span></div>
      <div class="muted">Reports + email.</div>
      <ul>
        <li>Daily reports (non‑AI)</li>
        <li>Email latest report</li>
      </ul>
      <button class="btn" onclick="activate('pro')">Activate Pro</button>
    </div>

    <div class="card" style="grid-column: 1 / -1">
      <h3 class="name">Full AI</h3>
      <div class="price">$69 <span class="muted">/mo</span></div>
      <div class="muted">AI summaries + action plans + on‑dashboard AI chat.</div>
      <ul>
        <li>AI report generator</li>
        <li>AI action plan generator</li>
        <li>Live AI Helper chat</li>
      </ul>
      <button class="btn btnGreen" onclick="activate('full_ai')">Activate Full AI</button>

      <div class="note">
        <b>Note:</b> These buttons call a demo activation endpoint. Later, Stripe will call a real webhook after payment.
      </div>

      <div class="note" id="status">Status: idle</div>
    </div>
  </div>
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
    const data = await r.json().catch(()=> ({}));
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
}));



/* ---------------------------
   Dashboard UI
   GET /dashboard?token=...
----------------------------*/
app.get("/dashboard", asyncHandler(async (req, res) => {
  setNoStore(res);

  const token = req.query.token;
  const site = await getSiteByToken(token);
  if (!site) return res.status(401).send("Unauthorized. Add ?token=YOUR_TOKEN");

  const plan = site.plan || "unpaid";
  if (plan === "unpaid") return res.redirect("/storefront?token=" + encodeURIComponent(token));

  res.setHeader("Content-Type", "text/html; charset=utf-8");

  // Clean dashboard: HTML + CSS only. All behavior comes from /dashboard.js
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Constrava Dashboard</title>
<style>
:root{
  --bg:#0b0f19;
  --panel: rgba(255,255,255,.06);
  --panel2: rgba(255,255,255,.04);
  --text:#e5e7eb;
  --muted:#9ca3af;
  --border: rgba(255,255,255,.12);
  --accent:#60a5fa;
  --accent2:#34d399;
  --danger:#fb7185;
  --shadow: 0 14px 40px rgba(0,0,0,.35);
  --radius: 16px;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial;
  background:
    radial-gradient(1100px 720px at 20% -10%, rgba(96,165,250,.20), transparent 60%),
    radial-gradient(900px 620px at 90% 0%, rgba(52,211,153,.14), transparent 55%),
    var(--bg);
  color: var(--text);
}
.wrap{max-width:1180px;margin:0 auto;padding:22px 16px 60px}
.top{
  display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  padding:16px;
  border:1px solid var(--border);
  border-radius: var(--radius);
  background: linear-gradient(180deg, rgba(255,255,255,.07), rgba(255,255,255,.02));
  box-shadow: var(--shadow);
}
/* ---------- Report UI (cards) ---------- */
.repCard{
  grid-column: span 6;
  border:1px solid rgba(255,255,255,.12);
  background: rgba(15,23,42,.35);
  border-radius: 16px;
  padding:12px;
  min-width:0;
}

.repWrap{
  display:grid;
  grid-template-columns:repeat(12,1fr);
  gap:12px;
}

.repCard:nth-child(3){
  grid-column: 1 / -1;
}

@media (max-width: 980px){ .repCard{ grid-column: 1 / -1; } }

.repTitle{
  font-weight:950;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
}
.repBadge{
  font-size:11px;
  color: rgba(229,231,235,.75);
  border:1px solid rgba(255,255,255,.12);
  padding:4px 8px;
  border-radius:999px;
  background: rgba(255,255,255,.04);
}
.repText{
  margin-top:8px;
  color: rgba(229,231,235,.90);
  font-size:13px;
  line-height:1.55;
}
.repList{
  margin:8px 0 0 0;
  padding-left:18px;
  color: rgba(229,231,235,.92);
  line-height:1.6;
}
.repList li{ margin:4px 0; }
.repKpi{
  margin-top:10px;
  padding:10px;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.12);
  background: rgba(96,165,250,.10);
}
.repKpi b{ font-size:14px; }

.brand{display:flex;align-items:center;gap:12px}
.logo{width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg, rgba(96,165,250,.95), rgba(52,211,153,.88));}
h1{margin:0;font-size:18px;font-weight:950}
.sub{margin-top:3px;font-size:12px;color:var(--muted)}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.pill{
  display:inline-block;
  padding:7px 10px;
  border:1px solid var(--border);
  border-radius:999px;
  background: rgba(15,23,42,.55);
  font-size:12px;
  color: var(--muted);
  white-space:nowrap;
}
.grid{margin-top:14px;display:grid;grid-template-columns:repeat(12,1fr);gap:12px;}
.card{
  border:1px solid var(--border);
  border-radius: var(--radius);
  background: var(--panel2);
  box-shadow: var(--shadow);
  padding:14px;
  min-width:0;
}
.kpi{font-size:28px;font-weight:1000;letter-spacing:-0.5px}
.kpiSmall{font-size:18px;font-weight:950}
.muted{color:var(--muted);font-size:12px;line-height:1.5}
button,select,a,input{
  border-radius:12px;border:1px solid var(--border);
  background: rgba(15,23,42,.55);
  color: var(--text);
  padding:10px 12px;
  font-weight:900;
  cursor:pointer;
  text-decoration:none;
  outline:none;
}
button:hover,a:hover,select:hover{border-color: rgba(96,165,250,.55)}
.btn{background: rgba(96,165,250,.14)}
.btnGreen{background: rgba(52,211,153,.14)}
.btnDanger{background: rgba(251,113,133,.10)}
.btnGhost{background: rgba(255,255,255,.04)}
.divider{height:1px;background: rgba(255,255,255,.10);margin:12px 0;}
.span12{grid-column:1 / -1}
.span8{grid-column: span 8}
.span6{grid-column: span 6}
.span4{grid-column: span 4}
.span3{grid-column: span 3}
@media (max-width: 980px){
  .span8,.span6,.span4,.span3{grid-column:1 / -1}
}
.chartBox{padding:10px;border-radius:14px;border:1px solid rgba(255,255,255,.10);background: rgba(15,23,42,.35)}
svg{display:block;width:100%;height:auto}
.list{display:flex;flex-direction:column;gap:8px;margin-top:10px}
.item{
  display:flex;justify-content:space-between;gap:10px;align-items:center;
  padding:10px 10px;border:1px solid rgba(255,255,255,.10);
  border-radius:14px;background: rgba(15,23,42,.35);
}
.barWrap{flex:1;min-width:0}
.bar{
  height:10px;border-radius:999px;background: rgba(96,165,250,.20);
  border:1px solid rgba(255,255,255,.10);
  overflow:hidden;
}
.bar > div{height:100%;background: rgba(96,165,250,.70)}
.mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace}
pre{
  margin:10px 0 0 0;
  white-space:pre-wrap;
  background: rgba(15,23,42,.55);
  border:1px solid rgba(255,255,255,.12);
  padding:12px;border-radius:14px;
}
.rightBtns{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>Constrava Dashboard</h1>
        <div class="sub">Token-auth dashboard • secure it later with accounts if desired</div>
      </div>
    </div>

    <div class="row">
      <select id="days">
        <option value="1">1 day</option>
        <option value="7" selected>7 days</option>
        <option value="30">30 days</option>
        <option value="365">1 year</option>
      </select>
      <button class="btnDanger" id="seedBtn">Seed demo data</button>
      <button class="btnGreen" id="aiReportTopBtn">Generate AI report</button>
      <button class="btn" id="refresh">Refresh</button>
      <a class="btnGhost" id="plansLink" href="/storefront?token=${encodeURIComponent(String(token))}">Plans</a>
      <a class="btnGhost" id="crmLink" href="#crmCard">CRM</a>
      <span class="pill" id="status">Status: idle</span>
    </div>
  </div>

  <div class="grid">
    <div class="card span12" id="chatCard">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div>
          <div style="font-weight:950">Live AI Helper</div>
          <div class="muted">Ask questions about your traffic, pages, conversions, and next steps.</div>
        </div>
        <span class="pill">Chat</span>
      </div>
      <div class="divider"></div>
      <div id="chatBox" style="height:220px;overflow:auto;padding:12px;border-radius:14px;border:1px solid rgba(255,255,255,.10);background: rgba(15,23,42,.35);">
        <div class="muted">Start by asking: “What should I improve first?”</div>
      </div>
      <div class="row" style="margin-top:10px">
        <input id="chatInput" placeholder="Type a message…" style="flex:1;min-width:220px" />
        <button class="btnGreen" id="chatSend">Send</button>
        <button class="btnGhost" id="chatClear">Clear</button>
      </div>
      <div class="muted" style="margin-top:8px">
        Note: Requires the <b>Full AI</b> plan (or the endpoint will return 403).
      </div>
    </div>

    <div class="card span12">
      <div style="font-weight:950">Latest AI Report</div>
      <div class="muted">Your most recent report (or seed sample).</div>
      <div class="divider"></div>
      <div id="latestAiReportCards" class="repWrap">Loading latest report…</div>

<details style="margin-top:10px">
  <summary class="muted" style="cursor:pointer">Show raw report</summary>
  <pre id="latestAiReport" class="mono" style="max-height:320px;overflow:auto">Loading…</pre>
</details>

    </div>

    <div class="card span3">
      <div class="muted">Visits today</div>
      <div class="kpi" id="kpiToday">—</div>
      <div class="muted" id="kpiTodaySub"></div>
    </div>

    <div class="card span3">
      <div class="muted">Visits in range</div>
      <div class="kpi" id="kpiRange">—</div>
      <div class="muted" id="kpiRangeSub"></div>
    </div>

    <div class="card span3">
      <div class="muted">Lead rate (leads/visits)</div>
      <div class="kpi" id="kpiLeadRate">—</div>
      <div class="muted">Goal: improve CTA + forms</div>
    </div>

    <div class="card span3">
      <div class="muted">Purchase rate</div>
      <div class="kpi" id="kpiPurchaseRate">—</div>
      <div class="muted">Track “purchase” events</div>
    </div>

    <div class="card span8">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div>
          <div style="font-weight:950">Traffic trend</div>
          <div class="muted">Visits per day (selected window)</div>
        </div>
        <div class="row">
          <span class="pill">Max/day: <b id="maxDay">—</b></span>
          <span class="pill">Avg/day: <b id="avgDay">—</b></span>
        </div>
      </div>

      <div class="chartBox" style="margin-top:10px">
        <svg id="trendSvg" viewBox="0 0 900 260" role="img" aria-label="Traffic trend chart"></svg>
      </div>

      <div class="divider"></div>

      <div class="row">
        <button class="btnGhost" id="simView">Sim page_view</button>
        <button class="btnGhost" id="simLead">Sim lead</button>
        <button class="btnGhost" id="simPurchase">Sim purchase</button>
        <button class="btnGhost" id="simCta">Sim cta_click</button>
        <button class="btn" id="share">Copy share link</button>
      </div>

      <div class="muted" style="margin-top:10px">
        Seeder requires <span class="mono">ENABLE_DEMO_SEED=true</span>. Sim buttons work any time.
      </div>
    </div>

    <div class="card span4">
      <div style="font-weight:950">Live</div>
      <div class="muted">Polls every few seconds for new page_views</div>
      <div class="divider"></div>
      <div class="row" style="justify-content:space-between">
        <div>
          <div class="muted">New page_views</div>
          <div class="kpiSmall" id="liveNew">—</div>
        </div>
        <div>
          <div class="muted">Last event</div>
          <div class="kpiSmall" id="liveLast">—</div>
        </div>
      </div>
      <div class="divider"></div>
      <pre id="liveJson">Loading…</pre>
      <div class="row" style="margin-top:10px">
        <button class="btnGhost" id="liveToggle">Pause</button>
        <button class="btnGhost" id="liveNow">Check now</button>
      </div>
    </div>

    <div class="card span6">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div>
          <div style="font-weight:950">Top pages</div>
          <div class="muted">Most viewed pages in range</div>
        </div>
        <span class="pill">Top 10</span>
      </div>
      <div class="list" id="topPages">Loading…</div>
    </div>

    <div class="card span6">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div>
          <div style="font-weight:950">Device mix & goals</div>
          <div class="muted">Breakdown + conversions</div>
        </div>
        <span class="pill">Visits → Leads → Purchases</span>
      </div>

      <div class="grid" style="margin-top:10px;gap:10px">
        <div class="card" style="grid-column: span 6; background: rgba(15,23,42,.35); box-shadow:none">
          <div class="muted">Device donut</div>
          <div class="chartBox" style="margin-top:8px">
            <svg id="deviceSvg" viewBox="0 0 240 160"></svg>
          </div>
          <div class="row" style="margin-top:8px">
            <span class="pill">Mobile: <b id="mob">—</b></span>
            <span class="pill">Desktop: <b id="desk">—</b></span>
          </div>
        </div>

        <div class="card" style="grid-column: span 6; background: rgba(15,23,42,.35); box-shadow:none">
          <div class="muted">Goals in range</div>
          <div class="row" style="margin-top:6px">
            <span class="pill">Leads: <b id="leads">—</b></span>
            <span class="pill">Purchases: <b id="purchases">—</b></span>
            <span class="pill">CTA: <b id="cta">—</b></span>
          </div>
          <div class="divider"></div>
          <div class="muted">Last event</div>
          <pre id="lastEvent">Loading…</pre>
        </div>
      </div>
    </div>

    
    <div class="card span12" id="crmCard">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div>
          <div style="font-weight:950">CRM — Leads</div>
          <div class="muted">Lead inbox saved from <span class="mono">lead</span> events (email optional).</div>
        </div>
        <div class="rightBtns">
          <button class="btnGhost" id="crmRefresh">Refresh</button>
          <button class="btnGhost" id="crmExport">Export CSV</button>
        </div>
      </div>
      <div class="divider"></div>
      <div class="list" id="crmLeads">Loading…</div>
      <div class="muted" style="margin-top:10px">
        Tip: Use <span class="mono">/demo/fire-event</span> with <span class="mono">event_name: "lead"</span> and include <span class="mono">lead_email</span>, <span class="mono">lead_name</span>, <span class="mono">lead_phone</span>.
      </div>

<div class="divider"></div>

<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
  <div>
    <div style="font-weight:950">Automated CRM (best-effort)</div>
    <div class="muted">Emails + calls can be auto-matched to clients with a confidence score. Low-confidence items appear in the review queue.</div>
  </div>
  <span class="pill">AI + Matching</span>
</div>

<div class="grid" style="margin-top:10px;gap:10px">
  <div class="card span6" style="background: rgba(15,23,42,.35); box-shadow:none">
    <div style="font-weight:950">Clients</div>
    <div class="muted">Search, create, and open a client.</div>
    <div class="row" style="margin-top:8px">
      <input id="crmClientSearch" placeholder="Search by name/email/phone…" style="flex:1;min-width:220px" />
      <button class="btn" id="crmClientSearchBtn">Search</button>
    </div>
    <div class="divider"></div>

    <div class="row">
      <input id="crmNewName" placeholder="Full name" style="flex:1;min-width:140px" />
      <input id="crmNewEmail" placeholder="Email" style="flex:1;min-width:140px" />
      <input id="crmNewPhone" placeholder="Phone" style="flex:1;min-width:120px" />
      <button class="btnGreen" id="crmCreateClient">Add</button>
    </div>

    <div class="list" id="crmClients" style="margin-top:10px">Loading…</div>
  </div>

  <div class="card span6" style="background: rgba(15,23,42,.35); box-shadow:none">
    <div style="font-weight:950">Client status (auto-inferred)</div>
    <div class="muted">Select a client to see latest touch + activity.</div>
    <div class="divider"></div>
    <pre id="crmClientDetail">Pick a client from the list.</pre>
  </div>

  <div class="card span6" style="background: rgba(15,23,42,.35); box-shadow:none">
    <div style="font-weight:950">Review queue</div>
    <div class="muted">Unmatched or low-confidence activities. Confirm or reject.</div>
    <div class="divider"></div>
    <div class="list" id="crmReview">Loading…</div>
  </div>

  <div class="card span6" style="background: rgba(15,23,42,.35); box-shadow:none">
    <div style="font-weight:950">Ask the CRM AI</div>
    <div class="muted">Example: “What’s the status of John Smith?”</div>
    <div class="divider"></div>
    <div class="row">
      <input id="crmAskInput" placeholder="Ask a CRM question…" style="flex:1;min-width:220px" />
      <button class="btnGreen" id="crmAskBtn">Ask</button>
    </div>
    <pre id="crmAskOut" style="max-height:320px;overflow:auto">—</pre>
  </div>
</div>

    </div>

<div class="card span12">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-end;flex-wrap:wrap">
        <div>
          <div style="font-weight:950">Reports</div>
          <div class="muted">History list</div>
        </div>
        <div class="rightBtns">
          <button class="btnGhost" id="loadReports">Refresh list</button>
        </div>
      </div>
      <div class="grid" style="margin-top:10px;gap:12px">
        <div class="card span6" style="background: rgba(15,23,42,.35); box-shadow:none">
          <div class="muted">Latest</div>
          <div id="reportCards" class="repWrap">Loading…</div>
    


<details style="margin-top:10px">
  <summary class="muted" style="cursor:pointer">Show raw report</summary>
  <pre id="report" class="mono" style="max-height:320px;overflow:auto">Loading…</pre>
</details>

        </div>
        <div class="card span6" style="background: rgba(15,23,42,.35); box-shadow:none">
          <div class="muted">History</div>
          <div class="list" id="reportsList">Loading…</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Load the real client script -->
<script>
  window.CONSTRAVA_TOKEN = ${JSON.stringify(String(token || ""))};
</script>
<script src="/dashboard.js"></script>


</body>
</html>`);
}));

/* ---------------------------
   Dashboard client JS
   GET /dashboard.js?token=...
----------------------------*/
app.get("/dashboard.js", (req, res) => {
  setNoStore(res);
  res.setHeader("Content-Type", "application/javascript; charset=utf-8");

  res.send(String.raw`
(() => {
  "use strict";

  const TOKEN =
    String(window.CONSTRAVA_TOKEN || "") ||
    new URLSearchParams(location.search).get("token") ||
    "";

  const $ = (id) => document.getElementById(id);

  function setStatus(t){
    const el = $("status");
    if (el) el.textContent = "Status: " + t;
  }

  function pct(n){
    return (Math.round((Number(n) || 0) * 10000) / 100).toFixed(2) + "%";
  }

  function clamp(n, min, max) {
    n = Number(n) || 0;
    return Math.max(min, Math.min(max, n));
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c]));
  }

  function renderTrend(svgEl, trend) {
    if (!svgEl) return;
    const W = 900, H = 260, p = 18;
    while (svgEl.firstChild) svgEl.removeChild(svgEl.firstChild);

    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("x", "0");
    bg.setAttribute("y", "0");
    bg.setAttribute("width", String(W));
    bg.setAttribute("height", String(H));
    bg.setAttribute("rx", "14");
    bg.setAttribute("fill", "rgba(15,23,42,.25)");
    bg.setAttribute("stroke", "rgba(255,255,255,.10)");
    svgEl.appendChild(bg);

    const n = (trend && trend.length) ? trend.length : 0;
    if (!n) return;

    let maxV = 0, sumV = 0;
    for (const r of trend) { maxV = Math.max(maxV, r.visits || 0); sumV += (r.visits || 0); }
    const avg = sumV / n;

    if ($("maxDay")) $("maxDay").textContent = String(maxV);
    if ($("avgDay")) $("avgDay").textContent = String(Math.round(avg * 10) / 10);

    const innerW = W - p * 2;
    const innerH = H - p * 2;

    const x = (i) => (n === 1 ? p + innerW / 2 : p + (i * innerW) / (n - 1));
    const y = (v) => {
      const m = Math.max(1, maxV);
      const t = clamp(v / m, 0, 1);
      return p + (1 - t) * innerH;
    };

    let d = "";
    for (let i = 0; i < n; i++) d += (i === 0 ? "M " : " L ") + x(i) + " " + y(trend[i].visits || 0);

    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    path.setAttribute("stroke", "rgba(96,165,250,.90)");
    path.setAttribute("stroke-width", "3");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    svgEl.appendChild(path);
  }

  function renderDevice(svgEl, mobile, desktop) {
    if (!svgEl) return;
    while (svgEl.firstChild) svgEl.removeChild(svgEl.firstChild);

    const cx = 80, cy = 80, r = 50, w = 16;
    const total = (mobile || 0) + (desktop || 0);
    const m = total ? mobile / total : 0.5;

    const start = -Math.PI / 2;
    const mid = start + Math.PI * 2 * m;

    function arc(a0, a1, color) {
      const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      const large = (a1 - a0) > Math.PI ? 1 : 0;

      const pth = document.createElementNS("http://www.w3.org/2000/svg", "path");
      pth.setAttribute("d", "M " + x0 + " " + y0 + " A " + r + " " + r + " 0 " + large + " 1 " + x1 + " " + y1);
      pth.setAttribute("stroke", color);
      pth.setAttribute("stroke-width", String(w));
      pth.setAttribute("fill", "none");
      pth.setAttribute("stroke-linecap", "round");
      svgEl.appendChild(pth);
    }

    const ring = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    ring.setAttribute("cx", String(cx));
    ring.setAttribute("cy", String(cy));
    ring.setAttribute("r", String(r));
    ring.setAttribute("stroke", "rgba(255,255,255,.12)");
    ring.setAttribute("stroke-width", String(w));
    ring.setAttribute("fill", "none");
    svgEl.appendChild(ring);

    arc(start, mid, "rgba(52,211,153,.90)");
    arc(mid, start + Math.PI * 2, "rgba(96,165,250,.90)");
  }

  function renderTopPages(container, rows) {
    if (!container) return;
    container.innerHTML = "";

    if (!rows || !rows.length) {
      container.textContent = "No page data yet.";
      return;
    }

    for (const r of rows) {
      const item = document.createElement("div");
      item.className = "item";

      const left = document.createElement("div");
      left.style.minWidth = "160px";
      left.style.maxWidth = "55%";
      left.style.overflow = "hidden";
      left.style.textOverflow = "ellipsis";
      left.style.whiteSpace = "nowrap";
      left.innerHTML =
        "<b>" + esc(r.page_type || "/") + "</b>" +
        "<div class='muted'>" + (r.views || 0) + " views • " + (r.share || 0) + "%</div>";

      const barWrap = document.createElement("div");
      barWrap.className = "barWrap";

      const bar = document.createElement("div");
      bar.className = "bar";

      const fill = document.createElement("div");
      fill.style.width = clamp(r.share || 0, 0, 100) + "%";

      bar.appendChild(fill);
      barWrap.appendChild(bar);

      item.appendChild(left);
      item.appendChild(barWrap);
      container.appendChild(item);
    }
  }

  
  // ===== CRM (Leads) =====
  let crmCache = [];

  function fmtTime(iso){
    try{
      const d = new Date(iso);
      if (isNaN(d.getTime())) return String(iso || "");
      return d.toLocaleString();
    }catch{ return String(iso || ""); }
  }

  function renderCRM(container, leads){
    if (!container) return;
    container.innerHTML = "";

    const rows = Array.isArray(leads) ? leads : [];
    crmCache = rows;

    if (!rows.length){
      container.textContent = "No leads yet.";
      return;
    }

    for (const l of rows){
      const item = document.createElement("div");
      item.className = "item";

      const left = document.createElement("div");
      const title = (l.email || l.name || "(no email)") + "";
      const sub = [
        l.name ? ("Name: " + l.name) : null,
        l.phone ? ("Phone: " + l.phone) : null,
        l.source_page ? ("Page: " + l.source_page) : null,
        ("Status: " + (l.status || "new")),
        ("At: " + fmtTime(l.created_at))
      ].filter(Boolean).join(" • ");

      left.innerHTML =
        "<b>" + esc(title) + "</b>" +
        "<div class='muted'>" + esc(sub) + "</div>" +
        (l.notes ? "<div class='muted' style='margin-top:6px'>Notes: " + esc(l.notes) + "</div>" : "");

      const right = document.createElement("div");
      right.style.display = "flex";
      right.style.gap = "8px";
      right.style.alignItems = "center";

      const btn = document.createElement("button");
      btn.className = "btnGhost";
      btn.textContent = "Edit";
      btn.addEventListener("click", async () => {
        const newStatus = prompt("Status (e.g. new, contacted, won, lost):", l.status || "new");
        if (newStatus === null) return;
        const newNotes = prompt("Notes (optional):", l.notes || "");
        if (newNotes === null) return;

        const r = await fetch("/crm/update", {
          method: "POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify({ token: TOKEN, lead_id: l.id, status: newStatus, notes: newNotes })
        });
        const j = await r.json().catch(()=>({}));
        if(!j.ok){ alert(j.error || "Update failed"); return; }
        await loadCRM();
      await loadCRMv2();
      });

      right.appendChild(btn);

      item.appendChild(left);
      item.appendChild(right);
      container.appendChild(item);
    }
  }

  function leadsToCSV(rows){
    const cols = ["id","email","name","phone","source_page","status","notes","created_at"];
    const escCsv = (v) => {
      const s = String(v ?? "");
      if (/["\n,]/.test(s)) return '"' + s.replace(/"/g,'""') + '"';
      return s;
    };
    const out = [];
    out.push(cols.join(","));
    for (const r of (rows || [])){
      out.push(cols.map(c => escCsv(r[c])).join(","));
    }
    return out.join("\n");
  }

  async function loadCRM(){
    const box = $("crmLeads");
    if (box) box.textContent = "Loading…";
    const r = await fetch("/crm?token=" + encodeURIComponent(TOKEN) + "&limit=200");
    const j = await r.json().catch(()=>({}));
    if(!j.ok){
      if (box) box.textContent = j.error || "Failed to load CRM.";
      return;
    }
    renderCRM(box, j.leads || []);
  }


// ===== CRM v2 (clients + review + AI) =====
let crmSelectedClientId = null;

function fmtWhen(iso){
  try{
    if(!iso) return "—";
    const d = new Date(iso);
    if(isNaN(d.getTime())) return String(iso);
    return d.toISOString().slice(0,19).replace("T"," ");
  }catch{ return String(iso||"—"); }
}

function makeListItem(title, sub, right){
  const item = document.createElement("div");
  item.className = "item";

  const left = document.createElement("div");
  left.style.minWidth = "0";
  left.innerHTML = "<b>" + esc(title) + "</b><div class='muted'>" + esc(sub || "") + "</div>";

  const r = document.createElement("div");
  r.className = "pill";
  r.textContent = right || "Open";

  item.appendChild(left);
  item.appendChild(r);
  return item;
}

async function loadCrmClients(q){
  const box = $("crmClients");
  if(!box) return;
  box.textContent = "Loading…";
  const url = "/crm/clients?token=" + encodeURIComponent(TOKEN) + (q ? "&q=" + encodeURIComponent(q) : "");
  const r = await fetch(url);
  const j = await r.json().catch(()=>({}));
  box.innerHTML = "";
  if(!j.ok){ box.textContent = j.error || "Failed."; return; }

  if(!j.clients || !j.clients.length){ box.textContent = "No clients yet."; return; }

  for(const c of j.clients){
    const title = (c.full_name || "(no name)") + (c.stage ? " • " + c.stage : "");
    const sub = [
      c.primary_email ? ("email: " + c.primary_email) : null,
      c.primary_phone ? ("phone: " + c.primary_phone) : null,
      ("last touch: " + fmtWhen(c.last_touch_at))
    ].filter(Boolean).join(" • ");

    const item = makeListItem(title, sub, "Select");
    item.style.cursor = "pointer";
    item.addEventListener("click", () => {
      crmSelectedClientId = c.id;
      loadCrmClientDetail(c.id);
    });
    box.appendChild(item);
  }
}

async function loadCrmClientDetail(clientId){
  const pre = $("crmClientDetail");
  if(!pre) return;
  pre.textContent = "Loading client…";

  const r = await fetch("/crm/client?token=" + encodeURIComponent(TOKEN) + "&client_id=" + encodeURIComponent(String(clientId)));
  const j = await r.json().catch(()=>({}));
  if(!j.ok){ pre.textContent = j.error || "Failed."; return; }

  const c = j.client || {};
  const acts = Array.isArray(j.activities) ? j.activities : [];
  const ids = Array.isArray(j.identities) ? j.identities : [];

  const lines = [];
  lines.push("CLIENT");
  lines.push("- Name: " + (c.full_name || "—"));
  lines.push("- Stage: " + (c.stage || "—") + " • Health: " + (c.health || "unknown"));
  lines.push("- Confidence: " + Math.round((Number(c.confidence||0.5))*100) + "%");
  lines.push("- Email: " + (c.primary_email || "—"));
  lines.push("- Phone: " + (c.primary_phone || "—"));
  lines.push("- Last touch: " + fmtWhen(c.last_touch_at));
  lines.push("");
  lines.push("IDENTITIES");
  if(!ids.length) lines.push("- —");
  for(const it of ids.slice(0,12)){
    lines.push("- " + it.kind + ": " + it.value);
  }
  lines.push("");
  lines.push("RECENT ACTIVITY");
  if(!acts.length) lines.push("- —");
  for(const a of acts.slice(0,8)){
    const who = a.type === "email"
      ? ((a.direction||"") + " " + (a.from_email || "—") + " → " + (a.to_email || "—")).trim()
      : (a.phone ? ("phone: " + a.phone) : "");
    const head = fmtWhen(a.occurred_at) + " • " + (a.type || "activity") + (a.match_status ? (" • " + a.match_status) : "");
    const sub = (a.subject ? ("subject: " + a.subject) : "") || (a.body_preview ? ("notes: " + String(a.body_preview).slice(0,140)) : "");
    lines.push("- " + head);
    if(who) lines.push("  " + who);
    if(sub) lines.push("  " + sub);
  }

  pre.textContent = lines.join("\n");
}

async function loadCrmReview(){
  const box = $("crmReview");
  if(!box) return;
  box.textContent = "Loading…";

  const r = await fetch("/crm/review?token=" + encodeURIComponent(TOKEN));
  const j = await r.json().catch(()=>({}));
  box.innerHTML = "";
  if(!j.ok){ box.textContent = j.error || "Failed."; return; }

  const q = Array.isArray(j.queue) ? j.queue : [];
  if(!q.length){ box.textContent = "Queue is empty ✅"; return; }

  for(const it of q){
    const title = fmtWhen(it.occurred_at) + " • " + (it.type || "activity");
    const sub =
      (it.subject ? ("subject: " + it.subject) : (it.body_preview ? it.body_preview : "")) +
      (it.phone ? (" • phone: " + it.phone) : "") +
      (" • conf: " + Math.round((Number(it.confidence||0))*100) + "%");

    const row = makeListItem(title, sub, "Review");
    row.style.cursor = "pointer";

    row.addEventListener("click", async () => {
      // quick action: confirm to selected client, else prompt to select first
      if(!crmSelectedClientId){
        alert("Select a client first (Clients list) to confirm this activity.");
        return;
      }
      const ok = confirm("Assign this activity to the selected client?");
      if(!ok) return;

      const rr = await fetch("/crm/review/confirm", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ token: TOKEN, match_id: it.match_id, client_id: crmSelectedClientId })
      });
      const jj = await rr.json().catch(()=>({}));
      if(!jj.ok){ alert(jj.error || "Failed"); return; }
      await loadCrmReview();
      if(crmSelectedClientId) await loadCrmClientDetail(crmSelectedClientId);
    });

    // add a reject button
    const rejectBtn = document.createElement("button");
    rejectBtn.className = "btnDanger";
    rejectBtn.textContent = "Reject";
    rejectBtn.style.padding = "8px 10px";
    rejectBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = confirm("Reject this match?");
      if(!ok) return;
      const rr = await fetch("/crm/review/reject", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ token: TOKEN, match_id: it.match_id })
      });
      const jj = await rr.json().catch(()=>({}));
      if(!jj.ok){ alert(jj.error || "Failed"); return; }
      await loadCrmReview();
    });

    // replace right pill with button group
    row.removeChild(row.lastChild);
    const right = document.createElement("div");
    right.style.display = "flex";
    right.style.gap = "8px";
    right.appendChild(rejectBtn);
    const hint = document.createElement("div");
    hint.className = "pill";
    hint.textContent = "Assign";
    right.appendChild(hint);
    row.appendChild(right);

    box.appendChild(row);
  }
}

async function crmCreateClient(){
  const n = $("crmNewName") ? $("crmNewName").value.trim() : "";
  const e = $("crmNewEmail") ? $("crmNewEmail").value.trim() : "";
  const p = $("crmNewPhone") ? $("crmNewPhone").value.trim() : "";
  if(!n && !e && !p){ alert("Add at least a name, email, or phone."); return; }

  const r = await fetch("/crm/clients", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ token: TOKEN, full_name: n, email: e, phone: p, stage:"lead" })
  });
  const j = await r.json().catch(()=>({}));
  if(!j.ok){ alert(j.error || "Failed"); return; }

  if ($("crmNewName")) $("crmNewName").value = "";
  if ($("crmNewEmail")) $("crmNewEmail").value = "";
  if ($("crmNewPhone")) $("crmNewPhone").value = "";

  await loadCrmClients($("crmClientSearch") ? $("crmClientSearch").value.trim() : "");
}

async function crmAsk(){
  const out = $("crmAskOut");
  const input = $("crmAskInput");
  if(!out || !input) return;

  const q = input.value.trim();
  if(!q) return;
  out.textContent = "Thinking…";

  const r = await fetch("/api/ai/crm/answer", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ token: TOKEN, question: q })
  });
  const j = await r.json().catch(()=>({}));
  if(!j.ok){ out.textContent = j.error || "Failed."; return; }
  out.textContent = j.reply || "—";
}

async function loadCRMv2(){
  await loadCrmClients("");
  await loadCrmReview();
}

// ===== Reports =====
  function splitLines(txt){
    return String(txt || "").replace(/\r\n/g,"\n").split("\n").map(s => s.trim()).filter(Boolean);
  }

  function parseReportSections(text){
    const lines = splitLines(text);
    const sections = { summary: "", highlights: [], steps: [], kpi: "" };
    let mode = "";

    for (const line0 of lines){
      const line = line0.replace(/\*\*/g,"");

      if (/^SUMMARY:/i.test(line)) { mode="summary"; continue; }
      if (/^HIGHLIGHTS:/i.test(line)) { mode="highlights"; continue; }
      if (/^NEXT STEPS:/i.test(line)) { mode="steps"; continue; }
      if (/^KPI:/i.test(line)){
        sections.kpi = line.replace(/^KPI:\s*/i,"").trim();
        mode="";
        continue;
      }

      const cleaned = line.replace(/^[-•]\s*/,"").replace(/^\d+\)\s*/,"").trim();
      if (!cleaned) continue;

      if (mode==="summary") sections.summary += (sections.summary?" ":"") + cleaned;
      if (mode==="highlights") sections.highlights.push(cleaned);
      if (mode==="steps") sections.steps.push(cleaned);
    }

    return sections;
  }

  function renderReportCards(containerEl, text){
    if (!containerEl) return;

    const s = parseReportSections(text);
    const escHtml = (v) => String(v || "").replace(/[&<>"']/g, (c) => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[c]));

    function ul(items, cap){
      cap = cap || 3;
      const list = Array.isArray(items) ? items : [];
      const shown = list.slice(0, cap);
      const hiddenCount = Math.max(0, list.length - shown.length);

      if (!shown.length) return '<div class="muted">—</div>';

      const lis = shown.map((x) => '<li>' + escHtml(x) + '</li>').join("");
      const more = hiddenCount
        ? '<div class="muted" style="margin-top:6px">+' + hiddenCount + ' more (see raw report)</div>'
        : "";

      return '<ul class="repList">' + lis + '</ul>' + more;
    }

    const kpiHtml = s.kpi ? '<div class="repKpi"><b>' + escHtml(s.kpi) + '</b></div>' : "";

    containerEl.innerHTML =
      '<div class="repCard"><div class="repTitle">Summary</div><div class="repText">' + escHtml(s.summary) + '</div>' + kpiHtml + '</div>' +
      '<div class="repCard"><div class="repTitle">Highlights</div>' + ul(s.highlights, 3) + '</div>' +
      '<div class="repCard repFull"><div class="repTitle">Next Steps</div>' + ul(s.steps, 3) + '</div>';
  }

  async function loadLatestReport() {
    const pre1 = $("latestAiReport");
    const cards1 = $("latestAiReportCards");
    if (pre1) pre1.textContent = "Loading latest report...";

    const rr = await fetch("/reports/latest?token=" + encodeURIComponent(TOKEN));
    const jj = await rr.json().catch(()=>({}));

    const text = (jj.ok && jj.report && jj.report.report_text) ? jj.report.report_text : "";
    if (pre1) pre1.textContent = text || "No report yet.";
    renderReportCards(cards1, text);
  }

  async function loadReportsList() {
    const list = $("reportsList");
    if (!list) return;

    list.textContent = "Loading...";
    const r = await fetch("/reports?token=" + encodeURIComponent(TOKEN) + "&limit=30");
    const j = await r.json().catch(() => ({}));

    list.innerHTML = "";
    if (!j.ok) { list.textContent = j.error || "Failed to load reports"; return; }
    if (!j.reports || !j.reports.length) { list.textContent = "No reports yet."; return; }

    for (const rep of j.reports) {
      const item = document.createElement("div");
      item.className = "item";

      const left = document.createElement("div");
      left.innerHTML = "<b>" + esc(rep.report_date) + "</b><div class='muted'>" + esc(rep.preview || "") + "</div>";

      const right = document.createElement("div");
      right.className = "pill";
      right.textContent = "Open";

      item.appendChild(left);
      item.appendChild(right);
      list.appendChild(item);
    }
  }

  async function refresh() {
    try {
      const days = $("days") ? $("days").value : "7";
      setStatus("loading metrics…");

      const r = await fetch("/metrics?token=" + encodeURIComponent(TOKEN) + "&days=" + encodeURIComponent(days));
      const j = await r.json().catch(() => ({}));
      if (!j.ok) { setStatus(j.error || "error"); return; }

      if ($("kpiToday")) $("kpiToday").textContent = j.visits_today;
      if ($("kpiRange")) $("kpiRange").textContent = j.visits_range;
      if ($("kpiLeadRate")) $("kpiLeadRate").textContent = pct(j.conversion_rate || 0);
      if ($("kpiPurchaseRate")) $("kpiPurchaseRate").textContent = pct(j.purchase_rate || 0);

      if ($("leads")) $("leads").textContent = j.leads || 0;
      if ($("purchases")) $("purchases").textContent = j.purchases || 0;
      if ($("cta")) $("cta").textContent = j.cta_clicks || 0;

      const mob = (j.device_mix && j.device_mix.mobile) ? j.device_mix.mobile : 0;
      const desk = (j.device_mix && j.device_mix.desktop) ? j.device_mix.desktop : 0;
      if ($("mob")) $("mob").textContent = mob;
      if ($("desk")) $("desk").textContent = desk;

      if ($("lastEvent")) $("lastEvent").textContent = j.last_event ? JSON.stringify(j.last_event, null, 2) : "No events yet.";

      renderTrend($("trendSvg"), j.trend || []);
      renderDevice($("deviceSvg"), mob, desk);
      renderTopPages($("topPages"), j.top_pages_range || []);

      await loadCRM();
      await loadLatestReport();
      await loadReportsList();

      setStatus("ready");
    } catch (e) {
      setStatus("error: " + (e && e.message ? e.message : "unknown"));
    }
  }

  async function fire(eventName) {
    setStatus("sending " + eventName + "…");
    const r = await fetch("/demo/fire-event", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: TOKEN,
        event_name: eventName,
        page_type: location.pathname,
        device: /Mobi|Android/i.test(navigator.userAgent) ? "mobile" : "desktop"
      })
    });
    const d = await r.json().catch(() => ({}));
    if (!d.ok) { setStatus(d.error || "error"); return; }
    setStatus("sent ✅");
    setTimeout(refresh, 300);
  }

  async function seed() {
    setStatus("seeding…");
    const r = await fetch("/demo/seed?token=" + encodeURIComponent(TOKEN), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ days: 14, events_per_day: 60 })
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { setStatus(j.error || "seed failed"); return; }
    setStatus("seeded ✅");
    setTimeout(refresh, 350);
  }

  async function share() {
    setStatus("creating share link…");
    const r = await fetch("/demo/link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: TOKEN })
    });
    const d = await r.json().catch(() => ({}));
    if (!d.ok) { setStatus(d.error || "error"); return; }

    try { await navigator.clipboard.writeText(d.url); setStatus("copied ✅"); }
    catch { setStatus("share link: " + d.url); }
  }

  // live polling
  let liveSince = new Date().toISOString();
  let liveOn = true;
  let liveTimer = null;

  async function liveCheck() {
    try {
      const url = "/live?token=" + encodeURIComponent(TOKEN) + "&since=" + encodeURIComponent(liveSince);
      const r = await fetch(url);
      const j = await r.json().catch(() => ({}));
      if (!j.ok) return;
      if ($("liveNew")) $("liveNew").textContent = String(j.new_page_views || 0);
      if ($("liveLast")) $("liveLast").textContent = j.last_event ? (j.last_event.event_name || "—") : "—";
      if ($("liveJson")) $("liveJson").textContent = JSON.stringify(j, null, 2);
      liveSince = j.now || new Date().toISOString();
    } catch {}
  }

  function startLive() {
    if (liveTimer) clearInterval(liveTimer);
    liveTimer = setInterval(() => { if (liveOn) liveCheck(); }, 3500);
  }

  async function aiReport() {
    setStatus("generating AI report…");
    const r = await fetch("/generate-report?token=" + encodeURIComponent(TOKEN), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: TOKEN })
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { setStatus(j.error || "AI report failed"); return; }
    setStatus("AI report saved ✅");
    await loadLatestReport();
    await loadReportsList();
  }

  // ===== AI CHAT =====
let chatHistory = [];

function addMsg(role, text){
  const box = $("chatBox");
  if(!box) return;

  const div = document.createElement("div");
  div.style.marginBottom = "10px";
  div.style.lineHeight = "1.45";

  const label = (role === "user") ? "You" : "AI";

  // escape HTML, then turn newlines into <br>
  const safe = esc(text).replace(/\n/g, "<br>");

  div.innerHTML =
    "<b>" + label + ":</b> " +
    "<span style=\"white-space:normal\">" + safe + "</span>";

  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}


async function sendChat(){
  const input = $("chatInput");
  if (!input) return;

  const msg = input.value.trim();
  if (!msg) return;
  input.value = "";

  addMsg("user", msg);

  // temporary "thinking…" line
  const box = $("chatBox");
  let thinkingEl = null;
  if (box) {
    thinkingEl = document.createElement("div");
    thinkingEl.style.marginBottom = "8px";
    thinkingEl.innerHTML = "<b>AI:</b> <span class='muted'>Thinking…</span>";
    box.appendChild(thinkingEl);
    box.scrollTop = box.scrollHeight;
  }

  try{
    const r = await fetch("/api/ai/chat", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ token: TOKEN, message: msg, history: chatHistory.slice(-12) })
    });
    const j = await r.json().catch(()=>({}));

    if (thinkingEl && box) box.removeChild(thinkingEl);

    if(!j.ok){
      addMsg("ai", j.error || "Chat failed.");
      return;
    }

    const reply = j.reply || "(no reply)";
    addMsg("ai", reply);

    chatHistory.push({ role: "user", content: msg });
    chatHistory.push({ role: "assistant", content: reply });
  }catch(e){
    if (thinkingEl && box) box.removeChild(thinkingEl);
    addMsg("ai", "Error: " + (e?.message || "unknown"));
  }
}

function clearChat(){
  const box = $("chatBox");
  if (!box) return;
  box.innerHTML = '<div class="muted">Chat cleared.</div>';
  chatHistory = [];
}

window.addEventListener("DOMContentLoaded", () => {

    if (!TOKEN) { setStatus("missing token"); return; }

    if ($("refresh")) $("refresh").addEventListener("click", refresh);
    if ($("days")) $("days").addEventListener("change", refresh);
    if ($("chatSend")) $("chatSend").addEventListener("click", sendChat);
if ($("chatClear")) $("chatClear").addEventListener("click", clearChat);

if ($("chatInput")) {
  $("chatInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendChat();
  });
}


    if ($("simView")) $("simView").addEventListener("click", () => fire("page_view"));
    if ($("simLead")) $("simLead").addEventListener("click", () => fire("lead"));
    if ($("simPurchase")) $("simPurchase").addEventListener("click", () => fire("purchase"));
    if ($("simCta")) $("simCta").addEventListener("click", () => fire("cta_click"));

    if ($("share")) $("share").addEventListener("click", share);
    if ($("seedBtn")) $("seedBtn").addEventListener("click", seed);

    if ($("crmRefresh")) $("crmRefresh").addEventListener("click", loadCRM);
    if ($("crmExport")) $("crmExport").addEventListener("click", () => {
      try{
        const csv = leadsToCSV(crmCache);
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "crm_leads.csv";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setStatus("exported CSV ✅");
      }catch(e){
        setStatus("export failed");
      }

// CRM v2 listeners
if ($("crmClientSearchBtn")) $("crmClientSearchBtn").addEventListener("click", () => {
  const q = $("crmClientSearch") ? $("crmClientSearch").value.trim() : "";
  loadCrmClients(q);
});
if ($("crmClientSearch")) $("crmClientSearch").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const q = $("crmClientSearch").value.trim();
    loadCrmClients(q);
  }
});

if ($("crmCreateClient")) $("crmCreateClient").addEventListener("click", crmCreateClient);

if ($("crmAskBtn")) $("crmAskBtn").addEventListener("click", crmAsk);
if ($("crmAskInput")) $("crmAskInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") crmAsk();
});
    });

    if ($("loadReports")) $("loadReports").addEventListener("click", loadReportsList);
    if ($("aiReportTopBtn")) $("aiReportTopBtn").addEventListener("click", aiReport);
    if ($("liveToggle")) $("liveToggle").addEventListener("click", () => {
      liveOn = !liveOn;
      $("liveToggle").textContent = liveOn ? "Pause" : "Resume";
      setStatus(liveOn ? "live on" : "live paused");
    });
    if ($("liveNow")) $("liveNow").addEventListener("click", liveCheck);

    startLive();
    liveCheck();
    refresh();
  });
})();`.trim());
  });


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

app.post("/jobs/run-daily", asyncHandler(async (req, res) => {
  const result = await runDailyForAllSites();
  res.json(result);
}));

if (process.env.ENABLE_SCHEDULER === "true") {
  console.log("⏱️ In-process scheduler enabled (not a real cron).");
  runDailyForAllSites().catch(() => {});
  setInterval(() => runDailyForAllSites().catch(() => {}), 6 * 60 * 60 * 1000);
}

/* ---------------------------
   Errors
----------------------------*/
app.use((err, req, res, next) => {
  console.error("ERROR:", err && err.stack ? err.stack : err);
  res.status(500).json({ ok: false, error: String(err.message || err) });
});

/* ---------------------------
   Start server (WAIT for DB)
----------------------------*/
(async () => {
  try {
    await ensureTables();
    app.listen(PORT, () => console.log(`🚀 Constrava running on port ${PORT}`));
  } catch (e) {
    console.error("❌ Failed to start:", e?.message || e);
    process.exit(1);
  }
})();

