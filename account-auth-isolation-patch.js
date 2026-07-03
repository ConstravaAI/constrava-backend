import fs from "fs";

const SERVER_FILE = "server.js";
const MARKER = "// === Constrava account auth + isolation patch ===";

function writeIfChanged(file, next, label) {
  const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  if (current === next) {
    console.log(`[account-auth-isolation-patch] ${label} already current.`);
    return false;
  }
  fs.writeFileSync(file, next);
  console.log(`[account-auth-isolation-patch] Updated ${label}.`);
  return true;
}

function patchServer() {
  if (!fs.existsSync(SERVER_FILE)) {
    console.warn("[account-auth-isolation-patch] server.js not found; skipping.");
    return;
  }

  let text = fs.readFileSync(SERVER_FILE, "utf8");

  if (!text.includes("scryptCallback")) {
    text = text.replace(
      'import { randomBytes } from "crypto";',
      'import { randomBytes, createHash, scrypt as scryptCallback, timingSafeEqual } from "crypto";\nimport { promisify } from "util";'
    );
  }

  if (!text.includes('if (["/dashboard.html", "/crm.html"].includes(req.path)) return res.redirect("/dashboard");')) {
    text = text.replace(
      'app.use(express.static(__dirname));',
      'app.use((req, res, next) => { if (["/dashboard.html", "/crm.html"].includes(req.path)) return res.redirect("/dashboard"); next(); });\napp.use(express.static(__dirname));'
    );
  }

  const authBlock = String.raw`
${MARKER}
const scrypt = promisify(scryptCallback);
const AUTH_COOKIE = "cx_session";
const AUTH_SESSION_DAYS = 14;
const AUTH_SESSION_MS = AUTH_SESSION_DAYS * 24 * 60 * 60 * 1000;
const DEFAULT_DEV_EMAIL = process.env.DEV_ACCOUNT_EMAIL || process.env.ADMIN_EMAIL || TO_EMAIL || "constrava@constravaai.com";
const DEFAULT_DEV_NAME = process.env.DEV_ACCOUNT_NAME || "Constrava Developer";
const BUILTIN_DEV_SALT = process.env.DEV_ACCOUNT_PASSWORD ? "" : "669fba61c6e558b86d5361d23c80145c";
const BUILTIN_DEV_HASH = process.env.DEV_ACCOUNT_PASSWORD ? "" : "JU8vFf+I3Z+2eqapKg7unKBnWYGO737M8NdOfnzTYzfZGsJByMxEyTi/aeSnropWyygxv827ImHpy3GDDkFUbg==";
const memoryAccounts = new Map();
const memoryAccountsByEmail = new Map();
const memorySessions = new Map();
const memorySettings = new Map();
const memoryAccountRecords = new Map();
let authSchemaReady = null;

function normEmail(email) { return String(email || "").trim().toLowerCase(); }
function stableId(prefix, value) { return prefix + "_" + createHash("sha256").update(String(value || prefix)).digest("hex").slice(0, 24); }
function tokenHash(token) { return createHash("sha256").update(String(token || "")).digest("hex"); }
function publicAccount(account) { return account ? { id: account.id, email: account.email, display_name: account.display_name, role: account.role, site_id: account.site_id, dashboard_token: account.dashboard_token } : null; }
function defaultSettings() { return { theme: "constrava-green", privacy: "account-only", notifications: true, dashboardRange: 7, createdBy: "account-auth" }; }
function accountDashboardToken(email) { return stableId("cx_dash", normEmail(email)); }
function accountSiteId(email) { return accountDashboardToken(email); }
function parseCookies(req) {
  const out = {};
  const raw = String(req.get("cookie") || "");
  raw.split(";").forEach((part) => {
    const index = part.indexOf("=");
    if (index < 0) return;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) out[key] = decodeURIComponent(value || "");
  });
  return out;
}
function setAuthCookie(req, res, token) {
  const secure = req.secure || String(req.get("x-forwarded-proto") || "").includes("https");
  res.setHeader("Set-Cookie", AUTH_COOKIE + "=" + encodeURIComponent(token) + "; HttpOnly; Path=/; SameSite=Lax; Max-Age=" + Math.floor(AUTH_SESSION_MS / 1000) + (secure ? "; Secure" : ""));
}
function clearAuthCookie(req, res) {
  const secure = req.secure || String(req.get("x-forwarded-proto") || "").includes("https");
  res.setHeader("Set-Cookie", AUTH_COOKIE + "=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0" + (secure ? "; Secure" : ""));
}
function wantsJson(req) { return req.path.startsWith("/api/") || req.path.endsWith(".json") || String(req.get("accept") || "").includes("application/json"); }
function safeAuthReturnTo(value) {
  const clean = String(value || "/dashboard");
  if (!clean.startsWith("/")) return "/dashboard";
  if (clean.startsWith("//")) return "/dashboard";
  if (clean.startsWith("/signin") || clean.startsWith("/auth/")) return "/dashboard";
  return clean;
}
async function passwordHash(password, salt = randomBytes(16).toString("hex")) {
  const hash = (await scrypt(String(password || ""), salt, 64)).toString("base64");
  return { salt, hash };
}
async function passwordMatches(password, salt, expectedHash) {
  try {
    const actual = await scrypt(String(password || ""), String(salt || ""), 64);
    const expected = Buffer.from(String(expectedHash || ""), "base64");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}
async function developerCredentials() {
  const email = normEmail(DEFAULT_DEV_EMAIL);
  if (!email) return null;
  if (process.env.DEV_ACCOUNT_PASSWORD) {
    const hashed = await passwordHash(process.env.DEV_ACCOUNT_PASSWORD);
    return { email, display_name: DEFAULT_DEV_NAME, role: "developer", salt: hashed.salt, password_hash: hashed.hash };
  }
  return { email, display_name: DEFAULT_DEV_NAME, role: "developer", salt: BUILTIN_DEV_SALT, password_hash: BUILTIN_DEV_HASH };
}
function rememberMemoryAccount(account) {
  memoryAccounts.set(account.id, account);
  memoryAccountsByEmail.set(normEmail(account.email), account.id);
  if (!memorySettings.has(account.id)) memorySettings.set(account.id, defaultSettings());
  if (!memoryAccountRecords.has(account.id)) memoryAccountRecords.set(account.id, []);
}
async function ensureAuthSchema() {
  if (authSchemaReady) return authSchemaReady;
  authSchemaReady = (async () => {
    const dev = await developerCredentials();
    if (!hasDb()) {
      if (dev) rememberMemoryAccount({ id: stableId("acct", dev.email), email: dev.email, display_name: dev.display_name, role: dev.role, salt: dev.salt, password_hash: dev.password_hash, site_id: accountSiteId(dev.email), dashboard_token: accountDashboardToken(dev.email), created_at: new Date().toISOString() });
      return true;
    }
    await db().query("CREATE TABLE IF NOT EXISTS app_accounts (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', salt TEXT NOT NULL, password_hash TEXT NOT NULL, site_id TEXT UNIQUE NOT NULL, dashboard_token TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    await db().query("CREATE TABLE IF NOT EXISTS app_sessions (token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES app_accounts(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), user_agent TEXT, ip TEXT)");
    await db().query("CREATE TABLE IF NOT EXISTS app_settings (account_id TEXT PRIMARY KEY REFERENCES app_accounts(id) ON DELETE CASCADE, settings JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    await db().query("CREATE TABLE IF NOT EXISTS app_records (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES app_accounts(id) ON DELETE CASCADE, record_type TEXT NOT NULL DEFAULT 'record', title TEXT NOT NULL DEFAULT 'Untitled record', status TEXT NOT NULL DEFAULT 'New', payload JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    await db().query("CREATE INDEX IF NOT EXISTS idx_app_sessions_account ON app_sessions(account_id)");
    await db().query("CREATE INDEX IF NOT EXISTS idx_app_records_account ON app_records(account_id, updated_at DESC)");
    if (dev) {
      const account = { id: stableId("acct", dev.email), email: dev.email, display_name: dev.display_name, role: dev.role, salt: dev.salt, password_hash: dev.password_hash, site_id: accountSiteId(dev.email), dashboard_token: accountDashboardToken(dev.email) };
      await db().query("INSERT INTO app_accounts (id,email,display_name,role,salt,password_hash,site_id,dashboard_token) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (email) DO UPDATE SET display_name=EXCLUDED.display_name, role=EXCLUDED.role, salt=EXCLUDED.salt, password_hash=EXCLUDED.password_hash, site_id=EXCLUDED.site_id, dashboard_token=EXCLUDED.dashboard_token, updated_at=NOW()", [account.id, account.email, account.display_name, account.role, account.salt, account.password_hash, account.site_id, account.dashboard_token]);
      await db().query("INSERT INTO app_settings (account_id, settings) VALUES ($1, $2::jsonb) ON CONFLICT (account_id) DO NOTHING", [account.id, JSON.stringify(defaultSettings())]);
    }
    await db().query("DELETE FROM app_sessions WHERE expires_at < NOW()");
    return true;
  })().catch((error) => { authSchemaReady = null; throw error; });
  return authSchemaReady;
}
async function findAccountByEmail(email) {
  await ensureAuthSchema();
  const clean = normEmail(email);
  if (!clean) return null;
  if (!hasDb()) {
    const id = memoryAccountsByEmail.get(clean);
    return id ? memoryAccounts.get(id) : null;
  }
  const result = await db().query("SELECT * FROM app_accounts WHERE email=$1 LIMIT 1", [clean]);
  return result.rows[0] || null;
}
async function findAccountById(id) {
  await ensureAuthSchema();
  if (!id) return null;
  if (!hasDb()) return memoryAccounts.get(String(id)) || null;
  const result = await db().query("SELECT * FROM app_accounts WHERE id=$1 LIMIT 1", [String(id)]);
  return result.rows[0] || null;
}
async function createAccountSession(account, req, res) {
  await ensureAuthSchema();
  const token = makeToken("sess") + randomBytes(16).toString("hex");
  const hash = tokenHash(token);
  const expiresAt = new Date(Date.now() + AUTH_SESSION_MS);
  if (hasDb()) {
    await db().query("INSERT INTO app_sessions (token_hash, account_id, expires_at, user_agent, ip) VALUES ($1,$2,$3,$4,$5)", [hash, account.id, expiresAt, String(req.get("user-agent") || ""), req.ip || ""]);
  } else {
    memorySessions.set(hash, { account_id: account.id, expires_at: expiresAt.toISOString() });
  }
  setAuthCookie(req, res, token);
}
async function getAuthAccount(req) {
  if (req.account) return req.account;
  await ensureAuthSchema();
  const raw = parseCookies(req)[AUTH_COOKIE];
  if (!raw) return null;
  const hash = tokenHash(raw);
  if (hasDb()) {
    const result = await db().query("SELECT a.* FROM app_sessions s JOIN app_accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at > NOW() LIMIT 1", [hash]);
    if (!result.rows[0]) return null;
    db().query("UPDATE app_sessions SET last_seen_at=NOW() WHERE token_hash=$1", [hash]).catch(() => {});
    req.account = result.rows[0];
    return req.account;
  }
  const session = memorySessions.get(hash);
  if (!session || new Date(session.expires_at).getTime() < Date.now()) { memorySessions.delete(hash); return null; }
  req.account = await findAccountById(session.account_id);
  return req.account;
}
async function destroyAccountSession(req, res) {
  await ensureAuthSchema();
  const raw = parseCookies(req)[AUTH_COOKIE];
  if (raw) {
    const hash = tokenHash(raw);
    if (hasDb()) await db().query("DELETE FROM app_sessions WHERE token_hash=$1", [hash]);
    else memorySessions.delete(hash);
  }
  clearAuthCookie(req, res);
}
async function getAccountSettings(account) {
  await ensureAuthSchema();
  if (!account) return defaultSettings();
  if (!hasDb()) return memorySettings.get(account.id) || defaultSettings();
  const result = await db().query("SELECT settings FROM app_settings WHERE account_id=$1 LIMIT 1", [account.id]);
  if (result.rows[0]) return result.rows[0].settings || defaultSettings();
  await db().query("INSERT INTO app_settings (account_id, settings) VALUES ($1, $2::jsonb) ON CONFLICT (account_id) DO NOTHING", [account.id, JSON.stringify(defaultSettings())]);
  return defaultSettings();
}
async function saveAccountSettings(account, settings) {
  await ensureAuthSchema();
  const clean = { ...defaultSettings(), ...(settings && typeof settings === "object" ? settings : {}) };
  if (!hasDb()) { memorySettings.set(account.id, clean); return clean; }
  const result = await db().query("INSERT INTO app_settings (account_id, settings, updated_at) VALUES ($1, $2::jsonb, NOW()) ON CONFLICT (account_id) DO UPDATE SET settings=EXCLUDED.settings, updated_at=NOW() RETURNING settings", [account.id, JSON.stringify(clean)]);
  return result.rows[0]?.settings || clean;
}
function normalizeAccountRecord(row) {
  const payload = row.payload && typeof row.payload === "object" ? row.payload : {};
  return { ...payload, id: row.id, record_id: row.id, record_type: row.record_type || payload.record_type || "record", type: row.record_type || payload.type || "record", title: row.title || payload.title || payload.name || "Untitled record", name: payload.name || row.title || payload.title || "Untitled record", status: row.status || payload.status || "New", created_at: row.created_at, updated_at: row.updated_at };
}
async function listAccountRecords(account) {
  await ensureAuthSchema();
  if (!account) return [];
  if (!hasDb()) return (memoryAccountRecords.get(account.id) || []).map(normalizeAccountRecord);
  const result = await db().query("SELECT * FROM app_records WHERE account_id=$1 ORDER BY updated_at DESC LIMIT 1000", [account.id]);
  return result.rows.map(normalizeAccountRecord);
}
async function upsertAccountRecord(account, input = {}, id = "") {
  await ensureAuthSchema();
  const now = new Date().toISOString();
  const record = { ...(input && typeof input === "object" ? input : {}) };
  const recordId = String(id || record.id || record.record_id || makeToken("rec"));
  const recordType = String(record.record_type || record.type || "record");
  const title = String(record.title || record.name || record.company || record.email || "Untitled record");
  const status = String(record.status || record.stage || "New");
  record.id = recordId;
  record.record_id = recordId;
  record.record_type = recordType;
  record.title = title;
  record.name = record.name || title;
  record.status = status;
  if (!hasDb()) {
    const list = memoryAccountRecords.get(account.id) || [];
    const filtered = list.filter((r) => r.id !== recordId);
    filtered.unshift({ id: recordId, account_id: account.id, record_type: recordType, title, status, payload: record, created_at: record.created_at || now, updated_at: now });
    memoryAccountRecords.set(account.id, filtered);
    return normalizeAccountRecord(filtered[0]);
  }
  const result = await db().query("INSERT INTO app_records (id,account_id,record_type,title,status,payload) VALUES ($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT (id) DO UPDATE SET record_type=EXCLUDED.record_type, title=EXCLUDED.title, status=EXCLUDED.status, payload=EXCLUDED.payload, updated_at=NOW() WHERE app_records.account_id=EXCLUDED.account_id RETURNING *", [recordId, account.id, recordType, title, status, JSON.stringify(record)]);
  return result.rows[0] ? normalizeAccountRecord(result.rows[0]) : null;
}
async function deleteAccountRecord(account, id) {
  await ensureAuthSchema();
  const recordId = String(id || "");
  if (!recordId) return false;
  if (!hasDb()) {
    const list = memoryAccountRecords.get(account.id) || [];
    memoryAccountRecords.set(account.id, list.filter((r) => r.id !== recordId));
    return true;
  }
  const result = await db().query("DELETE FROM app_records WHERE id=$1 AND account_id=$2", [recordId, account.id]);
  return result.rowCount > 0;
}
function privateAppPath(pathname) {
  return pathname === "/sites" || pathname === "/crm" || pathname.startsWith("/crm/") || pathname === "/dashboard" || pathname.startsWith("/dashboard/") || pathname === "/api/dashboard" || pathname === "/reports/latest" || pathname === "/live" || pathname.startsWith("/api/google/forms") || pathname.startsWith("/auth/google/forms");
}
`;

  if (!text.includes(MARKER)) {
    text = text.replace('const GOOGLE_FORM_SCOPES = ["openid", "email", "profile"];', 'const GOOGLE_FORM_SCOPES = ["openid", "email", "profile"];\n' + authBlock);
  }

  const authRoutes = String.raw`
app.get("/welcome", async (req, res) => { const account = await getAuthAccount(req).catch(() => null); if (account) return res.redirect("/dashboard"); res.sendFile(path.join(__dirname, "welcome.html")); });
app.get("/signin", async (req, res) => { const account = await getAuthAccount(req).catch(() => null); if (account) return res.redirect(safeAuthReturnTo(req.query.returnTo)); res.sendFile(path.join(__dirname, "signin.html")); });
app.get("/app", async (req, res) => { const account = await getAuthAccount(req).catch(() => null); res.redirect(account ? "/dashboard" : "/welcome"); });
app.get("/auth/me", async (req, res) => { const account = await getAuthAccount(req).catch(() => null); if (!account) return res.status(401).json({ ok: false, signedIn: false }); const settings = await getAccountSettings(account); res.json({ ok: true, signedIn: true, account: publicAccount(account), settings }); });
app.post("/auth/login", async (req, res) => { try { const email = normEmail(req.body?.email); const password = String(req.body?.password || ""); const account = await findAccountByEmail(email); if (!account || !(await passwordMatches(password, account.salt, account.password_hash))) return res.status(401).json({ ok: false, error: "Invalid email or password." }); await createAccountSession(account, req, res); res.json({ ok: true, account: publicAccount(account), returnTo: safeAuthReturnTo(req.body?.returnTo || req.query.returnTo) }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Sign in failed." }); } });
app.post("/auth/logout", async (req, res) => { await destroyAccountSession(req, res).catch(() => clearAuthCookie(req, res)); res.json({ ok: true }); });
app.get("/auth/logout", async (req, res) => { await destroyAccountSession(req, res).catch(() => clearAuthCookie(req, res)); res.redirect("/signin"); });
app.get("/api/settings", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); res.json({ ok: true, account: publicAccount(account), settings: await getAccountSettings(account) }); });
app.post("/api/settings", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); res.json({ ok: true, account: publicAccount(account), settings: await saveAccountSettings(account, req.body?.settings || req.body || {}) }); });
app.put("/api/settings", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); res.json({ ok: true, account: publicAccount(account), settings: await saveAccountSettings(account, req.body?.settings || req.body || {}) }); });
app.get("/api/records", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); res.json({ ok: true, account: publicAccount(account), records: await listAccountRecords(account) }); });
app.post("/api/records", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); const record = await upsertAccountRecord(account, req.body || {}); res.status(201).json({ ok: true, account: publicAccount(account), record }); });
app.put("/api/records/:id", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); const record = await upsertAccountRecord(account, req.body || {}, req.params.id); res.json({ ok: true, account: publicAccount(account), record }); });
app.delete("/api/records/:id", async (req, res) => { const account = await getAuthAccount(req); if (!account) return res.status(401).json({ ok: false, error: "Sign in required." }); const deleted = await deleteAccountRecord(account, req.params.id); res.json({ ok: true, deleted }); });
`;

  if (!text.includes('app.post("/auth/login"')) {
    text = text.replace('app.get("/analytics/install"', authRoutes + '\napp.get("/analytics/install"');
  }

  const privateMiddleware = String.raw`
app.use(async (req, res, next) => {
  if (!privateAppPath(req.path)) return next();
  try {
    const account = await getAuthAccount(req);
    if (!account) {
      if (wantsJson(req) || req.method !== "GET") return res.status(401).json({ ok: false, error: "Sign in required." });
      return res.redirect("/welcome?returnTo=" + encodeURIComponent(req.originalUrl || "/dashboard"));
    }
    req.account = account;
    req.query.token = account.dashboard_token;
    req.query.private = "1";
    if (req.body && typeof req.body === "object") {
      req.body.token = account.dashboard_token;
      req.body.dashboard_token = account.dashboard_token;
      req.body.site_id = account.site_id;
    }
    req.accountSettings = await getAccountSettings(account).catch(() => defaultSettings());
    req.accountRecords = await listAccountRecords(account).catch(() => []);
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      if (body && typeof body === "object" && (req.path === "/dashboard/data" || req.path === "/api/dashboard")) {
        const existing = Array.isArray(body.records) ? body.records : Array.isArray(body.leads) ? body.leads : [];
        const records = [...req.accountRecords, ...existing];
        return originalJson({ ...body, account: publicAccount(account), settings: req.accountSettings, records, leads: records.length ? records : body.leads, site: { ...(body.site || {}), site_id: account.site_id, token: account.dashboard_token, owner_email: account.email } });
      }
      return originalJson(body);
    };
    next();
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "Account authorization failed." });
  }
});
`;

  if (!text.includes('privateAppPath(req.path)')) {
    text = text.replace('app.post("/dashboard/simulate"', privateMiddleware + '\napp.post("/dashboard/simulate"');
  }

  const oldPrivateLine = 'function isPrivateRequest(req) { return String(req.query.private || "") === "1" || String(req.get("x-constrava-private") || "") === "1"; }';
  const newPrivateLine = 'function isPrivateRequest(req) { return Boolean(req.account) || String(req.query.private || "") === "1" || String(req.get("x-constrava-private") || "") === "1"; }';
  if (text.includes(oldPrivateLine)) text = text.replace(oldPrivateLine, newPrivateLine);

  const oldInjection = '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>';
  const newInjection = '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script><script src="/account-session.js"></script>';
  if (text.includes(oldInjection) && !text.includes('/account-session.js')) text = text.replaceAll(oldInjection, newInjection);

  writeIfChanged(SERVER_FILE, text, "server.js account authentication and isolation");
}

try {
  patchServer();
  console.log("[account-auth-isolation-patch] Account sign-in, developer account, and account-level privacy are active.");
} catch (error) {
  console.warn("[account-auth-isolation-patch] skipped after non-fatal error:", error && error.message ? error.message : error);
}
