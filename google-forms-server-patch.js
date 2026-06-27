import fs from "fs";

const file = "server.js";
let source = fs.readFileSync(file, "utf8");
let changed = false;

function replaceOnce(find, replace, label) {
  if (source.includes(replace)) return;
  if (!source.includes(find)) {
    console.warn(`[google-forms-server-patch] Could not find ${label}; leaving server.js unchanged for that patch.`);
    return;
  }
  source = source.replace(find, replace);
  changed = true;
}

replaceOnce(
  'const GOOGLE_FORM_SCOPES = ["openid", "email", "profile"];',
  'const GOOGLE_FORM_SCOPES = ["openid", "email", "profile", "https://www.googleapis.com/auth/drive.metadata.readonly", "https://www.googleapis.com/auth/forms.body.readonly"];',
  "Google OAuth scopes"
);

const helperAnchor = 'function googleRedirectUri(req) { return `${appBase(req)}/auth/google/forms/callback`; }';
const helperBlock = `
// __googleFormsPersistentPatch_v1
async function ensureGoogleFormsTablePersistent() {
  if (!hasDb()) return false;
  await db().query(\`CREATE TABLE IF NOT EXISTS google_form_connections (
    id TEXT PRIMARY KEY,
    site_slug TEXT NOT NULL,
    form_slug TEXT NOT NULL,
    dashboard_token TEXT,
    google_account_email TEXT,
    google_form_id TEXT,
    google_form_name TEXT,
    access_token TEXT,
    refresh_token TEXT,
    expires_at BIGINT,
    scope TEXT,
    connected_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )\`);
  return true;
}
function publicGoogleConnection(conn) {
  return {
    connection_id: conn.connection_id || conn.id,
    account: conn.account || conn.google_account_email || "Google account",
    site_slug: conn.site_slug,
    form_slug: conn.form_slug,
    google_form_id: conn.google_form_id || "",
    google_form_name: conn.google_form_name || "",
    connected_at: conn.connected_at,
    scope: conn.scope || ""
  };
}
async function saveGoogleConnectionPersistent(conn) {
  googleConnections.set(conn.connection_id, conn);
  if (!hasDb()) return conn;
  await ensureGoogleFormsTablePersistent();
  await db().query(
    \`INSERT INTO google_form_connections (id, site_slug, form_slug, dashboard_token, google_account_email, google_form_id, google_form_name, access_token, refresh_token, expires_at, scope, connected_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
      ON CONFLICT (id) DO UPDATE SET
        site_slug=EXCLUDED.site_slug,
        form_slug=EXCLUDED.form_slug,
        dashboard_token=EXCLUDED.dashboard_token,
        google_account_email=EXCLUDED.google_account_email,
        google_form_id=COALESCE(EXCLUDED.google_form_id, google_form_connections.google_form_id),
        google_form_name=COALESCE(EXCLUDED.google_form_name, google_form_connections.google_form_name),
        access_token=EXCLUDED.access_token,
        refresh_token=COALESCE(EXCLUDED.refresh_token, google_form_connections.refresh_token),
        expires_at=EXCLUDED.expires_at,
        scope=EXCLUDED.scope,
        updated_at=NOW()\`,
    [conn.connection_id, conn.site_slug, conn.form_slug, conn.dashboard_token, conn.account, conn.google_form_id || null, conn.google_form_name || null, conn.access_token, conn.refresh_token || null, conn.expires_at || null, conn.scope || GOOGLE_FORM_SCOPES.join(" ")]
  );
  return conn;
}
async function getGoogleConnectionPersistent(connectionId) {
  const id = String(connectionId || "");
  if (!id) return null;
  if (googleConnections.has(id)) return googleConnections.get(id);
  if (!hasDb()) return null;
  await ensureGoogleFormsTablePersistent();
  const result = await db().query("SELECT * FROM google_form_connections WHERE id = $1 LIMIT 1", [id]);
  const row = result.rows[0];
  if (!row) return null;
  const conn = {
    connection_id: row.id,
    site_slug: row.site_slug,
    form_slug: row.form_slug,
    dashboard_token: row.dashboard_token,
    account: row.google_account_email,
    google_form_id: row.google_form_id,
    google_form_name: row.google_form_name,
    access_token: row.access_token,
    refresh_token: row.refresh_token,
    expires_at: Number(row.expires_at || 0),
    scope: row.scope,
    connected_at: row.connected_at
  };
  googleConnections.set(id, conn);
  return conn;
}
async function updateGoogleConnectionPersistent(connectionId, patch) {
  const conn = await getGoogleConnectionPersistent(connectionId);
  if (!conn) return null;
  Object.assign(conn, patch, { updated_at: new Date().toISOString() });
  await saveGoogleConnectionPersistent(conn);
  return conn;
}
async function refreshGoogleConnectionPersistent(conn) {
  if (!conn) throw new Error("Google Forms connection not found.");
  if (conn.expires_at && Date.now() < Number(conn.expires_at) - 60000 && conn.access_token) return conn.access_token;
  if (!conn.refresh_token) return conn.access_token;
  const result = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID || "",
      client_secret: process.env.GOOGLE_CLIENT_SECRET || "",
      refresh_token: conn.refresh_token,
      grant_type: "refresh_token"
    })
  });
  const json = await result.json();
  if (!result.ok) throw new Error(json.error_description || json.error || "Google token refresh failed.");
  conn.access_token = json.access_token || conn.access_token;
  conn.expires_at = Date.now() + Number(json.expires_in || 3600) * 1000;
  await saveGoogleConnectionPersistent(conn);
  return conn.access_token;
}
`;
if (!source.includes("__googleFormsPersistentPatch_v1")) {
  replaceOnce(helperAnchor, `${helperAnchor}\n${helperBlock}`, "persistent Google Forms helpers");
}

replaceOnce(
  'googleConnections.set(connectionId, { connection_id: connectionId, site_slug: String(state.siteSlug || "google-forms-site"), form_slug: String(state.formSlug || "google-form"), dashboard_token: String(state.token || "demo"), account, access_token: tokens.access_token, refresh_token: tokens.refresh_token, expires_at: Date.now() + Number(tokens.expires_in || 3600) * 1000, scope: tokens.scope || GOOGLE_FORM_SCOPES.join(" "), connected_at: new Date().toISOString() });',
  'await saveGoogleConnectionPersistent({ connection_id: connectionId, site_slug: String(state.siteSlug || "google-forms-site"), form_slug: String(state.formSlug || "google-form"), dashboard_token: String(state.token || "demo"), account, access_token: tokens.access_token, refresh_token: tokens.refresh_token, expires_at: Date.now() + Number(tokens.expires_in || 3600) * 1000, scope: tokens.scope || GOOGLE_FORM_SCOPES.join(" "), connected_at: new Date().toISOString() });',
  "OAuth callback persistent save"
);

replaceOnce(
  'app.get("/api/google/forms/status", (req, res) => { if (!requirePrivate(req, res)) return; const conn = googleConnections.get(String(req.query.connectionId || "")); if (!conn) return res.status(404).json({ ok: false, error: "Google Forms connection not found." }); res.json({ ok: true, connection: { connection_id: conn.connection_id, account: conn.account, site_slug: conn.site_slug, form_slug: conn.form_slug, connected_at: conn.connected_at } }); });',
  'app.get("/api/google/forms/status", async (req, res) => { if (!requirePrivate(req, res)) return; try { const conn = await getGoogleConnectionPersistent(req.query.connectionId); if (!conn) return res.status(404).json({ ok: false, error: "Google Forms connection not found." }); res.json({ ok: true, connection: publicGoogleConnection(conn), persistent: hasDb() }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Google Forms status failed." }); } });',
  "Google Forms status route"
);

replaceOnce(
  'app.get("/api/google/forms/list", async (req, res) => { if (!requirePrivate(req, res)) return; res.json({ ok: true, forms: [], connection: { connection_id: String(req.query.connectionId || ""), account: "Google account" }, note: "Google OAuth form listing is temporarily disabled. Generate Apps Script manually." }); });',
  'app.get("/api/google/forms/list", async (req, res) => { if (!requirePrivate(req, res)) return; try { const conn = await getGoogleConnectionPersistent(req.query.connectionId); if (!conn) return res.status(404).json({ ok: false, error: "Google Forms connection not found. Sign in again." }); const accessToken = await refreshGoogleConnectionPersistent(conn); if (!accessToken) return res.status(401).json({ ok: false, error: "Google access token is missing. Sign in again." }); const params = new URLSearchParams({ q: "mimeType=\\\'application/vnd.google-apps.form\\\' and trashed=false", fields: "files(id,name,modifiedTime,webViewLink),nextPageToken", orderBy: "modifiedTime desc", pageSize: "25" }); const driveResponse = await fetch(`https://www.googleapis.com/drive/v3/files?${params.toString()}`, { headers: { Authorization: `Bearer ${accessToken}` } }); const json = await driveResponse.json(); if (!driveResponse.ok) throw new Error(json.error?.message || json.error_description || "Could not load Google Forms."); const forms = (json.files || []).map((f) => ({ id: f.id, name: f.name, modifiedTime: f.modifiedTime, url: f.webViewLink })); res.json({ ok: true, forms, connection: publicGoogleConnection(conn) }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Could not list Google Forms." }); } });',
  "Google Forms list route"
);

const appsScriptRoute = 'app.get("/api/google/forms/apps-script", (req, res) => { if (!requirePrivate(req, res)) return; const siteSlug = String(req.query.siteSlug || "google-forms-site"); const formSlug = String(req.query.formSlug || "google-form"); const endpoint = `${CANONICAL_ORIGIN}/api/forms/intake/${encodeURIComponent(siteSlug)}/${encodeURIComponent(formSlug)}`; const key = String(req.query.key || `cx_${siteSlug.replace(/[^a-z0-9]+/gi, "_")}_${formSlug.replace(/[^a-z0-9]+/gi, "_")}_google`); res.type("text/plain").send(googleAppsScript(siteSlug, formSlug, endpoint, key)); });';
const selectRoute = 'app.post("/api/google/forms/select", async (req, res) => { if (!requirePrivate(req, res)) return; try { const connectionId = String(req.body?.connectionId || req.query.connectionId || ""); const formId = String(req.body?.formId || req.body?.google_form_id || "").trim(); const formName = String(req.body?.formName || req.body?.google_form_name || "Google Form").trim(); if (!connectionId) return res.status(400).json({ ok: false, error: "Missing connectionId." }); if (!formId) return res.status(400).json({ ok: false, error: "Missing formId." }); const conn = await updateGoogleConnectionPersistent(connectionId, { google_form_id: formId, google_form_name: formName }); if (!conn) return res.status(404).json({ ok: false, error: "Google Forms connection not found." }); res.json({ ok: true, connection: publicGoogleConnection(conn), message: "Google Form selected and saved." }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Could not save selected Google Form." }); } });';
if (!source.includes('app.post("/api/google/forms/select"')) {
  replaceOnce(appsScriptRoute, `${selectRoute}\n${appsScriptRoute}`, "Google Forms select route");
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Google Forms backend patch applied.");
} else {
  console.log("Google Forms backend patch already applied or no matching changes were needed.");
}
