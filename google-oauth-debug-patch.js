import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[google-oauth-debug-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
if (source.includes("/debug/google-oauth")) {
  console.log("Google OAuth debug route already exists.");
  process.exit(0);
}

const anchor = 'app.get("/auth/google/forms/start", (req, res) => {';
const route = `app.get("/debug/google-oauth", (req, res) => {
  if (!isPrivateRequest(req)) return res.status(403).json({ ok: false, error: "Add ?private=1 to view safe OAuth debug info." });
  const state = encodeState({ siteSlug: req.query.siteSlug || "google-forms-site", formSlug: req.query.formSlug || "google-form", token: req.query.token || "demo", returnTo: safeReturnTo(req.query.returnTo), nonce: makeToken("state") });
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", process.env.GOOGLE_CLIENT_ID || "");
  url.searchParams.set("redirect_uri", googleRedirectUri(req));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("include_granted_scopes", "true");
  url.searchParams.set("prompt", "select_account consent");
  url.searchParams.set("scope", GOOGLE_FORM_SCOPES.join(" "));
  url.searchParams.set("state", state);
  const clientId = process.env.GOOGLE_CLIENT_ID || "";
  res.json({
    ok: true,
    appBase: appBase(req),
    redirect_uri: googleRedirectUri(req),
    client_id_prefix: clientId.slice(0, 16),
    client_id_suffix: clientId.slice(-32),
    client_id_length: clientId.length,
    has_client_secret: Boolean(process.env.GOOGLE_CLIENT_SECRET),
    scopes: GOOGLE_FORM_SCOPES,
    oauth_url: url.toString()
  });
});
`;

if (!source.includes(anchor)) {
  console.warn("[google-oauth-debug-patch] OAuth start route anchor not found.");
  process.exit(0);
}

source = source.replace(anchor, `${route}\n${anchor}`);
fs.writeFileSync(file, source);
console.log("Google OAuth debug route added.");
