import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[google-forms-basic-oauth-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const wideScopes = 'const GOOGLE_FORM_SCOPES = ["openid", "email", "profile", "https://www.googleapis.com/auth/drive.metadata.readonly", "https://www.googleapis.com/auth/forms.body.readonly"];';
const basicScopes = 'const GOOGLE_FORM_SCOPES = ["openid", "email", "profile"];';
if (source.includes(wideScopes)) {
  source = source.replace(wideScopes, basicScopes);
  changed = true;
}

const oldPrompt = 'url.searchParams.set("prompt", "consent");';
const newPrompt = 'url.searchParams.set("prompt", "select_account consent");';
if (source.includes(oldPrompt)) {
  source = source.replace(oldPrompt, newPrompt);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Google OAuth debug mode enabled: basic scopes and account picker.");
} else {
  console.log("Google OAuth debug patch already applied or matching route not found.");
}
