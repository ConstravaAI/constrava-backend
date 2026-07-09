import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(here, "server.js");
const runtimePath = path.join(here, ".server.generated.js");

const fixedSignInPage = String.raw`function signInPage() {
  const devConfigured = Boolean(process.env[DEV_LOGIN_KEY_ENV]);
  return \`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in | Constrava</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7fbff;color:#071629;font-family:Inter,system-ui,sans-serif}.card{width:min(460px,calc(100% - 36px));background:white;border:1px solid #d9e3f2;border-radius:28px;padding:28px;box-shadow:0 24px 70px rgba(6,26,51,.10)}h1{color:#061a33;font-size:42px;letter-spacing:-.06em}label{font-weight:900;color:#263d5c}input{width:100%;border:1px solid #d9e3f2;border-radius:14px;padding:13px;margin:6px 0 12px;font:inherit}.submit,.back{border:1px solid #d9e3f2;border-radius:999px;padding:12px;font:inherit;font-weight:900;cursor:pointer}.submit{background:#061a33;color:white;min-width:128px}.back{display:flex;justify-content:center;text-decoration:none;color:#061a33;margin-top:44px}.status{min-height:22px;color:#9d2b2b}.hint{font-size:13px;background:#eaf2ff;border:1px solid #d9e3f2;padding:10px;border-radius:14px}</style></head><body><main class="card"><h1 id="title">Sign in</h1><p id="copy">Enter your saved account details to open your dashboard.</p>\${devConfigured ? \`<p class="hint">Developer login is enabled for \${DEV_EMAIL}. Use the configured \${DEV_LOGIN_KEY_ENV} value as the password.</p>\` : ""}<form id="authForm"><label>Email</label><input name="email" type="email" autocomplete="email" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="submit" id="submitBtn">Sign in</button></form><p class="status" id="status"></p><a class="back" href="/">Back to homepage</a></main><script>localStorage.removeItem("constrava_session_token");authForm.onsubmit=async function(e){e.preventDefault();status.textContent="";submitBtn.disabled=true;try{const payload=Object.fromEntries(new FormData(authForm));const r=await fetch("/api/auth/login",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});const data=await r.json();if(!r.ok)throw new Error(data.error||"Authentication failed");location.href="/dashboard/"}catch(err){status.textContent=err.message}finally{submitBtn.disabled=false}};</script></body></html>\`;
}`;

let source = await fs.readFile(serverPath, "utf8");
const start = source.indexOf("function signInPage() {");
const end = source.indexOf("\n\nfunction appPage", start);

if (start === -1 || end === -1) {
  throw new Error("Could not locate signInPage() in src/server.js");
}

source = source.slice(0, start) + fixedSignInPage + source.slice(end);
await fs.writeFile(runtimePath, source);
await import(`${pathToFileURL(runtimePath).href}?v=${Date.now()}`);
