import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-google-auth-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 44200 + Math.floor(Math.random() * 300);
const origin = `http://127.0.0.1:${port}`;
await writeFile(dataFile, "{}\n", "utf8");

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(root, "scripts", "test-google-auth-fetch-mock.mjs")).href, path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "", DEV_LOGIN_KEY: "", GOOGLE_CALENDAR_CLIENT_ID: "google-auth-test.apps.googleusercontent.com", GOOGLE_CALENDAR_CLIENT_SECRET: "google-auth-test-secret", EMAIL_TOKEN_ENCRYPTION_KEY: "google-auth-test-encryption-key" },
  stdio: ["ignore", "pipe", "pipe"]
});
let serverOutput = "";
child.stdout.on("data", (chunk) => { serverOutput += chunk; });
child.stderr.on("data", (chunk) => { serverOutput += chunk; });

async function waitForServer() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try { if ((await fetch(origin)).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Google auth test server did not start.\n${serverOutput}`);
}

async function request(pathname, { cookie = "", redirect = "manual" } = {}) {
  return fetch(`${origin}${pathname}`, { redirect, headers: cookie ? { cookie } : {} });
}

async function begin(mode, cookie = "") {
  const response = await request(`/api/auth/google/start?mode=${mode}`, { cookie });
  assert.equal(response.status, 302);
  const authorizeUrl = new URL(response.headers.get("location"));
  assert.equal(authorizeUrl.hostname, "accounts.google.com");
  assert.equal(authorizeUrl.searchParams.get("prompt"), "select_account consent");
  return authorizeUrl.searchParams.get("state");
}

async function callback(state, code, cookie = "") {
  const response = await request(`/api/calendar/oauth/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}`, { cookie });
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "/projects?google=connected");
  return response;
}

try {
  await waitForServer();

  const signupState = await begin("signup");
  const signup = await callback(signupState, "primary");
  const signupCookie = (signup.headers.get("set-cookie") || "").split(";")[0];
  assert.match(signupCookie, /^constrava_session=/);

  let accountResponse = await request("/api/account/google-accounts", { cookie: signupCookie });
  let accountData = await accountResponse.json();
  assert.equal(accountResponse.status, 200);
  assert.deepEqual(accountData.accounts.map((entry) => entry.email), ["primary-google@example.com"]);

  const projectsResponse = await request("/api/projects", { cookie: signupCookie });
  assert.deepEqual((await projectsResponse.json()).projects, []);

  const loginState = await begin("login");
  const login = await callback(loginState, "primary");
  const loginCookie = (login.headers.get("set-cookie") || "").split(";")[0];
  assert.match(loginCookie, /^constrava_session=/);

  const connectState = await begin("connect", loginCookie);
  const connect = await callback(connectState, "second", loginCookie);
  assert.equal(connect.headers.get("set-cookie"), null);

  accountResponse = await request("/api/account/google-accounts", { cookie: loginCookie });
  accountData = await accountResponse.json();
  assert.deepEqual(accountData.accounts.map((entry) => entry.email).sort(), ["primary-google@example.com", "second-google@example.com"]);

  const saved = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(saved.users.length, 1);
  assert.deepEqual(saved.users[0].googleSubjects.sort(), ["google_subject_primary", "google_subject_second"]);
  assert.equal(saved.googleAccounts.every((entry) => entry.accountUserId === saved.users[0].id), true);
  assert.equal(saved.workspaces.some((entry) => entry.ownerUserId === saved.users[0].id), false);

  console.log("Google authentication passed: signup, login, account-wide connection, session cookies, and project-free account creation.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
