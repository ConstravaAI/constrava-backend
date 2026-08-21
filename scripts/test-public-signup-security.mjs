import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-public-security-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const emailFile = path.join(temporaryDirectory, "verification-email.json");
const port = 43200 + Math.floor(Math.random() * 500);
const origin = `http://127.0.0.1:${port}`;
const developerKey = "test-developer-key-that-is-not-public";

await writeFile(dataFile, "{}\n", "utf8");

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(root, "scripts", "test-account-email-fetch-mock.mjs")).href, path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: {
    ...process.env,
    PORT: String(port),
    PUBLIC_ORIGIN: origin,
    DATA_FILE: dataFile,
    DATABASE_URL: "",
    OPENAI_API_KEY: "",
    DEV_LOGIN_KEY: developerKey,
    RESEND_API_KEY: "re_account_test",
    ACCOUNT_EMAIL_FROM: "Constrava <accounts@updates.example.com>",
    ACCOUNT_TEST_EMAIL_FILE: emailFile,
    GOOGLE_CALENDAR_CLIENT_ID: "public-security.apps.googleusercontent.com",
    GOOGLE_CALENDAR_CLIENT_SECRET: "public-security-secret",
    EMAIL_TOKEN_ENCRYPTION_KEY: "public-security-token-encryption-key"
  },
  stdio: ["ignore", "pipe", "pipe"]
});
let serverOutput = "";
child.stdout.on("data", (chunk) => { serverOutput += chunk; });
child.stderr.on("data", (chunk) => { serverOutput += chunk; });

async function waitForServer() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(origin);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Public security test server did not start.\n${serverOutput}`);
}

async function request(pathname, { method = "GET", body, headers = {} } = {}) {
  return fetch(`${origin}${pathname}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual"
  });
}

async function jsonRequest(pathname, options = {}) {
  const response = await request(pathname, options);
  return { response, data: await response.json() };
}

try {
  await waitForServer();

  const homepageResponse = await request("/");
  const homepage = await homepageResponse.text();
  assert.equal(homepageResponse.status, 200);
  assert.match(homepage, /Free Business Management, CRM &amp; SEO Tools \| Constrava/);
  assert.match(homepage, /<link rel="canonical"/);
  assert.match(homepage, /application\/ld\+json/);
  assert.match(homepage, /Create your free account/);
  assert.match(homepage, /href="\/signin">Log in<\/a>/);
  assert.match(homepage, /href="\/signup">Sign up<\/a>/);
  assert.doesNotMatch(homepage, /â|Â|Ã/);
  assert.equal(homepageResponse.headers.get("x-frame-options"), "DENY");
  assert.equal(homepageResponse.headers.get("x-content-type-options"), "nosniff");
  assert.match(homepageResponse.headers.get("content-security-policy") || "", /frame-ancestors 'none'/);
  assert.equal(homepageResponse.headers.get("x-robots-tag"), "index, follow");
  assert.match(homepageResponse.headers.get("cache-control") || "", /public/);

  const demoResponse = await request("/demo");
  const demoPage = await demoResponse.text();
  assert.equal(demoResponse.status, 200);
  assert.ok(demoPage.length > 250_000, `Generated dashboard was unexpectedly short (${demoPage.length} characters).`);
  assert.match(demoPage, /<section id="app"><\/section>/);
  assert.match(demoPage, /function render\(\)\{/);
  assert.match(demoPage, /refresh\('analytics'\);/);
  assert.match(demoPage, /<\/body>\s*<\/html>\s*$/);
  assert.match(demoPage, /fluid-aspect-layout-v1/);
  assert.match(demoPage, />12-hour<\/button>/);
  assert.match(demoPage, /Add a Website Tracker/);
  assert.match(demoPage, /highestPriorityItems/);
  assert.doesNotMatch(demoPage, /<section class="workspace">/);

  const robotsResponse = await request("/robots.txt");
  assert.match(await robotsResponse.text(), /Sitemap: .*\/sitemap\.xml/);
  const sitemapResponse = await request("/sitemap.xml");
  assert.match(await sitemapResponse.text(), new RegExp(`<loc>${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\/</loc>`));
  const missingResponse = await request("/not-a-real-page");
  assert.equal(missingResponse.status, 404);
  assert.equal(missingResponse.headers.get("x-robots-tag"), "noindex, nofollow");

  const signupPageResponse = await request("/signup");
  const signupPage = await signupPageResponse.text();
  assert.match(signupPage, /Standard account only/);
  assert.match(signupPage, /at least 7 characters and include 1 special character/i);
  assert.match(signupPage, /id="passwordMismatchDialog"/);
  assert.match(signupPage, /mismatchDialog\.showModal/);
  assert.match(signupPage, /Sign up with Google/);
  assert.match(signupPage, /\/api\/auth\/google\/start\?mode=signup/);
  assert.doesNotMatch(signupPage, /DEV_LOGIN_KEY|constrava@constravaai\.com/);

  const signInPageResponse = await request("/signin");
  const signInPageMarkup = await signInPageResponse.text();
  assert.match(signInPageMarkup, /Log in with Google/);
  assert.match(signInPageMarkup, /document\.getElementById\("status"\)/);
  assert.doesNotMatch(signInPageMarkup, /(?<!el\.)status\.textContent/);
  const signInClientScript = signInPageMarkup.split("<script>")[1].split("</script>")[0];
  assert.doesNotThrow(() => new vm.Script(signInClientScript));
  const elements = Object.fromEntries(["authForm", "loginTab", "signupTab", "nameWrap", "confirmWrap", "confirmPassword", "passwordInput", "passwordHelp", "securityNote", "title", "copy", "submitBtn", "status", "googleAuthButton", "googleAuthLabel", "passwordMismatchDialog", "passwordMismatchClose"].map((elementId) => {
    const handlers = {};
    return [elementId, { id: elementId, handlers, style: {}, dataset: {}, classList: { toggle() {} }, setAttribute() {}, addEventListener(type, handler) { handlers[type] = handler; }, querySelector() { return elements?.nameInput; }, close() {}, focus() {} }];
  }));
  elements.nameInput = { required: false, focus() {} };
  const clientWindow = {
    location: { search: "?google_error=Google%20test%20error", pathname: "/signin", assign() {} },
    history: { replaceState(_state, _title, nextPath) { clientWindow.location.pathname = nextPath; clientWindow.location.search = ""; } },
    addEventListener() {}
  };
  vm.runInNewContext(signInClientScript, {
    window: clientWindow,
    document: { getElementById: (elementId) => elements[elementId] || null, querySelector: () => elements.nameInput },
    localStorage: { removeItem() {} }, URLSearchParams, FormData: class { *[Symbol.iterator]() {} }, fetch: async () => { throw new Error("not called"); },
    Object, String, JSON, Error
  });
  assert.equal(elements.status.textContent, "Google test error");
  assert.equal(elements.googleAuthButton.href, "/api/auth/google/start?mode=login");
  elements.signupTab.handlers.click();
  assert.equal(elements.googleAuthButton.href, "/api/auth/google/start?mode=signup");
  assert.equal(elements.confirmPassword.required, true);
  assert.equal(elements.passwordInput.minLength, 7);
  const googleStart = await request("/api/auth/google/start?mode=login");
  assert.equal(googleStart.status, 302);
  const googleAuthorizeUrl = new URL(googleStart.headers.get("location"));
  assert.equal(googleAuthorizeUrl.hostname, "accounts.google.com");
  assert.equal(googleAuthorizeUrl.searchParams.get("prompt"), "select_account consent");
  assert.equal(googleAuthorizeUrl.searchParams.get("redirect_uri"), `${origin}/api/calendar/oauth/callback`);

  const weakSignup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.10" },
    body: { name: "Public User", email: "weak@example.com", password: "short" }
  });
  assert.equal(weakSignup.response.status, 400);

  const noSpecialCharacterSignup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.10" },
    body: { name: "Public User", email: "ordinary@example.com", password: "SevenChars" }
  });
  assert.equal(noSpecialCharacterSignup.response.status, 400);

  const crossSiteSignup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "sec-fetch-site": "cross-site", "x-forwarded-for": "198.51.100.11" },
    body: { name: "Cross Site", email: "cross@example.com", password: "a secure cross site passphrase" }
  });
  assert.equal(crossSiteSignup.response.status, 403);

  const standardPassword = "FreeCRM!";
  const signup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.12" },
    body: {
      name: "Taylor Customer",
      email: "taylor@example.com",
      password: standardPassword,
      role: "developer",
      accountType: "developer",
      isDeveloper: true
    }
  });
  assert.equal(signup.response.status, 201, JSON.stringify(signup.data));
  assert.equal(signup.data.verificationRequired, true);
  assert.equal(signup.data.next, "/verify-email-sent");
  assert.equal(signup.response.headers.get("set-cookie"), null);

  let saved = JSON.parse(await readFile(dataFile, "utf8"));
  let standardUser = saved.users.find((entry) => entry.email === "taylor@example.com");
  assert.equal(standardUser.role, "user");
  assert.equal(standardUser.accountType, "standard");
  assert.equal(standardUser.isDeveloper, false);
  assert.equal(standardUser.authProvider, "password");
  assert.equal(standardUser.workspaceId, "");
  assert.equal(standardUser.emailVerifiedAt, "");
  assert.match(standardUser.emailVerificationTokenHash, /^[a-f0-9]{64}$/);
  assert.equal(saved.workspaces.some((workspace) => workspace.ownerUserId === standardUser.id), false);
  assert.equal(saved.workspaceMembers.some((membership) => membership.userId === standardUser.id), false);

  const pendingLogin = await jsonRequest("/api/auth/login", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.16" },
    body: { email: "taylor@example.com", password: standardPassword }
  });
  assert.equal(pendingLogin.response.status, 403);
  assert.equal(pendingLogin.data.code, "email_verification_required");

  const verificationEmail = JSON.parse(await readFile(emailFile, "utf8"));
  const verificationToken = new URL(verificationEmail.verificationUrl).searchParams.get("token");
  const verification = await jsonRequest("/api/auth/verify-email", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.17" },
    body: { token: verificationToken }
  });
  assert.equal(verification.response.status, 200, JSON.stringify(verification.data));
  assert.equal(verification.data.user.role, "user");
  assert.equal(verification.data.user.emailVerified, true);
  const sessionCookie = verification.response.headers.get("set-cookie") || "";
  assert.match(sessionCookie, /HttpOnly/i);
  assert.match(sessionCookie, /SameSite=Lax/i);

  const newUserProjects = await jsonRequest("/api/projects", {
    headers: { cookie: sessionCookie.split(";")[0] }
  });
  assert.equal(newUserProjects.response.status, 200, JSON.stringify(newUserProjects.data));
  assert.deepEqual(newUserProjects.data.projects, []);

  const projectPageResponse = await request("/projects", { headers: { cookie: sessionCookie.split(";")[0] } });
  const projectPage = await projectPageResponse.text();
  assert.equal(projectPageResponse.status, 200);
  assert.match(projectPage, /Connect a Google account/);
  assert.match(projectPage, /\/api\/auth\/google\/start\?mode=connect/);

  const reusedVerification = await jsonRequest("/api/auth/verify-email", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.18" },
    body: { token: verificationToken }
  });
  assert.equal(reusedVerification.response.status, 400);

  saved = JSON.parse(await readFile(dataFile, "utf8"));
  standardUser = saved.users.find((entry) => entry.email === "taylor@example.com");
  assert.ok(standardUser.emailVerifiedAt);
  assert.equal(standardUser.emailVerificationTokenHash, "");
  assert.equal(standardUser.emailVerificationExpiresAt, "");
  assert.equal(saved.workspaces.some((workspace) => workspace.ownerUserId === standardUser.id), false);
  assert.equal(saved.workspaceMembers.some((membership) => membership.userId === standardUser.id), false);

  const publicDeveloperLogin = await jsonRequest("/api/auth/login", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.13" },
    body: { email: "constrava@constravaai.com", password: developerKey }
  });
  assert.equal(publicDeveloperLogin.response.status, 200, JSON.stringify(publicDeveloperLogin.data));
  assert.equal(publicDeveloperLogin.data.user.role, "developer");
  assert.match(publicDeveloperLogin.response.headers.get("set-cookie") || "", /constrava_session=/);

  const wrongDeveloperLogin = await jsonRequest("/api/auth/login", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.17" },
    body: { email: "constrava@constravaai.com", password: "not-the-developer-key" }
  });
  assert.equal(wrongDeveloperLogin.response.status, 401);

  const developerLogin = await jsonRequest("/api/auth/developer-login", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.14" },
    body: { password: developerKey }
  });
  assert.equal(developerLogin.response.status, 200, JSON.stringify(developerLogin.data));
  assert.equal(developerLogin.data.user.role, "developer");
  saved = JSON.parse(await readFile(dataFile, "utf8"));
  const developerUsers = saved.users.filter((entry) => entry.email === "constrava@constravaai.com");
  assert.equal(developerUsers.length, 1, "normal accounts must not duplicate or replace the developer account");
  assert.equal(developerUsers[0].role, "developer");
  assert.equal(saved.users.find((entry) => entry.email === "taylor@example.com")?.role, "user", "developer login must not change the test account");

  for (let attempt = 0; attempt < 6; attempt += 1) {
    const response = await jsonRequest("/api/auth/signup", {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.15" },
      body: { name: "Rate Test", email: "rate-limit@example.com", password: "short" }
    });
    assert.equal(response.response.status, 400);
  }
  const correctedSignup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.15" },
    body: { name: "Rate Test", email: "rate-limit@example.com", password: "Fixed!7" }
  });
  assert.equal(correctedSignup.response.status, 201, JSON.stringify(correctedSignup.data));

  for (const retiredPath of ["/api/microsoft-accounts", "/api/messaging-connections", "/api/form-connections", "/api/forms/ingest"]) {
    const retired = await jsonRequest(retiredPath);
    assert.equal(retired.response.status, 404, retiredPath);
  }

  console.log("Public account security passed: recoverable password validation, project-free signup, server-key developer login, hardened headers, clean SEO output, and retired provider routes.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
