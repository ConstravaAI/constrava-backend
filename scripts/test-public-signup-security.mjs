import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
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
    ACCOUNT_TEST_EMAIL_FILE: emailFile
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
  assert.doesNotMatch(homepage, /â|Â|Ã/);
  assert.equal(homepageResponse.headers.get("x-frame-options"), "DENY");
  assert.equal(homepageResponse.headers.get("x-content-type-options"), "nosniff");
  assert.match(homepageResponse.headers.get("content-security-policy") || "", /frame-ancestors 'none'/);
  assert.equal(homepageResponse.headers.get("x-robots-tag"), "index, follow");
  assert.match(homepageResponse.headers.get("cache-control") || "", /public/);

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
  assert.doesNotMatch(signupPage, /DEV_LOGIN_KEY|constrava@constravaai\.com/);

  const weakSignup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.10" },
    body: { name: "Public User", email: "weak@example.com", password: "short" }
  });
  assert.equal(weakSignup.response.status, 400);

  const crossSiteSignup = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "sec-fetch-site": "cross-site", "x-forwarded-for": "198.51.100.11" },
    body: { name: "Cross Site", email: "cross@example.com", password: "a secure cross site passphrase" }
  });
  assert.equal(crossSiteSignup.response.status, 403);

  const standardPassword = "a memorable standard account passphrase";
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
  assert.equal(standardUser.emailVerifiedAt, "");
  assert.match(standardUser.emailVerificationTokenHash, /^[a-f0-9]{64}$/);

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

  const publicDeveloperLogin = await jsonRequest("/api/auth/login", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.13" },
    body: { email: "constrava@constravaai.com", password: developerKey }
  });
  assert.equal(publicDeveloperLogin.response.status, 401);

  const developerLogin = await jsonRequest("/api/auth/developer-login", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.14" },
    body: { password: developerKey }
  });
  assert.equal(developerLogin.response.status, 200, JSON.stringify(developerLogin.data));
  assert.equal(developerLogin.data.user.role, "developer");

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await jsonRequest("/api/auth/signup", {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.15" },
      body: { name: "Rate Test", email: "rate-limit@example.com", password: "short" }
    });
    assert.equal(response.response.status, 400);
  }
  const rateLimited = await jsonRequest("/api/auth/signup", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.15" },
    body: { name: "Rate Test", email: "rate-limit@example.com", password: "short" }
  });
  assert.equal(rateLimited.response.status, 429);
  assert.ok(Number(rateLimited.response.headers.get("retry-after")) > 0);

  for (const retiredPath of ["/api/microsoft-accounts", "/api/messaging-connections", "/api/form-connections", "/api/forms/ingest"]) {
    const retired = await jsonRequest(retiredPath);
    assert.equal(retired.response.status, 404, retiredPath);
  }

  console.log("Public account security passed: standard-only signup, isolated developer login, throttling, hardened headers, clean SEO output, and retired provider routes.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
