import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-google-isolation-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43800 + Math.floor(Math.random() * 400);
const origin = `http://127.0.0.1:${port}`;
const future = new Date(Date.now() + 60 * 60_000).toISOString();
const now = new Date().toISOString();
const encryptionSecret = "isolation-test-key";

function encryptedTokens(scope) {
  const key = crypto.createHash("sha256").update(encryptionSecret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify({ access_token: "test", refresh_token: "test", scope, expiresAt: Date.now() + 60 * 60_000 }), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64url")).join(".");
}

const store = {
  users: [
    { id: "user_a", email: "a@example.com", name: "Member A", role: "user", workspaceId: "shared", emailVerifiedAt: now, createdAt: now },
    { id: "user_b", email: "b@example.com", name: "Member B", role: "user", workspaceId: "shared", emailVerifiedAt: now, createdAt: now }
  ],
  sessions: [
    { id: "session_a", userId: "user_a", activeWorkspaceId: "shared", createdAt: now, expiresAt: future },
    { id: "session_b", userId: "user_b", activeWorkspaceId: "shared", createdAt: now, expiresAt: future }
  ],
  workspaces: [{ id: "shared", name: "Shared CRM", ownerUserId: "user_a", createdAt: now, updatedAt: now }],
  workspaceMembers: [
    { id: "member_a", workspaceId: "shared", userId: "user_a", role: "owner", status: "active", joinedAt: now },
    { id: "member_b", workspaceId: "shared", userId: "user_b", role: "member", status: "active", joinedAt: now }
  ],
  googleAccounts: [
    { id: "google_a", accountUserId: "user_a", workspaceId: "", linkedWorkspaceIds: ["shared"], email: "owner-google@example.com", name: "Owner Google", status: "active", authorizationStatus: "authorized", selectedApps: ["gmail", "analytics"], oauthTokens: encryptedTokens("openid email profile https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/analytics.readonly"), createdAt: now, updatedAt: now },
    { id: "google_b", accountUserId: "user_b", workspaceId: "", linkedWorkspaceIds: ["shared"], email: "member-google@example.com", name: "Member Google", status: "active", authorizationStatus: "authorized", selectedApps: ["calendar", "analytics"], oauthTokens: encryptedTokens("openid email profile https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.events.readonly https://www.googleapis.com/auth/analytics.readonly"), createdAt: now, updatedAt: now }
  ],
  emailConnections: [
    { id: "email_a", accountUserId: "user_a", workspaceId: "shared", sourceId: "source_email_a", googleAccountId: "google_a", provider: "gmail", emailAddress: "owner-google@example.com", name: "Owner Gmail", status: "active", authorizationStatus: "authorized" },
    { id: "email_b", accountUserId: "user_b", workspaceId: "shared", sourceId: "source_email_b", googleAccountId: "google_b", provider: "gmail", emailAddress: "member-google@example.com", name: "Member Gmail", status: "active", authorizationStatus: "authorized" }
  ],
  calendarConnections: [
    { id: "calendar_a", accountUserId: "user_a", workspaceId: "shared", sourceId: "source_calendar_a", googleAccountId: "google_a", provider: "google", accountEmail: "owner-google@example.com", name: "Owner Calendar", status: "active", authorizationStatus: "authorized" },
    { id: "calendar_b", accountUserId: "user_b", workspaceId: "shared", sourceId: "source_calendar_b", googleAccountId: "google_b", provider: "google", accountEmail: "member-google@example.com", name: "Member Calendar", status: "active", authorizationStatus: "authorized" }
  ],
  businessConnections: [],
  adsenseConnections: [],
  googleAnalyticsConnections: [
    { id: "analytics_a", accountUserId: "user_a", workspaceId: "shared", sourceId: "source_analytics_a", googleAccountId: "google_a", name: "Owner Analytics", analyticsPropertyName: "properties/1001", analyticsPropertyId: "1001", analyticsPropertyDisplayName: "Owner Site", status: "active", authorizationStatus: "authorized", reportRange: "LAST_30_DAYS", createdAt: now, updatedAt: now },
    { id: "analytics_b", accountUserId: "user_b", workspaceId: "shared", sourceId: "source_analytics_b", googleAccountId: "google_b", name: "Member Analytics", analyticsPropertyName: "properties/2002", analyticsPropertyId: "2002", analyticsPropertyDisplayName: "Member Site", status: "active", authorizationStatus: "authorized", reportRange: "LAST_30_DAYS", createdAt: now, updatedAt: now }
  ],
  sources: [
    { id: "source_email_a", accountUserId: "user_a", workspaceId: "shared", name: "Owner Gmail", type: "email", status: "connected", metadata: { googleAccountId: "google_a", emailAddress: "owner-google@example.com" } },
    { id: "source_email_b", accountUserId: "user_b", workspaceId: "shared", name: "Member Gmail", type: "email", status: "connected", metadata: { googleAccountId: "google_b", emailAddress: "member-google@example.com" } },
    { id: "source_calendar_a", accountUserId: "user_a", workspaceId: "shared", name: "Owner Calendar", type: "calendar", status: "connected", metadata: { googleAccountId: "google_a", accountEmail: "owner-google@example.com" } },
    { id: "source_calendar_b", accountUserId: "user_b", workspaceId: "shared", name: "Member Calendar", type: "calendar", status: "connected", metadata: { googleAccountId: "google_b", accountEmail: "member-google@example.com" } },
    { id: "source_analytics_a", accountUserId: "user_a", workspaceId: "shared", name: "Owner Analytics", type: "google_analytics", status: "connected", metadata: { googleAccountId: "google_a", analyticsPropertyName: "properties/1001" } },
    { id: "source_analytics_b", accountUserId: "user_b", workspaceId: "shared", name: "Member Analytics", type: "google_analytics", status: "connected", metadata: { googleAccountId: "google_b", analyticsPropertyName: "properties/2002" } }
  ],
  records: [],
  draftRecords: [],
  events: [],
  plans: [],
  ingestionEvents: [],
  formConnections: [],
  reports: []
};

await writeFile(dataFile, JSON.stringify(store, null, 2), "utf8");

const child = spawn(process.execPath, [path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "", DEV_LOGIN_KEY: "", EMAIL_TOKEN_ENCRYPTION_KEY: encryptionSecret },
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
  throw new Error(`Isolation test server did not start.\n${serverOutput}`);
}

async function json(pathname, sessionId, options = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    ...options,
    redirect: "manual",
    headers: { cookie: `constrava_session=${sessionId}`, ...(options.body ? { "content-type": "application/json" } : {}), ...(options.headers || {}) }
  });
  return { response, data: await response.json() };
}

try {
  await waitForServer();
  for (const [sessionId, ownId, otherId, ownEmail, otherEmail, ownApps] of [
    ["session_a", "google_a", "google_b", "owner-google@example.com", "member-google@example.com", ["gmail", "analytics"]],
    ["session_b", "google_b", "google_a", "member-google@example.com", "owner-google@example.com", ["calendar", "analytics"]]
  ]) {
    const accounts = await json("/api/google-accounts", sessionId);
    assert.equal(accounts.response.status, 200, JSON.stringify(accounts.data));
    assert.deepEqual(accounts.data.accounts.map((entry) => entry.id), [ownId]);
    assert.deepEqual(accounts.data.accounts[0].authorizedApps, ownApps);
    assert.doesNotMatch(JSON.stringify(accounts.data), new RegExp(otherEmail));

    const accountAccounts = await json("/api/account/google-accounts", sessionId);
    assert.deepEqual(accountAccounts.data.accounts.map((entry) => entry.id), [ownId]);

    const emails = await json("/api/email-connections", sessionId);
    assert.equal(emails.data.connections.length, 1);
    assert.equal(emails.data.connections[0].accountUserId, sessionId === "session_a" ? "user_a" : "user_b");

    const calendars = await json("/api/calendar-connections", sessionId);
    assert.equal(calendars.data.connections.length, 1);

    const analytics = await json("/api/google-analytics-connections", sessionId);
    assert.equal(analytics.data.connections.length, 1);
    assert.equal(analytics.data.connections[0].accountUserId, sessionId === "session_a" ? "user_a" : "user_b");
    assert.doesNotMatch(JSON.stringify(analytics.data), new RegExp(otherEmail));

    const resources = await json("/api/connected-resources", sessionId);
    assert.match(JSON.stringify(resources.data), new RegExp(ownEmail));
    assert.doesNotMatch(JSON.stringify(resources.data), new RegExp(otherEmail));
    assert.equal(resources.data.resources.some((entry) => entry.id === otherId || entry.metadata?.googleAccountId === otherId), false);

    const sources = await json("/api/sources", sessionId);
    const foreignSources = sources.data.sources.filter((entry) => entry.name === "Member-owned Google resource");
    assert.ok(foreignSources.length >= 3);
    assert.doesNotMatch(JSON.stringify(foreignSources), new RegExp(otherEmail));
    assert.equal(foreignSources.some((entry) => entry.metadata?.googleAccountId === otherId), false);

    const forbiddenScan = await json(`/api/google-accounts/${otherId}/apps/scan`, sessionId, { method: "POST", body: "{}" });
    assert.equal(forbiddenScan.response.status, 404);
  }
  console.log("Google account isolation passed: shared CRM members only see and manage their own Google accounts and connections.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
