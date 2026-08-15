import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-calendar-sync-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const encryptionSecret = "calendar-sync-test-encryption-key";
const port = 43129;
const origin = `http://127.0.0.1:${port}`;

function encryptTokens(tokens) {
  const key = crypto.createHash("sha256").update(encryptionSecret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(tokens), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64url")).join(".");
}

const now = new Date().toISOString();
await writeFile(dataFile, JSON.stringify({
  sources: [{ id: "source_calendar_test", workspaceId: "workspace_test", name: "Test calendar", type: "calendar", status: "connected", metadata: {} }],
  records: [{ id: "record_existing", workspaceId: "workspace_test", type: "Note", title: "Existing record", fields: { body: "Control record" }, status: "active", priorityScore: 10, createdAt: now, updatedAt: now }], draftRecords: [], events: [], plans: [], ingestionEvents: [], formConnections: [], emailConnections: [], businessConnections: [], messagingConnections: [], websiteConnections: [], reports: [],
  googleAccounts: [{ id: "google_test", accountUserId: "user_test", workspaceId: "workspace_test", name: "Test Google account", displayName: "Calendar Owner", email: "owner@example.com", status: "active", authorizationStatus: "authorized", authorizationReady: true, enabledResources: { gmail: true, calendar: true }, oauthTokens: encryptTokens({ access_token: "calendar-access-token", scope: "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.events.readonly", expiresAt: Date.now() + 60 * 60 * 1000 }), authorizedAt: now, createdAt: now, updatedAt: now }],
  calendarConnections: [{
    id: "calendar_test", accountUserId: "user_test", workspaceId: "workspace_test", sourceId: "source_calendar_test",
    name: "Test Google Calendar", provider: "google", accountEmail: "owner@example.com", calendarName: "Primary calendar", timeZone: "UTC",
    sync: { direction: "read_only", window: "upcoming_90", createTasks: true, attachNotes: true, includeDeclined: false, includePrivate: false },
    status: "active", authorizationStatus: "authorized", authorizedAt: now, activatedAt: now, googleAccountId: "google_test", oauthTokens: ""
  }],
  workspaces: [{ id: "workspace_test", name: "Calendar Test", createdAt: now, updatedAt: now }],
  workspaceMembers: [{ id: "membership_test", workspaceId: "workspace_test", userId: "user_test", role: "owner", status: "active", createdAt: now }],
  workspaceInvitations: [],
  users: [{ id: "user_test", email: "owner@example.com", name: "Calendar Owner", role: "user", workspaceId: "workspace_test", createdAt: now }],
  sessions: [{ id: "session_test", userId: "user_test", activeWorkspaceId: "workspace_test", createdAt: now, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() }]
}), "utf8");

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(root, "scripts", "test-calendar-fetch-mock.mjs")).href, path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "", EMAIL_TOKEN_ENCRYPTION_KEY: encryptionSecret, GMAIL_CLIENT_ID: "shared-google-client", GMAIL_CLIENT_SECRET: "shared-google-secret" },
  stdio: ["ignore", "pipe", "pipe"]
});
let serverOutput = "";
child.stdout.on("data", (chunk) => { serverOutput += chunk; });
child.stderr.on("data", (chunk) => { serverOutput += chunk; });

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(origin);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Calendar sync test server did not start.\n${serverOutput}`);
}

async function sync() {
  const response = await fetch(`${origin}/api/calendar-connections/sync`, { method: "POST", headers: { cookie: "constrava_session=session_test", "content-type": "application/json" } });
  const data = await response.json();
  assert.equal(response.status, 200, JSON.stringify(data));
  return data;
}

async function calendarRequest(pathname, options = {}) {
  const method = options.method || "POST";
  const response = await fetch(`${origin}${pathname}`, {
    method,
    headers: { cookie: "constrava_session=session_test", "content-type": "application/json" },
    body: ["GET", "HEAD"].includes(method) ? undefined : options.body === undefined ? "{}" : JSON.stringify(options.body)
  });
  const data = await response.json();
  assert.equal(response.status, options.status || 200, JSON.stringify(data));
  return data;
}

try {
  await waitForServer();
  const googleAccounts = await calendarRequest("/api/google-accounts", { method: "GET", body: undefined });
  assert.equal(googleAccounts.accounts.length, 1);
  assert.equal(googleAccounts.apps.length, 6, "the Google app picker should list every supported Google resource");
  assert.equal(googleAccounts.accounts[0].credentialConfigured, true);
  assert.equal(googleAccounts.accounts[0].oauthTokens, undefined, "shared Google tokens must never be returned to the browser");
  const sharedAuthorization = await calendarRequest("/api/google-accounts/google_test/authorize");
  const sharedScope = new URL(sharedAuthorization.authorizeUrl).searchParams.get("scope") || "";
  assert.match(sharedScope, /openid/);
  assert.doesNotMatch(sharedScope, /gmail\.readonly/, "initial Google connection should request identity only");
  const appAuthorization = await calendarRequest("/api/google-accounts/google_test/apps/authorize", { body: { apps: ["gmail", "calendar"] } });
  const appScope = new URL(appAuthorization.authorizeUrl).searchParams.get("scope") || "";
  assert.match(appScope, /gmail\.readonly/);
  assert.match(appScope, /calendar\.events\.readonly/);
  assert.equal(new URL(appAuthorization.authorizeUrl).searchParams.get("include_granted_scopes"), "true");
  const appScan = await calendarRequest("/api/google-accounts/google_test/apps/scan");
  assert.equal(appScan.scan.status, "complete");
  assert.equal(appScan.scan.apps.find((app) => app.id === "gmail").status, "detected");
  assert.equal(appScan.scan.apps.find((app) => app.id === "gmail").count, 42);
  assert.equal(appScan.scan.apps.find((app) => app.id === "calendar").status, "detected");
  assert.equal(appScan.scan.apps.find((app) => app.id === "drive").status, "not_selected");
  const emailConnection = await calendarRequest("/api/email-connections", { body: { provider: "gmail", name: "Shared Gmail", emailAddress: "owner@example.com" }, status: 201 });
  const linkedEmail = await calendarRequest(`/api/email-connections/${emailConnection.connection.id}/link-google`, { body: { googleAccountId: "google_test" } });
  assert.equal(linkedEmail.connection.googleAccountId, "google_test");
  assert.equal(linkedEmail.connection.authorizationStatus, "authorized");
  assert.equal(linkedEmail.connection.oauthTokens, undefined);
  const oauthEmail = await calendarRequest("/api/email-connections", { body: { provider: "gmail", name: "OAuth Gmail", emailAddress: "owner@example.com" }, status: 201 });
  const oauthEmailAuthorization = await calendarRequest(`/api/email-connections/${oauthEmail.connection.id}/authorize`);
  const oauthEmailUrl = new URL(oauthEmailAuthorization.authorizeUrl);
  assert.match(oauthEmailUrl.searchParams.get("scope") || "", /calendar\.events\.readonly/, "connecting Gmail should request the reusable Calendar permission too");
  const oauthEmailCallback = await fetch(`${origin}/api/email/oauth/callback?state=${encodeURIComponent(oauthEmailUrl.searchParams.get("state"))}&code=gmail-oauth-test`, { headers: { cookie: "constrava_session=session_test" }, redirect: "manual" });
  assert.equal(oauthEmailCallback.status, 302);
  const afterGmailOAuth = JSON.parse(await readFile(dataFile, "utf8"));
  const savedOAuthEmail = afterGmailOAuth.emailConnections.find((entry) => entry.id === oauthEmail.connection.id);
  assert.equal(savedOAuthEmail.googleAccountId, "google_test", "a Gmail connection should automatically save and link the reusable Google account");
  assert.equal(savedOAuthEmail.oauthTokens, "", "resource connections should use the shared encrypted Google token");
  assert.equal(afterGmailOAuth.googleAccounts.length, 1, "connecting an existing Google email should update instead of duplicating the account");
  assert.equal(afterGmailOAuth.googleAccounts[0].oauthClient, "gmail");
  assert.ok(afterGmailOAuth.googleAccounts[0].oauthTokens, "the reusable Google credential should be saved server-side");
  const discovery = await calendarRequest("/api/calendar-connections/calendar_test/calendars/scan");
  assert.equal(discovery.calendars.length, 2, "the connected Google account calendars should be discoverable");
  assert.equal(discovery.connection.credentialConfigured, true, "a linked shared Google credential should be recognized");
  assert.ok(discovery.calendars.some((calendar) => calendar.primary), "the calendar list should identify the primary calendar");
  const selection = await calendarRequest("/api/calendar-connections/calendar_test", { method: "PATCH", body: { selectedCalendarIds: ["calendar_test_secondary"] } });
  assert.deepEqual(selection.connection.selectedCalendarIds, ["calendar_test_secondary"]);
  assert.equal(selection.connection.calendarSelectionConfigured, true);
  const first = await sync();
  assert.equal(first.processed, 1);
  assert.ok(first.drafted > 0);
  const afterFirst = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(afterFirst.records.filter((record) => record.workspaceId === "workspace_test").length, 1, "calendar review must not publish records directly");
  assert.ok(afterFirst.draftRecords.length > 0, "calendar review should create reviewable CRM drafts");
  assert.ok(afterFirst.draftRecords.some((record) => record.type === "Task" && /call/i.test(record.title)), "a clear task on a secondary calendar should create a Task draft");
  assert.equal(afterFirst.ingestionEvents.length, 1);
  assert.equal(afterFirst.ingestionEvents[0].payload.calendarName, "Test Calendar");
  assert.equal(afterFirst.calendarConnections[0].calendarSyncTokens["owner@example.com"], undefined, "unselected calendars must not be scanned for events");
  assert.equal(afterFirst.calendarConnections[0].calendarSyncTokens.calendar_test_secondary, "secondary-calendar-sync-token-test");
  assert.equal(afterFirst.calendarConnections[0].availableCalendars.length, 2);
  assert.deepEqual(afterFirst.calendarConnections[0].selectedCalendarIds, ["calendar_test_secondary"]);

  const draftCount = afterFirst.draftRecords.length;
  const second = await sync();
  assert.equal(second.processed, 0, "the same provider event must be deduplicated");
  const afterSecond = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(afterSecond.draftRecords.length, draftCount, "refreshing twice must not create duplicate drafts");
  assert.equal(afterSecond.ingestionEvents.length, 1, "refreshing twice must not create duplicate ingestion events");
  const oauthCalendar = await calendarRequest("/api/calendar-connections", { body: { provider: "google", name: "OAuth Calendar", accountEmail: "owner@example.com" }, status: 201 });
  const oauthCalendarAuthorization = await calendarRequest(`/api/calendar-connections/${oauthCalendar.connection.id}/authorize`);
  const oauthCalendarUrl = new URL(oauthCalendarAuthorization.authorizeUrl);
  assert.match(oauthCalendarUrl.searchParams.get("scope") || "", /gmail\.readonly/, "connecting Calendar should request the reusable Gmail permission too");
  const oauthCalendarCallback = await fetch(`${origin}/api/calendar/oauth/callback?state=${encodeURIComponent(oauthCalendarUrl.searchParams.get("state"))}&code=calendar-oauth-test`, { headers: { cookie: "constrava_session=session_test" }, redirect: "manual" });
  assert.equal(oauthCalendarCallback.status, 302);
  const afterCalendarOAuth = JSON.parse(await readFile(dataFile, "utf8"));
  const savedOAuthCalendar = afterCalendarOAuth.calendarConnections.find((entry) => entry.id === oauthCalendar.connection.id);
  assert.equal(savedOAuthCalendar.googleAccountId, "google_test", "a Calendar connection should automatically save and link the reusable Google account");
  assert.equal(savedOAuthCalendar.oauthTokens, "", "Calendar should use the shared encrypted Google token");
  assert.equal(afterCalendarOAuth.googleAccounts.length, 1, "connecting the same Google account from Calendar should not create a duplicate");
  assert.equal(afterCalendarOAuth.googleAccounts[0].oauthClient, "calendar");
  const typedGoogleAccount = await calendarRequest("/api/google-accounts", { body: { name: "Typed account", email: "typed@example.com" }, status: 201 });
  const identityAuthorization = await calendarRequest(`/api/google-accounts/${typedGoogleAccount.account.id}/authorize`);
  const identityUrl = new URL(identityAuthorization.authorizeUrl);
  assert.doesNotMatch(identityUrl.searchParams.get("scope") || "", /gmail\.readonly/, "the first account step should only identify the Google account");
  const identityCallback = await fetch(`${origin}/api/calendar/oauth/callback?state=${encodeURIComponent(identityUrl.searchParams.get("state"))}&code=identity-oauth-test`, { headers: { cookie: "constrava_session=session_test" }, redirect: "manual" });
  assert.equal(identityCallback.status, 302);
  const afterIdentityOAuth = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(afterIdentityOAuth.googleAccounts.length, 1, "the Google-returned email should merge a typed placeholder into the existing saved account");
  assert.equal(afterIdentityOAuth.googleAccounts[0].email, "owner@example.com");
  console.log(`Calendar refresh sync passed: ${draftCount} review draft(s), zero published records, duplicate prevented.`);
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
