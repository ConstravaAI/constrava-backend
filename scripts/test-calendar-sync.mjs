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
  calendarConnections: [{
    id: "calendar_test", accountUserId: "user_test", workspaceId: "workspace_test", sourceId: "source_calendar_test",
    name: "Test Google Calendar", provider: "google", accountEmail: "owner@example.com", calendarName: "Primary calendar", timeZone: "UTC",
    sync: { direction: "read_only", window: "upcoming_90", createTasks: true, attachNotes: true, includeDeclined: false, includePrivate: false },
    status: "active", authorizationStatus: "authorized", authorizedAt: now, activatedAt: now, oauthTokens: encryptTokens({ access_token: "calendar-access-token", expiresAt: Date.now() + 60 * 60 * 1000 })
  }],
  workspaces: [{ id: "workspace_test", name: "Calendar Test", createdAt: now, updatedAt: now }],
  workspaceMembers: [{ id: "membership_test", workspaceId: "workspace_test", userId: "user_test", role: "owner", status: "active", createdAt: now }],
  workspaceInvitations: [],
  users: [{ id: "user_test", email: "owner@example.com", name: "Calendar Owner", role: "user", workspaceId: "workspace_test", createdAt: now }],
  sessions: [{ id: "session_test", userId: "user_test", activeWorkspaceId: "workspace_test", createdAt: now, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() }]
}), "utf8");

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(root, "scripts", "test-calendar-fetch-mock.mjs")).href, path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "", EMAIL_TOKEN_ENCRYPTION_KEY: encryptionSecret },
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

try {
  await waitForServer();
  const first = await sync();
  assert.equal(first.processed, 1);
  assert.ok(first.drafted > 0);
  const afterFirst = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(afterFirst.records.filter((record) => record.workspaceId === "workspace_test").length, 1, "calendar review must not publish records directly");
  assert.ok(afterFirst.draftRecords.length > 0, "calendar review should create reviewable CRM drafts");
  assert.ok(afterFirst.draftRecords.some((record) => record.type === "Task" && /call/i.test(record.title)), "a clear task on a secondary calendar should create a Task draft");
  assert.equal(afterFirst.ingestionEvents.length, 1);
  assert.equal(afterFirst.ingestionEvents[0].payload.calendarName, "Test Calendar");
  assert.equal(afterFirst.calendarConnections[0].calendarSyncTokens["owner@example.com"], "primary-calendar-sync-token-test");
  assert.equal(afterFirst.calendarConnections[0].calendarSyncTokens.calendar_test_secondary, "secondary-calendar-sync-token-test");

  const draftCount = afterFirst.draftRecords.length;
  const second = await sync();
  assert.equal(second.processed, 0, "the same provider event must be deduplicated");
  const afterSecond = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(afterSecond.draftRecords.length, draftCount, "refreshing twice must not create duplicate drafts");
  assert.equal(afterSecond.ingestionEvents.length, 1, "refreshing twice must not create duplicate ingestion events");
  console.log(`Calendar refresh sync passed: ${draftCount} review draft(s), zero published records, duplicate prevented.`);
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
