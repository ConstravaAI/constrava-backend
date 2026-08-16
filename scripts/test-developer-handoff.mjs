import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-developer-handoff-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43130;
const origin = `http://127.0.0.1:${port}`;
const now = new Date().toISOString();

await writeFile(dataFile, JSON.stringify({
  sources: [{ id: "source_website_test", workspaceId: "workspace_test", name: "Test Website", type: "website", status: "draft", metadata: {} }],
  records: [], draftRecords: [], events: [], plans: [], ingestionEvents: [], formConnections: [], emailConnections: [], googleAccounts: [], adsenseConnections: [], microsoftAccounts: [], calendarConnections: [], businessConnections: [], messagingConnections: [], reports: [], developerHandoffs: [],
  websiteConnections: [{ id: "website_test", accountUserId: "user_test", workspaceId: "workspace_test", sourceId: "source_website_test", name: "Test Website", productionUrl: "https://www.example.com/", additionalDomains: [], platform: "custom", tracking: { pageViews: true, trafficSources: true, formSubmissions: false }, installation: { method: "manual", values: {} }, test: { status: "idle", matchedEvents: 0, lastChecked: "" }, setupStep: 3, status: "draft", createdAt: now, updatedAt: now, activatedAt: "" }],
  identityEntities: [], identityIdentifiers: [], identityMentions: [], identityRelationships: [], identityRecordLinks: [], identityReconciliation: {},
  workspaces: [{ id: "workspace_test", name: "Website Test CRM", ownerUserId: "user_test", createdAt: now, updatedAt: now }],
  workspaceMembers: [{ id: "membership_test", workspaceId: "workspace_test", userId: "user_test", role: "owner", status: "active", joinedAt: now }],
  workspaceInvitations: [],
  users: [{ id: "user_test", email: "owner@example.com", name: "Website Owner", role: "user", workspaceId: "workspace_test", createdAt: now }],
  sessions: [{ id: "session_test", userId: "user_test", activeWorkspaceId: "workspace_test", createdAt: now, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() }]
}), "utf8");

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(root, "scripts", "test-developer-handoff-fetch-mock.mjs")).href, path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "", RESEND_API_KEY: "re_test", DEVELOPER_HANDOFF_FROM: "Constrava <handoff@updates.example.com>" },
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
  throw new Error(`Developer handoff test server did not start.\n${serverOutput}`);
}

async function request(pathname, { method = "GET", body, status = 200 } = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    method,
    headers: { cookie: "constrava_session=session_test", "content-type": "application/json" },
    body: ["GET", "HEAD"].includes(method) ? undefined : JSON.stringify(body || {})
  });
  const data = await response.json();
  assert.equal(response.status, status, JSON.stringify(data));
  return data;
}

try {
  await waitForServer();
  const sourceResponse = await request("/api/sources");
  assert.match(sourceResponse.snippet, /workspaceId=workspace_test/);
  assert.match(sourceResponse.snippet, /site_workspace_test/);
  assert.doesNotMatch(sourceResponse.snippet, /demo=1/);

  await request("/api/website-connections/website_test/developer-handoff", { method: "POST", body: { developerEmail: "not-an-email" }, status: 400 });
  const result = await request("/api/website-connections/website_test/developer-handoff", {
    method: "POST",
    body: { developerName: "Alex Developer", developerEmail: "developer@example.com", message: "Please deploy this before launch.", deadline: "2026-09-01" }
  });
  assert.equal(result.sent, true);
  assert.equal(result.handoff.to, "developer@example.com");
  assert.equal(result.handoff.providerMessageId, "email_developer_handoff_test");
  const saved = JSON.parse(await readFile(dataFile, "utf8"));
  assert.equal(saved.developerHandoffs.length, 1);
  assert.equal(saved.developerHandoffs[0].status, "sent");
  assert.equal(saved.developerHandoffs[0].providerMessageId, "email_developer_handoff_test");
  assert.equal(saved.developerHandoffs[0].message, undefined, "the full email message should not be copied into the audit record");
  assert.equal(saved.websiteConnections[0].installation.method, "developer");
  assert.equal(saved.websiteConnections[0].installation.values.developer.message, "Please deploy this before launch.");
  console.log("Developer handoff email passed: validated recipient, complete payload, workspace snippet, persistence, and delivery audit.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}

