import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-hidden-upgrade-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43138;
const origin = `http://127.0.0.1:${port}`;
const now = new Date().toISOString();
const person = {
  id: "person_existing", workspaceId: "workspace_test", type: "Person", title: "Existing Person", status: "active",
  priorityScore: 50, priorityReasons: [], tags: [], fields: { name: "Existing Person", email: "existing@legacyroof.example", companyName: "Legacy Roof" },
  relationships: [], sourceIds: [], createdAt: now, updatedAt: now, metadata: {}
};
person.metadata.identityFingerprint = crypto.createHash("sha256").update(JSON.stringify([1, person.type, person.title, person.fields, person.updatedAt])).digest("base64url");

await writeFile(dataFile, JSON.stringify({
  sources: [], records: [person], draftRecords: [], events: [], plans: [], ingestionEvents: [], formConnections: [], emailConnections: [], adsenseConnections: [], googleAnalyticsConnections: [], businessConnections: [], messagingConnections: [], websiteConnections: [], reports: [], googleAccounts: [], microsoftAccounts: [], calendarConnections: [],
  identityEntities: [
    { id: "identity_person_existing", workspaceId: "workspace_test", entityType: "Person", canonicalName: "Existing Person", normalizedName: "existing person", aliases: [], hidden: true, status: "confirmed", facts: { companyEntityId: "identity_company_legacy" }, createdAt: now, updatedAt: now },
    { id: "identity_company_legacy", workspaceId: "workspace_test", entityType: "Company", canonicalName: "Legacy Roof", normalizedName: "legacy roof", aliases: [], hidden: true, status: "provisional", facts: {}, createdAt: now, updatedAt: now }
  ],
  identityIdentifiers: [{ id: "identifier_existing_email", workspaceId: "workspace_test", entityId: "identity_person_existing", type: "email", value: "existing@legacyroof.example", verified: true, sourceRecordId: person.id, createdAt: now, updatedAt: now }],
  identityMentions: [],
  identityRelationships: [{ id: "relationship_existing", workspaceId: "workspace_test", key: "identity_person_existing:associated_with:identity_company_legacy", fromEntityId: "identity_person_existing", toEntityId: "identity_company_legacy", type: "associated_with", sourceId: person.id, createdAt: now, updatedAt: now }],
  identityRecordLinks: [{ id: "link_existing_person", workspaceId: "workspace_test", entityId: "identity_person_existing", recordId: person.id, recordType: "Person", createdAt: now, updatedAt: now }],
  identityReconciliation: { workspace_test: { version: 1, lastRunAt: now, processed: 0, recordCount: 1 } },
  workspaces: [{ id: "workspace_test", name: "Hidden Upgrade Test", ownerUserId: "user_test", createdAt: now, updatedAt: now }],
  workspaceMembers: [{ id: "membership_test", workspaceId: "workspace_test", userId: "user_test", role: "owner", status: "active", joinedAt: now }], workspaceInvitations: [],
  users: [{ id: "user_test", email: "owner@example.com", name: "Owner", role: "user", accountType: "standard", workspaceId: "workspace_test", createdAt: now }],
  sessions: [{ id: "session_test", userId: "user_test", activeWorkspaceId: "workspace_test", createdAt: now, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() }]
}), "utf8");

const child = spawn(process.execPath, [path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "" },
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
  throw new Error(`Hidden identity upgrade test server did not start.\n${serverOutput}`);
}

async function dashboard() {
  const response = await fetch(`${origin}/api/dashboard/summary`, { headers: { cookie: "constrava_session=session_test" } });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  return body;
}

try {
  await waitForServer();
  const firstSummary = await dashboard();
  let saved = JSON.parse(await readFile(dataFile, "utf8"));
  let companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(firstSummary.identityReconciliation.upgraded, true);
  assert.equal(firstSummary.identityReconciliation.visibleCompaniesCreated, 1);
  assert.equal(companies.length, 1, "the version upgrade must promote the existing hidden company into one visible Company record");
  assert.equal(companies[0].title, "Legacy Roof");
  assert.equal(saved.records.find((record) => record.id === person.id).fields.companyRecordId, companies[0].id);
  assert.equal(saved.identityRecordLinks.find((link) => link.recordId === companies[0].id)?.entityId, "identity_company_legacy");

  const secondSummary = await dashboard();
  saved = JSON.parse(await readFile(dataFile, "utf8"));
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(secondSummary.identityReconciliation.upgraded, false);
  assert.equal(companies.length, 1, "later refreshes must not create duplicate companies");
  console.log("Hidden identity upgrade passed: existing hidden companies are promoted once and linked to their visible people.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
