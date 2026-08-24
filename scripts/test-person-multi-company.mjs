import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-person-companies-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43139;
const origin = `http://127.0.0.1:${port}`;
const now = new Date().toISOString();

await writeFile(dataFile, JSON.stringify({
  sources: [], records: [], draftRecords: [], events: [], plans: [], ingestionEvents: [], formConnections: [], emailConnections: [], adsenseConnections: [], googleAnalyticsConnections: [], businessConnections: [], messagingConnections: [], websiteConnections: [], reports: [], googleAccounts: [], microsoftAccounts: [], calendarConnections: [],
  identityEntities: [], identityIdentifiers: [], identityMentions: [], identityRelationships: [], identityRecordLinks: [], identityReconciliation: {},
  workspaces: [{ id: "workspace_test", name: "Multiple Companies Test", ownerUserId: "user_test", createdAt: now, updatedAt: now }],
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
  throw new Error(`Multiple-company test server did not start.\n${serverOutput}`);
}

async function request(pathname, body, expectedStatus = 200) {
  const response = await fetch(`${origin}${pathname}`, { method: "POST", headers: { cookie: "constrava_session=session_test", "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await response.json();
  assert.equal(response.status, expectedStatus, JSON.stringify(data));
  return data;
}

async function store() { return JSON.parse(await readFile(dataFile, "utf8")); }
function record(saved, id) { return saved.records.find((entry) => entry.id === id); }
function entityFor(saved, recordId) { const link = saved.identityRecordLinks.find((entry) => entry.recordId === recordId); return link ? saved.identityEntities.find((entry) => entry.id === link.entityId) : null; }

try {
  await waitForServer();
  const north = (await request("/api/records/manual", { type: "Company", title: "Northwind Manufacturing", priorityLevel: "normal" }, 201)).record;
  const harbor = (await request("/api/records/manual", { type: "Company", title: "Harbor Community Foundation", priorityLevel: "normal" }, 201)).record;
  const person = (await request("/api/records/manual", { type: "Person", title: "Jordan Lee", email: "jordan@example.com", companyRecordIds: [north.id, harbor.id], priorityLevel: "normal" }, 201)).record;

  let saved = await store();
  let savedPerson = record(saved, person.id);
  assert.deepEqual(savedPerson.fields.companyRecordIds, [north.id, harbor.id]);
  assert.deepEqual(savedPerson.fields.companyNames, [record(saved, north.id).title, record(saved, harbor.id).title]);
  assert.equal(savedPerson.fields.companyRecordId, north.id, "the first selected company remains the backwards-compatible primary company");
  assert.deepEqual(new Set(savedPerson.relationships.filter((relationship) => relationship.type === "works_at").map((relationship) => relationship.recordId)), new Set([north.id, harbor.id]));
  assert.ok(record(saved, north.id).fields.people.some((entry) => entry.recordId === person.id));
  assert.ok(record(saved, harbor.id).fields.people.some((entry) => entry.recordId === person.id));
  const personEntity = entityFor(saved, person.id);
  const associatedCompanyEntityIds = saved.identityRelationships.filter((relationship) => relationship.fromEntityId === personEntity.id && relationship.type === "associated_with").map((relationship) => relationship.toEntityId);
  assert.deepEqual(new Set(associatedCompanyEntityIds), new Set([entityFor(saved, north.id).id, entityFor(saved, harbor.id).id]), "hidden identity relationships must include every selected company");

  await request("/api/records/update", { id: person.id, type: "Person", title: person.title, email: "jordan@example.com", companyRecordIds: [harbor.id], priorityLevel: "normal" });
  saved = await store();
  savedPerson = record(saved, person.id);
  assert.deepEqual(savedPerson.fields.companyRecordIds, [harbor.id]);
  assert.ok(!record(saved, north.id).fields.people.some((entry) => entry.recordId === person.id), "removing one company must leave the person record intact");
  assert.ok(record(saved, harbor.id).fields.people.some((entry) => entry.recordId === person.id));

  await request("/api/records/update", { id: person.id, type: "Person", title: person.title, email: "jordan@example.com", companyRecordIds: [harbor.id], newCompanyName: "Cedar Arts Council", priorityLevel: "normal" });
  saved = await store();
  savedPerson = record(saved, person.id);
  const cedar = saved.records.find((entry) => entry.type === "Company" && entry.title === "Cedar Arts Council");
  assert.ok(cedar, "an unlisted company can still be created and added to the person's selected companies");
  assert.deepEqual(savedPerson.fields.companyRecordIds, [harbor.id, cedar.id]);

  await request("/api/records/delete", { id: harbor.id });
  saved = await store();
  savedPerson = record(saved, person.id);
  assert.deepEqual(savedPerson.fields.companyRecordIds, [cedar.id], "deleting one company must preserve the person's other company links");
  assert.equal(savedPerson.fields.companyRecordId, cedar.id);
  assert.equal(savedPerson.fields.companyName, cedar.title);
  assert.ok(record(saved, cedar.id).fields.people.some((entry) => entry.recordId === person.id));
  assert.deepEqual(saved.identityRelationships.filter((relationship) => relationship.fromEntityId === entityFor(saved, person.id).id && relationship.type === "associated_with").map((relationship) => relationship.toEntityId), [entityFor(saved, cedar.id).id]);

  console.log("Multiple person-company relationships passed: selection, removal, new-company creation, hidden identities, and deletion preserve every remaining link.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
