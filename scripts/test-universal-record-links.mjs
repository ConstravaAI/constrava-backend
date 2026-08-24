import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-universal-links-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43140;
const origin = `http://127.0.0.1:${port}`;
const now = new Date().toISOString();
const foreignRecord = { id: "note_foreign", workspaceId: "workspace_other", type: "Note", title: "Private note", status: "active", priorityScore: 50, priorityReasons: [], tags: [], fields: { recordType: "Note" }, relationships: [], sourceIds: [], createdAt: now, updatedAt: now, metadata: {} };

await writeFile(dataFile, JSON.stringify({
  sources: [], records: [foreignRecord], draftRecords: [], events: [], plans: [], ingestionEvents: [], formConnections: [], emailConnections: [], adsenseConnections: [], googleAnalyticsConnections: [], businessConnections: [], messagingConnections: [], websiteConnections: [], reports: [], googleAccounts: [], microsoftAccounts: [], calendarConnections: [],
  identityEntities: [], identityIdentifiers: [], identityMentions: [], identityRelationships: [], identityRecordLinks: [], identityReconciliation: {},
  workspaces: [{ id: "workspace_test", name: "Universal Links Test", ownerUserId: "user_test", createdAt: now, updatedAt: now }, { id: "workspace_other", name: "Other Workspace", ownerUserId: "user_other", createdAt: now, updatedAt: now }],
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
  throw new Error(`Universal record-link test server did not start.\n${serverOutput}`);
}

async function request(pathname, body, expectedStatus = 200) {
  const response = await fetch(`${origin}${pathname}`, { method: "POST", headers: { cookie: "constrava_session=session_test", "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await response.json();
  assert.equal(response.status, expectedStatus, JSON.stringify(data));
  return data;
}

async function store() { return JSON.parse(await readFile(dataFile, "utf8")); }
function record(saved, id) { return saved.records.find((entry) => entry.id === id); }
function genericLinks(savedRecord) { return new Set((savedRecord.relationships || []).filter((relationship) => relationship.type === "related_to").map((relationship) => relationship.recordId)); }
function assertLinks(saved, recordId, expectedIds) {
  const savedRecord = record(saved, recordId);
  assert.deepEqual(new Set(savedRecord.fields.relatedRecordIds || []), new Set(expectedIds));
  assert.deepEqual(genericLinks(savedRecord), new Set(expectedIds));
}

try {
  await waitForServer();
  const company = (await request("/api/records/manual", { type: "Company", title: "Northwind Manufacturing" }, 201)).record;
  const person = (await request("/api/records/manual", { type: "Person", title: "Jordan Lee", email: "jordan@example.com", companyRecordIds: [company.id] }, 201)).record;
  const task = (await request("/api/records/manual", { type: "Task", title: "Call Jordan" }, 201)).record;
  const note = (await request("/api/records/manual", { type: "Note", title: "Meeting context" }, 201)).record;
  const deal = (await request("/api/records/manual", { type: "Deal", title: "Annual renewal", relatedRecordIds: [person.id, company.id, task.id, note.id] }, 201)).record;

  let saved = await store();
  assertLinks(saved, deal.id, [person.id, company.id, task.id, note.id]);
  for (const relatedId of [person.id, company.id, task.id, note.id]) assertLinks(saved, relatedId, [deal.id]);
  assert.deepEqual(record(saved, person.id).fields.companyRecordIds, [company.id], "generic links must not replace the specialized person-company membership");
  assert.ok(record(saved, person.id).relationships.some((relationship) => relationship.type === "works_at" && relationship.recordId === company.id));

  await request("/api/records/update", { id: task.id, type: "Task", title: task.title, relatedRecordIds: [company.id] });
  saved = await store();
  assertLinks(saved, task.id, [company.id]);
  assertLinks(saved, company.id, [deal.id, task.id]);
  assertLinks(saved, deal.id, [person.id, company.id, note.id]);

  const selfLink = await request("/api/records/update", { id: deal.id, type: "Deal", title: deal.title, relatedRecordIds: [deal.id] }, 400);
  assert.match(selfLink.error, /cannot be related to itself/i);
  const foreignLink = await request("/api/records/update", { id: deal.id, type: "Deal", title: deal.title, relatedRecordIds: [foreignRecord.id] }, 400);
  assert.match(foreignLink.error, /this CRM project/i);
  saved = await store();
  assertLinks(saved, deal.id, [person.id, company.id, note.id]);

  await request("/api/records/delete", { id: note.id });
  saved = await store();
  assert.equal(record(saved, note.id), undefined);
  assertLinks(saved, deal.id, [person.id, company.id]);
  assert.ok(!saved.records.some((entry) => (entry.fields?.relatedRecordIds || []).includes(note.id)), "deleting a record must remove every saved reciprocal reference");
  assert.ok(!saved.records.some((entry) => (entry.relationships || []).some((relationship) => relationship.recordId === note.id)), "deleting a record must remove every relationship entry");

  console.log("Universal record relationships passed: all five types, reciprocal updates, removal, deletion cleanup, self-link protection, and workspace isolation.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
