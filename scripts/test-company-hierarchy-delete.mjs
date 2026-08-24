import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-company-hierarchy-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43138;
const origin = `http://127.0.0.1:${port}`;
const now = new Date().toISOString();

await writeFile(dataFile, JSON.stringify({
  sources: [], records: [], draftRecords: [], events: [], plans: [], ingestionEvents: [], formConnections: [], emailConnections: [], adsenseConnections: [], googleAnalyticsConnections: [], businessConnections: [], messagingConnections: [], websiteConnections: [], reports: [], googleAccounts: [], microsoftAccounts: [], calendarConnections: [],
  identityEntities: [], identityIdentifiers: [], identityMentions: [], identityRelationships: [], identityRecordLinks: [], identityReconciliation: {},
  workspaces: [{ id: "workspace_test", name: "Hierarchy Test", ownerUserId: "user_test", createdAt: now, updatedAt: now }],
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
  throw new Error(`Company hierarchy test server did not start.\n${serverOutput}`);
}

async function request(pathname, body, expectedStatus = 200) {
  const response = await fetch(`${origin}${pathname}`, { method: "POST", headers: { cookie: "constrava_session=session_test", "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await response.json();
  assert.equal(response.status, expectedStatus, JSON.stringify(data));
  return data;
}

async function store() { return JSON.parse(await readFile(dataFile, "utf8")); }

try {
  await waitForServer();
  const parent = (await request("/api/records/manual", { type: "Company", title: "Apex Holdings", priorityLevel: "normal" }, 201)).record;
  const subsidiary = (await request("/api/records/manual", { type: "Company", title: "Beacon Product Studio", parentCompanyRecordId: parent.id, priorityLevel: "normal" }, 201)).record;
  const division = (await request("/api/records/manual", { type: "Company", title: "Cedar Research Division", parentCompanyRecordId: subsidiary.id, priorityLevel: "normal" }, 201)).record;

  let saved = await store();
  let savedParent = saved.records.find((record) => record.id === parent.id);
  let savedSubsidiary = saved.records.find((record) => record.id === subsidiary.id);
  let savedDivision = saved.records.find((record) => record.id === division.id);
  assert.equal(savedSubsidiary.fields.parentCompanyRecordId, savedParent.id);
  assert.equal(savedSubsidiary.fields.parentCompanyName, savedParent.title);
  assert.ok(savedSubsidiary.relationships.some((relationship) => relationship.type === "part_of_company" && relationship.recordId === savedParent.id));
  assert.deepEqual(savedParent.fields.companies, [{ recordId: savedSubsidiary.id, name: savedSubsidiary.title }]);
  assert.ok(savedParent.relationships.some((relationship) => relationship.type === "has_company" && relationship.recordId === savedSubsidiary.id));
  assert.equal(savedDivision.fields.parentCompanyRecordId, savedSubsidiary.id);

  await request("/api/records/update", { id: savedParent.id, type: "Company", title: "Apex Holdings Group", parentCompanyRecordId: "", priorityLevel: "normal" });
  saved = await store();
  savedParent = saved.records.find((record) => record.id === parent.id);
  savedSubsidiary = saved.records.find((record) => record.id === subsidiary.id);
  assert.equal(savedSubsidiary.fields.parentCompanyName, savedParent.title, "renaming a parent company must update its child companies");

  await request("/api/records/update", { id: savedSubsidiary.id, type: "Company", title: savedSubsidiary.title, parentCompanyRecordId: savedSubsidiary.id, priorityLevel: "normal" }, 400);
  await request("/api/records/update", { id: savedParent.id, type: "Company", title: savedParent.title, parentCompanyRecordId: savedDivision.id, priorityLevel: "normal" }, 400);
  saved = await store();
  assert.equal(saved.records.find((record) => record.id === savedSubsidiary.id).fields.parentCompanyRecordId, savedParent.id, "rejected self-links must not alter saved data");
  assert.equal(saved.records.find((record) => record.id === savedParent.id).fields.parentCompanyRecordId, undefined, "rejected cycles must not alter saved data");

  const person = (await request("/api/records/manual", { type: "Person", title: "Dana Moss", email: "dana@beacon.example", companyName: savedSubsidiary.title, priorityLevel: "normal" }, 201)).record;
  saved = await store();
  assert.equal(saved.records.find((record) => record.id === person.id).fields.companyRecordId, savedSubsidiary.id);

  await request("/api/records/delete", { id: savedSubsidiary.id });
  saved = await store();
  assert.equal(saved.records.some((record) => record.id === savedSubsidiary.id), false);
  savedParent = saved.records.find((record) => record.id === savedParent.id);
  savedDivision = saved.records.find((record) => record.id === savedDivision.id);
  const detachedPerson = saved.records.find((record) => record.id === person.id);
  assert.equal(savedParent.fields.companies, undefined, "deleting a subsidiary must remove it from its parent company");
  assert.equal(savedDivision.fields.parentCompanyRecordId, undefined, "deleting a parent company must keep and detach its child companies");
  assert.equal(detachedPerson.fields.companyRecordId, undefined, "deleting a company must keep and detach its people");
  assert.equal(detachedPerson.fields.companyName, undefined);
  assert.ok(!saved.identityRecordLinks.some((link) => link.recordId === savedSubsidiary.id), "deleted records must lose their visible identity link");

  const secondPerson = (await request("/api/records/manual", { type: "Person", title: "Eli Stone", email: "eli@apex.example", companyName: savedParent.title, priorityLevel: "normal" }, 201)).record;
  await request("/api/records/delete", { id: secondPerson.id });
  saved = await store();
  savedParent = saved.records.find((record) => record.id === savedParent.id);
  assert.ok(!(savedParent.fields.people || []).some((entry) => entry.recordId === secondPerson.id), "deleting a person must remove it from the company People section");
  assert.equal(saved.records.some((record) => record.id === secondPerson.id), false);

  await request("/api/records/delete", { id: "missing_record" }, 404);
  console.log("Company hierarchy and record deletion passed: explicit parent links are bidirectional, cycle-safe, and cleanly detached on deletion.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
