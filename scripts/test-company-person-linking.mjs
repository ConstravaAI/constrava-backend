import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "constrava-company-linking-"));
const dataFile = path.join(temporaryDirectory, "store.json");
const port = 43137;
const origin = `http://127.0.0.1:${port}`;
const now = new Date().toISOString();

const plan = { planId: "plan_draft_person", workspaceId: "workspace_test", source: { kind: "manual", sourceId: "source_manual" }, summary: "Draft person", riskLevel: "review", aiProvider: "test", createdAt: now, actions: [], draftRecordIds: ["draft_alice"] };
const bobPlan = { planId: "plan_bob", workspaceId: "workspace_test", source: { kind: "manual", sourceId: "source_manual" }, summary: "Add Bob", riskLevel: "review", aiProvider: "test", createdAt: now, actions: [{ id: "action_bob", actionType: "create", recordType: "Person", targetRecordId: null, fields: { name: "Bob Singh", email: "bob@greenroof.example", companyName: "Green Roof" }, relationships: [], tags: [], priorityScore: 55, priorityReasons: ["Test"], reasoning: "Test person" }] };
await writeFile(dataFile, JSON.stringify({
  sources: [], records: [],
  draftRecords: [{ id: "draft_alice", workspaceId: "workspace_test", type: "Person", title: "Alice Carter", status: "draft", priorityScore: 60, priorityReasons: ["Test"], tags: [], fields: { name: "Alice Carter", email: "alice@greenroof.example", companyName: "Green Roof" }, relationships: [], sourceIds: ["source_manual"], createdAt: now, updatedAt: now, metadata: { planId: plan.planId, actionId: "action_alice", actionType: "create" } }],
  events: [], plans: [plan, bobPlan], ingestionEvents: [], formConnections: [], emailConnections: [], adsenseConnections: [], googleAnalyticsConnections: [], businessConnections: [], messagingConnections: [], websiteConnections: [], reports: [], googleAccounts: [], microsoftAccounts: [], calendarConnections: [],
  identityEntities: [], identityIdentifiers: [], identityMentions: [], identityRelationships: [], identityRecordLinks: [], identityReconciliation: {},
  workspaces: [{ id: "workspace_test", name: "Company Linking Test", ownerUserId: "user_test", createdAt: now, updatedAt: now }],
  workspaceMembers: [{ id: "membership_test", workspaceId: "workspace_test", userId: "user_test", role: "owner", status: "active", joinedAt: now }], workspaceInvitations: [],
  users: [{ id: "user_test", email: "owner@example.com", name: "Owner", role: "user", accountType: "standard", workspaceId: "workspace_test", createdAt: now }],
  sessions: [{ id: "session_test", userId: "user_test", activeWorkspaceId: "workspace_test", createdAt: now, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() }]
}), "utf8");

const child = spawn(process.execPath, ["--import", pathToFileURL(path.join(root, "scripts", "test-company-resolution-fetch-mock.mjs")).href, path.join(root, "scripts", "start-runtime.mjs")], {
  cwd: root,
  env: { ...process.env, PORT: String(port), PUBLIC_ORIGIN: origin, DATA_FILE: dataFile, DATABASE_URL: "", OPENAI_API_KEY: "company-linking-test-key" },
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
  throw new Error(`Company linking test server did not start.\n${serverOutput}`);
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
  await request("/api/records/drafts/publish", { id: "draft_alice" });
  let saved = await store();
  let companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  let people = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Person");
  assert.equal(companies.length, 1, "publishing a person should automatically create one visible company record");
  assert.equal(companies[0].title, "Green Roof");
  assert.deepEqual(companies[0].fields.people.map((person) => person.name), ["Alice Carter"]);
  assert.equal(people[0].fields.companyRecordId, companies[0].id);
  assert.ok(people[0].relationships.some((relationship) => relationship.type === "works_at" && relationship.recordId === companies[0].id));

  await request("/api/records/manual", { type: "Person", title: "Maria Chen", email: "maria@greenroof.example", companyName: "Green Roof Construction", priorityLevel: "normal" }, 201);
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  people = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Person");
  assert.equal(companies.length, 1, "AI semantic resolution must reuse the existing company instead of creating a duplicate");
  assert.equal(companies[0].title, "Green Roof Construction", "the company should adopt the most specific supported name");
  assert.ok(companies[0].fields.aliases.includes("Green Roof"));
  assert.deepEqual(new Set(companies[0].fields.people.map((person) => person.name)), new Set(["Alice Carter", "Maria Chen"]));
  assert.ok(people.every((person) => person.fields.companyName === "Green Roof Construction"), "the canonical company name should update on every connected person");
  assert.equal(companies[0].metadata.companyResolution.provider, "openai");

  await request("/api/records/commit", { planId: "plan_bob", actionIds: ["action_bob"] });
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(companies.length, 1);
  assert.deepEqual(new Set(companies[0].fields.people.map((person) => person.name)), new Set(["Alice Carter", "Maria Chen", "Bob Singh"]));

  await request("/api/records/manual", { type: "Company", title: "Green Roof", priorityLevel: "normal" }, 201);
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(companies.length, 1, "creating a company by a known alias must merge into the canonical company");

  await request("/api/records/manual", { type: "Company", title: "Green Roofing Materials", priorityLevel: "normal" }, 201);
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(companies.length, 2, "AI must be able to keep a similarly named but distinct company separate");
  const materials = companies.find((company) => company.title === "Green Roofing Materials");
  const maria = saved.records.find((record) => record.type === "Person" && record.title === "Maria Chen");
  await request("/api/records/update", { id: maria.id, type: "Person", title: maria.title, email: maria.fields.email, companyName: materials.title, priorityLevel: "normal" });
  saved = await store();
  const original = saved.records.find((record) => record.type === "Company" && record.title === "Green Roof Construction");
  const movedTo = saved.records.find((record) => record.id === materials.id);
  assert.deepEqual(new Set(original.fields.people.map((person) => person.name)), new Set(["Alice Carter", "Bob Singh"]), "moving a person should remove the old company link");
  assert.ok(movedTo.fields.people.some((person) => person.name === "Maria Chen"), "moving a person should add them to the new company");
  assert.equal(saved.records.find((record) => record.id === maria.id).fields.companyRecordId, movedTo.id);

  console.log("AI company linking passed: automatic company creation, semantic reuse, canonical naming, visible people lists, plan commits, alias deduplication, and relationship moves.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
