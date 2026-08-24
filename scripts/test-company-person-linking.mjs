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
  identityEntities: [
    { id: "identity_company_green_roof", workspaceId: "workspace_test", entityType: "Company", canonicalName: "Green Roof", normalizedName: "green roof", aliases: [], hidden: true, status: "provisional", facts: {}, createdAt: now, updatedAt: now },
    { id: "identity_company_green_roof_construction", workspaceId: "workspace_test", entityType: "Company", canonicalName: "Green Roof Construction", normalizedName: "green roof construction", aliases: [], hidden: true, status: "provisional", facts: {}, createdAt: now, updatedAt: now }
  ],
  identityIdentifiers: [{ id: "identifier_green_roof_domain", workspaceId: "workspace_test", entityId: "identity_company_green_roof", type: "domain", value: "greenroof.example", verified: false, sourceRecordId: "", createdAt: now, updatedAt: now }],
  identityMentions: [], identityRelationships: [], identityRecordLinks: [], identityReconciliation: {},
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

function hiddenCompanies(saved) { return saved.identityEntities.filter((entity) => entity.workspaceId === "workspace_test" && entity.entityType === "Company"); }
function hiddenEntityFor(saved, record) {
  const link = saved.identityRecordLinks.find((entry) => entry.workspaceId === "workspace_test" && entry.recordId === record.id);
  return link ? saved.identityEntities.find((entity) => entity.id === link.entityId) : null;
}

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
  assert.equal(hiddenCompanies(saved).length, 2, "the visible company must reuse its hidden identity without discarding a separate unresolved hidden mention");
  assert.equal(companies[0].metadata.identityEntityId, "identity_company_green_roof");
  assert.equal(hiddenEntityFor(saved, companies[0])?.id, "identity_company_green_roof");
  const aliceIdentity = hiddenEntityFor(saved, people[0]);
  assert.ok(aliceIdentity, "the visible person must be linked to a hidden person identity");
  assert.ok(saved.identityRelationships.some((relationship) => relationship.fromEntityId === aliceIdentity.id && relationship.toEntityId === "identity_company_green_roof" && relationship.type === "associated_with"));

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
  assert.equal(hiddenCompanies(saved).length, 1, "semantic resolution must merge the provisional hidden mention into the canonical hidden company");
  const hiddenGreenRoof = hiddenCompanies(saved)[0];
  assert.equal(hiddenGreenRoof.canonicalName, "Green Roof Construction");
  assert.ok(hiddenGreenRoof.aliases.includes("Green Roof"));
  assert.equal(hiddenEntityFor(saved, companies[0])?.id, hiddenGreenRoof.id);
  assert.deepEqual(new Set(hiddenGreenRoof.facts.personRecordIds), new Set(people.map((person) => person.id)));

  await request("/api/records/commit", { planId: "plan_bob", actionIds: ["action_bob"] });
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(companies.length, 1);
  assert.deepEqual(new Set(companies[0].fields.people.map((person) => person.name)), new Set(["Alice Carter", "Maria Chen", "Bob Singh"]));
  assert.equal(hiddenCompanies(saved).length, 1);
  assert.deepEqual(new Set(hiddenCompanies(saved)[0].facts.personRecordIds), new Set(saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Person").map((record) => record.id)));

  const companyContext = (await request("/api/records/manual", { type: "Note", title: "Green Roof account context", priorityLevel: "normal" }, 201)).record;
  await request("/api/records/manual", { type: "Company", title: "Green Roof", relatedRecordIds: [companyContext.id], priorityLevel: "normal" }, 201);
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(companies.length, 1, "creating a company by a known alias must merge into the canonical company");
  assert.equal(hiddenCompanies(saved).length, 1, "merging a standalone visible alias must not leave a duplicate hidden company");
  assert.ok(companies[0].relationships.some((relationship) => relationship.type === "related_to" && relationship.recordId === companyContext.id), "a merged company must retain the duplicate record's generic relationships");
  assert.ok(saved.records.find((record) => record.id === companyContext.id).relationships.some((relationship) => relationship.type === "related_to" && relationship.recordId === companies[0].id), "a merged company relationship must remain bidirectional");

  await request("/api/records/manual", { type: "Company", title: "Green Roofing Materials", priorityLevel: "normal" }, 201);
  saved = await store();
  companies = saved.records.filter((record) => record.workspaceId === "workspace_test" && record.type === "Company");
  assert.equal(companies.length, 2, "AI must be able to keep a similarly named but distinct company separate");
  assert.equal(hiddenCompanies(saved).length, 2, "a genuinely distinct visible company must have its own hidden identity");
  const materials = companies.find((company) => company.title === "Green Roofing Materials");
  const maria = saved.records.find((record) => record.type === "Person" && record.title === "Maria Chen");
  await request("/api/records/update", { id: maria.id, type: "Person", title: maria.title, email: maria.fields.email, companyName: materials.title, priorityLevel: "normal" });
  saved = await store();
  const original = saved.records.find((record) => record.type === "Company" && record.title === "Green Roof Construction");
  const movedTo = saved.records.find((record) => record.id === materials.id);
  assert.deepEqual(new Set(original.fields.people.map((person) => person.name)), new Set(["Alice Carter", "Bob Singh"]), "moving a person should remove the old company link");
  assert.ok(movedTo.fields.people.some((person) => person.name === "Maria Chen"), "moving a person should add them to the new company");
  const movedMaria = saved.records.find((record) => record.id === maria.id);
  assert.equal(movedMaria.fields.companyRecordId, movedTo.id);
  const originalIdentity = hiddenEntityFor(saved, original);
  const materialsIdentity = hiddenEntityFor(saved, movedTo);
  const mariaIdentity = hiddenEntityFor(saved, movedMaria);
  const mariaCompanyRelationships = saved.identityRelationships.filter((relationship) => relationship.fromEntityId === mariaIdentity.id && relationship.type === "associated_with");
  assert.deepEqual(mariaCompanyRelationships.map((relationship) => relationship.toEntityId), [materialsIdentity.id], "the hidden relationship must move with the visible person");
  assert.ok(!originalIdentity.facts.personRecordIds.includes(movedMaria.id), "the former hidden company must remove the person");
  assert.ok(materialsIdentity.facts.personRecordIds.includes(movedMaria.id), "the new hidden company must include the person");

  console.log("AI company linking passed: visible records and hidden identities share canonical companies, aliases, people, and relationship moves without duplicates.");
} finally {
  child.kill();
  await rm(temporaryDirectory, { recursive: true, force: true });
}
