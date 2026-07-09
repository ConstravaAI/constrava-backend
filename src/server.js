import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const file = path.join(root, "data", "store.json");
const PORT = Number(process.env.PORT || 3000);
const ORIGIN = process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`;
const DEV_EMAIL = "constrava@constravaai.com";
const DEV_LOGIN_KEY_ENV = "DEV_LOGIN_KEY";
const TYPES = ["Lead", "Person", "Company", "Deal", "Task", "Note", "Intake"];
const ACTIONS = ["create", "update", "attach_note", "create_task", "create_deal", "ignore"];

const id = (prefix) => `${prefix}_${crypto.randomBytes(5).toString("hex")}`;
const clean = (value) => String(value || "").replace(/\s+/g, " ").trim();
const clampScore = (value) => Math.max(0, Math.min(100, Number(value) || 0));

function baseRecord(type, title, fields = {}, priorityScore = 40, tags = [], workspaceId = "demo") {
  const now = new Date().toISOString();
  return {
    id: id(type.toLowerCase()),
    workspaceId,
    type,
    title,
    status: type === "Task" || type === "Deal" ? "open" : "active",
    priorityScore,
    priorityReasons: ["Seeded workspace context"],
    tags,
    fields,
    relationships: [],
    sourceIds: ["source_manual"],
    createdAt: now,
    updatedAt: now,
    metadata: {}
  };
}

function starterRecords(workspaceId = "demo") {
  return [
    baseRecord("Company", "Green Valley Roofing", { name: "Green Valley Roofing" }, 82, ["high intent"], workspaceId),
    baseRecord("Person", "John Parker", { email: "john@greenvalley.example", companyName: "Green Valley Roofing" }, 76, ["needs follow-up"], workspaceId),
    baseRecord("Deal", "Scheduling app quote", { value: 4000, stage: "qualified" }, 90, ["budget mentioned"], workspaceId),
    baseRecord("Task", "Follow up with Green Valley Roofing", { taskType: "email" }, 88, ["needs follow-up"], workspaceId)
  ];
}

function seed() {
  return {
    sources: [
      { id: "source_manual", workspaceId: "demo", name: "Manual Notes", type: "manual_note", status: "connected", metadata: {} },
      { id: "source_website", workspaceId: "demo", name: "Website Contact Form", type: "website_form", status: "connected", metadata: { siteId: "site_demo" } },
      { id: "source_email", workspaceId: "demo", name: "Email Inbox", type: "email", status: "ready_to_connect", metadata: {} },
      { id: "source_site", workspaceId: "demo", name: "External Website", type: "website", status: "ready_to_connect", metadata: {} }
    ],
    records: starterRecords("demo"),
    events: [{ id: id("event"), workspaceId: "demo", type: "page_view", siteId: "site_demo", sessionId: "sample", sourceUrl: "/", referrer: "direct", metadata: {}, createdAt: new Date().toISOString() }],
    plans: [],
    reports: [],
    users: [],
    sessions: []
  };
}

function ensureUserWorkspace(storeData, user) {
  if (!user.workspaceId) user.workspaceId = `workspace_${user.id}`;
  if (!storeData.records.some((record) => record.workspaceId === user.workspaceId)) {
    storeData.records.push(...starterRecords(user.workspaceId));
  }
}

function ensureDeveloperAccount(storeData) {
  if (!process.env[DEV_LOGIN_KEY_ENV]) return null;
  let user = storeData.users.find((candidate) => candidate.email === DEV_EMAIL);
  if (!user) {
    user = {
      id: "user_developer",
      email: DEV_EMAIL,
      name: "Constrava Developer",
      role: "developer",
      workspaceId: "workspace_developer",
      createdAt: new Date().toISOString(),
      authProvider: DEV_LOGIN_KEY_ENV
    };
    storeData.users.push(user);
  }
  user.name = user.name || "Constrava Developer";
  user.role = "developer";
  user.workspaceId = user.workspaceId || "workspace_developer";
  user.authProvider = DEV_LOGIN_KEY_ENV;
  ensureUserWorkspace(storeData, user);
  return user;
}

function normalize(storeData) {
  const fresh = seed();
  storeData.sources ||= fresh.sources;
  storeData.records ||= [];
  storeData.events ||= [];
  storeData.plans ||= [];
  storeData.reports ||= [];
  storeData.users ||= [];
  storeData.sessions ||= [];
  for (const starterSource of fresh.sources) {
    if (!storeData.sources.some((source) => source.id === starterSource.id)) storeData.sources.push(starterSource);
  }
  for (const record of storeData.records) record.workspaceId ||= "demo";
  for (const event of storeData.events) event.workspaceId ||= "demo";
  for (const plan of storeData.plans) plan.workspaceId ||= "demo";
  for (const report of storeData.reports) report.workspaceId ||= "demo";
  if (!storeData.records.some((record) => record.workspaceId === "demo")) storeData.records.push(...starterRecords("demo"));
  ensureDeveloperAccount(storeData);
  return storeData;
}

async function store() {
  await fs.mkdir(path.dirname(file), { recursive: true });
  try {
    return normalize(JSON.parse(await fs.readFile(file, "utf8")));
  } catch {
    const fresh = normalize(seed());
    await fs.writeFile(file, JSON.stringify(fresh, null, 2));
    return fresh;
  }
}

async function save(storeData) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, `${JSON.stringify(normalize(storeData), null, 2)}\n`);
}

async function readBody(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { rawText: raw };
  }
}

function send(res, status, data, headers = {}) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(data, null, 2));
}

function html(res, markup) {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(markup);
}

function redirect(res, location) {
  res.writeHead(302, { location, "cache-control": "no-store" });
  res.end();
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const index = part.indexOf("=");
    return [decodeURIComponent(index >= 0 ? part.slice(0, index) : part), decodeURIComponent(index >= 0 ? part.slice(index + 1) : "")];
  }));
}

function passwordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password || ""), salt, 32).toString("hex");
  return { salt, hash };
}

function safeEqualText(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, user) {
  if (!user?.passwordSalt || !user?.passwordHash) return false;
  const { hash } = passwordHash(password, user.passwordSalt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.passwordHash, "hex"));
}

function sessionCookie(sessionId, clear = false) {
  if (clear) return "constrava_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
  return `constrava_session=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`;
}

function currentUser(req, storeData) {
  const sessionId = parseCookies(req).constrava_session;
  if (!sessionId) return null;
  const session = storeData.sessions.find((entry) => entry.id === sessionId);
  if (!session) return null;
  const user = storeData.users.find((entry) => entry.id === session.userId) || null;
  if (user) ensureUserWorkspace(storeData, user);
  return user;
}

function publicUser(user) {
  if (!user) return null;
  return { id: user.id, email: user.email, name: user.name, role: user.role || "user", workspaceId: user.workspaceId };
}

function requestContext(req, url, storeData) {
  if (url.searchParams.get("demo") === "1") return { workspaceId: "demo", demo: true, user: null };
  const user = currentUser(req, storeData);
  if (!user) return null;
  return { workspaceId: user.workspaceId, demo: false, user };
}

function extract(text) {
  const email = text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || "";
  const money = text.match(/\$?\s?([0-9][0-9,]*(?:\.\d{2})?)/)?.[0] || "";
  const value = money ? Number(money.replace(/[$,\s]/g, "")) : 0;
  const companyName = text.match(/(?:from|at|with)\s+([A-Z][A-Za-z0-9&'. -]{2,70}?)(?:\s+wants|\s+needs|\s+asked|\s+has|,|\.|$)/)?.[1] || "";
  const name = text.match(/^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)(?:\s+from|\s+at|\s+wants|\s+needs|,)/)?.[1] || "";
  const request = text.match(/(?:wants|needs|requested|looking for)\s+(.+?)(?:\.|,| with | and | budget | follow)/i)?.[1] || text.slice(0, 110);
  return { email, value, companyName: clean(companyName), name: clean(name), request: clean(request) };
}

function priority(text, fields) {
  const lower = text.toLowerCase();
  let value = 38;
  const reasons = [];
  if (fields.value || /\$|budget|approved/.test(lower)) {
    value += fields.value >= 8000 ? 24 : 18;
    reasons.push(fields.value ? `Budget/value around $${fields.value.toLocaleString()}` : "Budget mentioned");
  }
  if (/urgent|asap|deadline|tomorrow|this week|end of the month/.test(lower)) {
    value += 20;
    reasons.push("Urgency or deadline language");
  }
  if (/quote|proposal|estimate|contract|ready|hire/.test(lower)) {
    value += 18;
    reasons.push("Buying intent detected");
  }
  if (/follow up|follow-up|call|email|schedule|meeting/.test(lower)) {
    value += 12;
    reasons.push("Clear next action");
  }
  return { score: clampScore(value), reasons: reasons.length ? reasons : ["General activity"] };
}

function tagsFor(text, fields) {
  const lower = text.toLowerCase();
  const tags = new Set();
  if (fields.value || /\$|budget/.test(lower)) tags.add("budget mentioned");
  if (/urgent|deadline|tomorrow|this week/.test(lower)) tags.add("urgent");
  if (/quote|proposal|estimate/.test(lower)) tags.add("quote requested");
  if (/follow|call|email|schedule/.test(lower)) tags.add("needs follow-up");
  if (!tags.size) tags.add("needs review");
  return [...tags];
}

function action(actionType, recordType, fields, priorityData, tags, reasoning) {
  return { id: id("action"), actionType, recordType, targetRecordId: null, confidence: 0.82, fields, relationships: [], tags, priorityScore: priorityData.score, priorityReasons: priorityData.reasons, reasoning, duplicateCandidates: [] };
}

async function makePlan(storeData, input, workspaceId) {
  const rawText = clean(input.rawText || input.text || JSON.stringify(input.fields || input));
  const fields = extract(rawText);
  const priorityData = priority(rawText, fields);
  const tags = tagsFor(rawText, fields);
  const plan = { planId: id("plan"), workspaceId, source: { kind: input.kind || "manual", sourceId: input.sourceId || "source_manual", rawText }, summary: "Prepared structured business records from the incoming information.", riskLevel: "review", aiProvider: "local-fallback", createdAt: new Date().toISOString(), actions: [] };
  plan.actions.push(action("create", "Intake", { title: `Intake from ${input.kind || "manual input"}`, rawText }, priorityData, tags, "Preserve the raw submission."));
  if (fields.companyName) plan.actions.push(action("create", "Company", { name: fields.companyName }, priorityData, tags, "Company-like name detected."));
  if (fields.name || fields.email) plan.actions.push(action("create", "Person", { name: fields.name || fields.email.split("@")[0] || "New Contact", email: fields.email, companyName: fields.companyName }, priorityData, tags, "Contact details detected."));
  if (/quote|proposal|estimate|budget|project|contract|automation|website|app|build/i.test(rawText)) plan.actions.push(action("create_deal", "Deal", { title: fields.request || "New opportunity", value: fields.value, stage: priorityData.score > 75 ? "qualified" : "new" }, priorityData, tags, "Opportunity language found."));
  if (/follow|call|email|schedule|meeting|tomorrow|monday|tuesday|wednesday|thursday|friday/i.test(rawText)) plan.actions.push(action("create_task", "Task", { title: fields.companyName ? `Follow up with ${fields.companyName}` : "Follow up on new intake", taskType: /call|meeting|schedule/i.test(rawText) ? "call" : "email" }, priorityData, ["needs follow-up", ...tags], "Next-action language found."));
  plan.actions.push(action("attach_note", "Note", { title: "Source note", body: rawText }, priorityData, tags, "Keep the original context attached."));
  return plan;
}

function commitPlan(storeData, planId, actionIds, workspaceId) {
  const plan = storeData.plans.find((entry) => entry.planId === planId && entry.workspaceId === workspaceId);
  if (!plan) throw Object.assign(new Error("Plan not found"), { status: 404 });
  const selected = new Set(actionIds || plan.actions.map((entry) => entry.id));
  const now = new Date().toISOString();
  const committed = [];
  for (const entry of plan.actions.filter((candidate) => selected.has(candidate.id) && candidate.actionType !== "ignore")) {
    const title = clean(entry.fields.title || entry.fields.name || entry.fields.companyName || entry.fields.request || `${entry.recordType} record`);
    const record = { id: id(entry.recordType.toLowerCase()), workspaceId, type: entry.recordType, title, status: entry.recordType === "Task" || entry.recordType === "Deal" ? "open" : "active", priorityScore: clampScore(entry.priorityScore), priorityReasons: entry.priorityReasons || [], tags: entry.tags || [], fields: entry.fields || {}, relationships: entry.relationships || [], sourceIds: [plan.source?.sourceId].filter(Boolean), createdAt: now, updatedAt: now, metadata: { planId, aiProvider: plan.aiProvider, reasoning: entry.reasoning } };
    storeData.records.push(record);
    committed.push(record);
  }
  plan.status = "committed";
  plan.committedAt = now;
  plan.committedRecordIds = committed.map((record) => record.id);
  return { plan, committed };
}

function filtered(storeData, query = {}, workspaceId = "demo") {
  let rows = storeData.records.filter((record) => record.workspaceId === workspaceId);
  if (query.type) rows = rows.filter((record) => record.type.toLowerCase() === query.type.toLowerCase());
  if (query.q) rows = rows.filter((record) => JSON.stringify(record).toLowerCase().includes(query.q.toLowerCase()));
  rows = [...rows];
  rows.sort(query.sort === "newest" ? (a, b) => b.createdAt.localeCompare(a.createdAt) : (a, b) => Number(b.priorityScore || 0) - Number(a.priorityScore || 0));
  return rows;
}

function dashboardSummary(storeData, workspaceId) {
  const rows = filtered(storeData, {}, workspaceId);
  const deals = rows.filter((record) => record.type === "Deal");
  const tasks = rows.filter((record) => record.type === "Task");
  const leads = rows.filter((record) => ["Lead", "Person", "Intake"].includes(record.type));
  const opportunity = deals.reduce((sum, deal) => sum + Number(deal.fields?.value || 0), 0);
  const highPriority = rows.filter((record) => record.priorityScore >= 75).slice(0, 6);
  return {
    metrics: { newLeads: leads.length, activeDeals: deals.length, overdueTasks: tasks.filter((task) => task.fields?.dueDate && task.fields.dueDate < new Date().toISOString().slice(0, 10)).length, conversionRate: leads.length ? Math.round((deals.length / leads.length) * 100) : 0, trafficEvents: storeData.events.filter((event) => event.workspaceId === workspaceId).length, revenueOpportunity: opportunity, aiCreatedRecords: rows.filter((record) => record.metadata?.aiProvider).length },
    sourcePerformance: storeData.sources.map((source) => ({ ...source, records: rows.filter((record) => record.sourceIds?.includes(source.id)).length, events: storeData.events.filter((event) => event.workspaceId === workspaceId && event.siteId === source.metadata?.siteId).length })),
    highPriority,
    recommendedActions: highPriority.slice(0, 4).map((record) => ({ title: `Review ${record.title}`, reason: record.priorityReasons?.[0] || "High priority", recordId: record.id })),
    recentRecords: rows.slice(0, 8)
  };
}

function snippet() {
  return '<script>(function(){var endpoint=' + JSON.stringify(ORIGIN + '/api/analytics/events?demo=1') + ';var sid=localStorage.getItem("constrava_session_id")||Math.random().toString(36).slice(2);localStorage.setItem("constrava_session_id",sid);function send(type,metadata){fetch(endpoint,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({workspaceId:"demo",siteId:"site_demo",type:type,sessionId:sid,sourceUrl:location.href,referrer:document.referrer,metadata:metadata||{}})}).catch(function(){})}send("page_view",{title:document.title});document.addEventListener("submit",function(e){var data={};Array.prototype.forEach.call(e.target.elements||[],function(i){if(i.name)data[i.name]=i.value});send("form_submission",{fields:data})},true)})();</script>';
}

function publicPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Constrava</title><style>
:root{--blue:#061a33;--blue2:#0d2b52;--blue3:#174675;--soft:#eaf2ff;--line:#d9e3f2;--ink:#071629;--muted:#607089;--bg:#f7fbff}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 15% 0%,#dbeaff 0,#f7fbff 34%,#fff 100%);color:var(--ink);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.55}.wrap{width:min(1100px,calc(100% - 36px));margin:auto}header{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.88);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}.nav{height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:12px;font-size:24px;font-weight:950;letter-spacing:-.04em;text-decoration:none;color:var(--blue)}.mark{width:42px;height:42px;border-radius:15px;background:linear-gradient(135deg,var(--blue),var(--blue3));color:white;display:grid;place-items:center;box-shadow:0 14px 32px rgba(6,26,51,.22)}.links{display:flex;gap:18px;align-items:center}.links a{color:#263d5c;text-decoration:none;font-weight:850;font-size:14px}.btn{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;padding:13px 18px;border:1px solid var(--line);text-decoration:none;font-weight:950;background:white;color:var(--blue);box-shadow:0 12px 30px rgba(6,26,51,.08)}.btn.primary{background:var(--blue);color:white;border-color:var(--blue)}.hero{padding:82px 0 56px}.heroGrid{display:grid;grid-template-columns:1.05fr .95fr;gap:44px;align-items:center}.eyebrow{display:inline-flex;align-items:center;border:1px solid #bed0ea;background:var(--soft);color:var(--blue);border-radius:999px;padding:7px 12px;font-size:13px;font-weight:950}h1{font-size:clamp(44px,7vw,76px);line-height:.96;letter-spacing:-.075em;margin:18px 0;color:var(--blue)}.lead{font-size:20px;color:var(--muted);max-width:650px}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}.note{font-size:14px;color:#71829b;margin-top:18px}.preview{background:white;border:1px solid rgba(6,26,51,.16);border-radius:34px;padding:18px;box-shadow:0 34px 90px rgba(6,26,51,.14)}.chrome{background:var(--blue);border-radius:24px;padding:14px}.dots{display:flex;gap:7px;margin-bottom:12px}.dots span{width:10px;height:10px;border-radius:999px;background:#8fa7c7}.screen{background:#f9fbff;border-radius:18px;padding:18px}.badge{display:inline-flex;background:var(--soft);color:var(--blue);border:1px solid #bed0ea;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:950}.metricGrid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.metric,.record{background:white;border:1px solid var(--line);border-radius:16px;padding:12px}.metric b{display:block;font-size:24px;color:var(--blue)}.record{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;margin-top:10px}.score{background:var(--soft);color:var(--blue);border-radius:999px;padding:5px 8px;font-weight:950}section{padding:62px 0}h2{font-size:clamp(32px,5vw,52px);line-height:1;letter-spacing:-.055em;margin:0 0 14px;color:var(--blue)}.sectionLead{font-size:18px;color:var(--muted);max-width:760px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:24px}.card{background:rgba(255,255,255,.94);border:1px solid var(--line);border-radius:24px;padding:22px;box-shadow:0 18px 48px rgba(6,26,51,.08)}.card h3{margin:0 0 8px;font-size:22px;color:var(--blue)}.card p{margin:0;color:var(--muted)}.cta{background:linear-gradient(135deg,var(--blue),var(--blue2));color:white;border-radius:34px;padding:34px;display:flex;align-items:center;justify-content:space-between;gap:22px}.cta h2{color:white}.cta p{color:#d8e6f8;margin:0}footer{border-top:1px solid var(--line);padding:26px 0;color:#71829b;font-size:14px}@media(max-width:850px){.heroGrid,.cards{grid-template-columns:1fr}.links a:not(.btn){display:none}.cta{display:block}.metricGrid{grid-template-columns:1fr}.record{grid-template-columns:1fr}.nav{height:auto;padding:14px 0;align-items:flex-start}}
</style></head><body><header><div class="wrap nav"><a class="brand" href="/"><span class="mark">C</span>Constrava</a><nav class="links"><a href="#features">Features</a><a href="#how">How it works</a><a class="btn" href="/demo">View demo</a><a class="btn primary" href="/signin">Sign in</a></nav></div></header><main><section class="hero"><div class="wrap heroGrid"><div><span class="eyebrow">Simple AI workspace for business records</span><h1>Turn messy business activity into organized records.</h1><p class="lead">Constrava helps capture leads, notes, forms, and follow-ups, then organizes them into records, tasks, deals, and priorities so a business knows what to act on next.</p><div class="actions"><a class="btn primary" href="/signin">Sign in to dashboard</a><a class="btn" href="/demo">View demo</a></div><p class="note">Demo: constravaai.com/demo · Sign in: constravaai.com/signin</p></div><div class="preview"><div class="chrome"><div class="dots"><span></span><span></span><span></span></div><div class="screen"><span class="badge">Dashboard</span><h3 style="margin:8px 0;color:#061a33">Priority Command Center</h3><div class="metricGrid"><div class="metric"><small>New leads</small><b>18</b></div><div class="metric"><small>Open deals</small><b>$42k</b></div><div class="metric"><small>Tasks</small><b>7</b></div></div><div class="record"><span class="badge">Deal</span><div><b>Scheduling app quote</b><br><small>Budget mentioned · follow-up needed</small></div><span class="score">90</span></div><div class="record"><span class="badge">Task</span><div><b>Follow up with new intake</b><br><small>Clear next action detected</small></div><span class="score">88</span></div></div></div></div></div></section><section id="features"><div class="wrap"><h2>What the tool does</h2><p class="sectionLead">Constrava is a lightweight operating dashboard for customer and business activity.</p><div class="cards"><article class="card"><h3>Capture records</h3><p>Store leads, companies, people, deals, tasks, notes, and website form activity in one place.</p></article><article class="card"><h3>Use AI to sort</h3><p>AI reviews messy text and suggests useful records, tags, priorities, and follow-ups.</p></article><article class="card"><h3>Act faster</h3><p>The dashboard highlights high-priority records, recommended actions, and business reports.</p></article></div></div></section><section id="how"><div class="wrap cta"><div><h2>Try the demo or sign in.</h2><p>The public demo shows a preview workspace. Signing in opens the dashboard connected to that saved account.</p></div><div class="actions"><a class="btn primary" href="/signin">Sign in</a><a class="btn" href="/demo">Demo</a></div></div></section></main><footer><div class="wrap">© 2026 Constrava · <a href="/demo">Demo</a> · <a href="/signin">Sign in</a></div></footer></body></html>`;
}

function signInPage() {
  const devConfigured = Boolean(process.env[DEV_LOGIN_KEY_ENV]);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in | Constrava</title><style>
:root{--blue:#061a33;--soft:#eaf2ff;--line:#d9e3f2;--ink:#071629;--muted:#607089}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at top,#dbeaff,#f7fbff 38%,#fff);color:var(--ink);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:24px}.shell{width:min(900px,100%);display:grid;grid-template-columns:.9fr 1.1fr;gap:22px}.panel,.card{background:white;border:1px solid var(--line);border-radius:28px;box-shadow:0 24px 70px rgba(6,26,51,.10)}.panel{padding:30px;background:linear-gradient(135deg,var(--blue),#0d2b52);color:white}.panel p{color:#d8e6f8}.brand{font-size:24px;font-weight:950}.card{padding:28px}h1{margin:0 0 10px;font-size:42px;letter-spacing:-.06em;color:var(--blue)}p{color:var(--muted);line-height:1.55}.tabs{display:flex;gap:8px;margin:18px 0}.tabs button{flex:1;border:1px solid var(--line);background:white;border-radius:999px;padding:10px;font-weight:900;color:var(--blue);cursor:pointer}.tabs button.active{background:var(--blue);color:white}label{font-size:13px;font-weight:900;color:#263d5c}input{width:100%;border:1px solid var(--line);border-radius:14px;padding:13px;margin:6px 0 12px;font:inherit}button.submit{width:100%;display:flex;justify-content:center;border:0;border-radius:999px;padding:13px 16px;background:var(--blue);color:white;text-decoration:none;font-weight:900;font:inherit;cursor:pointer}.back{margin-top:12px;width:100%;display:flex;justify-content:center;border-radius:999px;padding:13px 16px;background:white;color:var(--blue);border:1px solid var(--line);text-decoration:none;font-weight:900}.status{min-height:22px;font-size:14px;color:#9d2b2b}.hint{font-size:13px;background:var(--soft);border:1px solid var(--line);padding:10px;border-radius:14px}@media(max-width:800px){.shell{grid-template-columns:1fr}}
</style></head><body><main class="shell"><section class="panel"><div class="brand">Constrava</div><h1 style="color:white">Welcome back.</h1><p>Sign in with a saved account, or create a new one. After authentication, Constrava opens the dashboard connected to your personal workspace.</p></section><section class="card"><h1 id="title">Sign in</h1><p id="copy">Enter your saved account details to open your dashboard.</p>${devConfigured ? `<p class="hint">Developer login is enabled for ${DEV_EMAIL}. Use the configured ${DEV_LOGIN_KEY_ENV} value as the password.</p>` : ""}<div class="tabs"><button id="loginTab" class="active">Sign in</button><button id="signupTab">Create account</button></div><form id="authForm"><div id="nameWrap" style="display:none"><label>Name</label><input name="name" autocomplete="name" placeholder="Your name"></div><label>Email</label><input name="email" type="email" autocomplete="email" placeholder="you@company.com" required><label>Password</label><input name="password" type="password" autocomplete="current-password" placeholder="At least 6 characters" required><button class="submit" id="submitBtn">Sign in</button></form><p class="status" id="status"></p><a class="back" href="/">Back to homepage</a></section></main><script>
let mode="login";const setMode=function(next){mode=next;loginTab.classList.toggle("active",mode==="login");signupTab.classList.toggle("active",mode==="signup");nameWrap.style.display=mode==="signup"?"block":"none";title.textContent=mode==="signup"?"Create account":"Sign in";copy.textContent=mode==="signup"?"Create a saved account and open your personal dashboard.":"Enter your saved account details to open your dashboard.";submitBtn.textContent=mode==="signup"?"Create account":"Sign in";status.textContent=""};loginTab.onclick=function(){setMode("login")};signupTab.onclick=function(){setMode("signup")};authForm.onsubmit=async function(e){e.preventDefault();status.textContent="";submitBtn.disabled=true;try{const payload=Object.fromEntries(new FormData(authForm));const r=await fetch(mode==="signup"?"/api/auth/signup":"/api/auth/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});const data=await r.json();if(!r.ok)throw new Error(data.error||"Authentication failed");location.href="/dashboard"}catch(err){status.textContent=err.message}finally{submitBtn.disabled=false}};
</script></body></html>`;
}

function appPage({ demo = false, user = null } = {}) {
  const workspaceLabel = demo ? "Demo workspace" : `Personal workspace${user?.email ? " · " + user.email : ""}`;
  const apiSuffix = demo ? "demo=1" : "";
  const signoutCopy = demo ? "Exit demo" : "Sign out";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Constrava Dashboard</title><style>
:root{--blue:#061a33;--blue2:#0d2b52;--blue3:#174675;--soft:#eaf2ff;--line:#d9e3f2;--ink:#071629;--muted:#607089;--bg:#f7fbff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}.topbar{height:68px;background:var(--blue);color:white;display:flex;align-items:center;justify-content:space-between;padding:0 18px;box-shadow:0 16px 40px rgba(6,26,51,.18);position:sticky;top:0;z-index:10}.leftTools{display:flex;align-items:center;gap:18px;min-width:0}.brand{font-weight:950;font-size:20px;letter-spacing:-.04em;white-space:nowrap}.tabs{display:flex;align-items:center;gap:6px}.tab{border:0;background:transparent;color:#d8e6f8;font:inherit;font-weight:900;padding:11px 14px;border-radius:999px;cursor:pointer}.tab.active,.tab:hover{background:white;color:var(--blue)}.rightTools{display:flex;align-items:center;gap:8px}.iconBtn{width:42px;height:42px;border-radius:999px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.08);color:white;font-size:19px;display:grid;place-items:center;cursor:pointer}.iconBtn:hover{background:rgba(255,255,255,.18)}.shell{width:min(1180px,calc(100% - 36px));margin:28px auto}.workspace{display:flex;justify-content:space-between;gap:14px;align-items:end;margin-bottom:18px}.workspace h1{margin:0;color:var(--blue);font-size:40px;letter-spacing:-.055em}.muted{color:var(--muted)}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,1fr)}.two{grid-template-columns:1.1fr .9fr}.three{grid-template-columns:repeat(3,1fr)}.card{background:white;border:1px solid var(--line);border-radius:18px;box-shadow:0 16px 40px rgba(6,26,51,.08)}.in{padding:18px}.row{display:flex;justify-content:space-between;gap:12px}.metricValue{font-size:32px;font-weight:950;color:var(--blue)}.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;background:var(--soft);border:1px solid #bed0ea;color:var(--blue);font-size:12px;font-weight:900}.hot{background:#dceaff}.item{padding:13px 0;border-top:1px solid var(--line)}.item:first-child{border-top:0}.primary{background:var(--blue);color:white;border:0;padding:10px 14px;font-weight:900;border-radius:10px;cursor:pointer}.secondary,input,select,textarea{border:1px solid var(--line);background:white;padding:10px;border-radius:10px;font:inherit}textarea{min-height:130px;width:100%}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}.stack{display:grid;gap:12px}pre{white-space:pre-wrap;background:#061a33;color:#eef6ff;padding:14px;border-radius:12px;overflow:auto}.resource{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center}.resourceIcon{width:42px;height:42px;border-radius:14px;background:var(--soft);display:grid;place-items:center;color:var(--blue);font-size:20px}dialog{border:1px solid var(--line);border-radius:18px;padding:0;box-shadow:0 24px 80px rgba(6,26,51,.22);max-width:min(440px,calc(100vw - 30px))}dialog::backdrop{background:rgba(6,26,51,.42)}.modalHead,.modalBody,.modalFoot{padding:18px}.modalHead{border-bottom:1px solid var(--line)}.modalHead h2{margin:0;color:var(--blue)}.modalFoot{border-top:1px solid var(--line);display:flex;justify-content:flex-end;gap:10px}@media(max-width:850px){.topbar{height:auto;display:block;padding:14px}.leftTools{display:block}.tabs{margin-top:12px;overflow:auto}.workspace{display:block}.metrics,.two,.three{grid-template-columns:1fr}.resource{grid-template-columns:1fr}.shell{margin-top:18px}}
</style></head><body><header class="topbar"><div class="leftTools"><div class="brand">Constrava</div><nav class="tabs" aria-label="Dashboard sections"><button class="tab active" data-tab="analytics">Analytics</button><button class="tab" data-tab="crm">CRM</button><button class="tab" data-tab="resources">Connected Resources</button></nav></div><div class="rightTools"><button class="iconBtn" id="settingsIcon" title="Settings" aria-label="Settings">⚙</button><button class="iconBtn" id="signoutIcon" title="${signoutCopy}" aria-label="${signoutCopy}">⎋</button></div></header><main class="shell"><section class="workspace"><div><p class="muted" id="workspaceLabel">${workspaceLabel}</p><h1 id="pageTitle">Analytics</h1></div><div><input id="search" placeholder="Search records, tasks, leads..."> <button class="primary" id="aiAdd">AI Add</button></div></section><section id="app"></section></main><dialog id="settingsDialog"><div class="modalHead"><h2>Settings</h2></div><div class="modalBody"><p class="muted">Workspace settings will live here. Current workspace:</p><input value="${workspaceLabel.replaceAll('"', "&quot;")}"></div><div class="modalFoot"><button class="secondary" id="closeSettings">Close</button></div></dialog><dialog id="signoutDialog"><div class="modalHead"><h2>Are you sure?</h2></div><div class="modalBody"><p class="muted">This will ${demo ? "leave the demo" : "sign you out"} and return you to the public homepage.</p></div><div class="modalFoot"><button class="secondary" id="cancelSignout">Cancel</button><button class="primary" id="confirmSignout">${signoutCopy}</button></div></dialog><dialog id="planDialog"><div class="modalHead"><h2 id="planTitle"></h2></div><div class="modalBody" id="planBody"></div><div class="modalFoot"><button class="secondary" id="closePlan">Cancel</button><button class="primary" id="commitPlan">Commit selected</button></div></dialog><script>
const DEMO=${JSON.stringify(demo)};const API_SUFFIX=${JSON.stringify(apiSuffix)};let S={tab:"analytics",records:[],plans:[],plan:null,summary:null};const esc=function(v){return String(v==null?"":v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;")};function url(p){return API_SUFFIX?p+(p.includes("?")?"&":"?")+API_SUFFIX:p}async function api(p,o){o=o||{};const r=await fetch(url(p),{...o,headers:{"content-type":"application/json",...(o.headers||{})}});const d=await r.json();if(r.status===401){location.href="/signin";return null}if(!r.ok)throw Error(d.error||"Request failed");return d}function money(v){return Number(v||0).toLocaleString(undefined,{style:"currency",currency:"USD",maximumFractionDigits:0})}function metric(n,v,t){return '<div class="card"><div class="in"><p class="muted">'+n+'</p><div class="metricValue">'+v+'</div><p class="muted">'+t+'</p></div></div>'}function row(r){return '<div class="item"><div class="row"><div><span class="pill">'+esc(r.type)+'</span> <b>'+esc(r.title)+'</b><p class="muted">'+esc((r.priorityReasons||[])[0]||"")+'</p></div><span class="pill hot">'+Math.round(r.priorityScore||0)+'</span></div></div>'}async function load(){let out=await Promise.all([api("/api/dashboard/summary"),api("/api/records"),api("/api/sources"),api("/api/plans"),api("/api/reports"),api("/api/analytics/events")]);S.summary=out[0];S.records=out[1].records;S.sources=out[2].sources;S.snippet=out[2].snippet;S.plans=out[3].plans;S.reports=out[4].reports;S.events=out[5].events}function tab(name){S.tab=name;document.querySelectorAll(".tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));pageTitle.textContent=name==="crm"?"CRM":name==="resources"?"Connected Resources":"Analytics";render()}function render(){let h="",m=S.summary.metrics;if(S.tab==="analytics"){h='<div class="grid metrics">'+metric("New leads",m.newLeads,"Intakes and contacts")+metric("Active deals",m.activeDeals,money(m.revenueOpportunity))+metric("Traffic events",m.trafficEvents,"Captured activity")+metric("AI-created",m.aiCreatedRecords,"Committed records")+'</div><div class="grid two" style="margin-top:16px"><section class="card"><div class="in"><h2>Recommended actions</h2>'+S.summary.recommendedActions.map(a=>'<div class="item"><b>'+esc(a.title)+'</b><p class="muted">'+esc(a.reason)+'</p></div>').join("")+'</div></section><section class="card"><div class="in"><h2>Recent analytics events</h2>'+S.events.slice(0,8).map(e=>'<div class="item"><b>'+esc(e.type)+'</b><p class="muted">'+esc(e.sourceUrl||e.siteId||"")+'</p></div>').join("")+'</div></section></div>'}if(S.tab==="crm"){h='<div class="toolbar"><input id="crmFilter" placeholder="Filter CRM records"><button class="primary" id="filterBtn">Apply</button></div><div class="grid three">'+["Person","Company","Deal","Task","Intake","Note"].map(t=>'<section class="card"><div class="in"><h2>'+t+'</h2>'+S.records.filter(r=>r.type===t).map(row).join("")+'</div></section>').join("")+'</div><section class="card" style="margin-top:16px"><div class="in stack"><h2>AI record creation</h2><form id="aiForm"><textarea name="rawText" required placeholder="Paste a lead, email, form submission, or messy note"></textarea><button class="primary">Create AI plan</button></form></div></section>'}if(S.tab==="resources"){h='<div class="grid two"><section class="card"><div class="in"><h2>Outside resources</h2>'+S.sources.map(s=>'<div class="item resource"><div class="resourceIcon">'+(s.type.includes("email")?"✉":s.type.includes("website")?"⌁":"●")+'</div><div><b>'+esc(s.name)+'</b><p class="muted">'+esc(s.type)+' · '+esc(s.status)+'</p></div><button class="secondary">Configure</button></div>').join("")+'</div></section><section class="card"><div class="in"><h2>Website tracker</h2><p class="muted">Use this snippet on an outside website to send analytics events into the demo source.</p><pre>'+esc(S.snippet)+'</pre></div></section></div><section class="card" style="margin-top:16px"><div class="in"><h2>Recent plans</h2>'+S.plans.slice(0,8).map(p=>'<div class="item"><b>'+esc(p.summary)+'</b><p class="muted">'+esc(p.aiProvider)+' · '+p.actions.length+' actions</p><button class="secondary" data-plan="'+esc(p.planId)+'">Review</button></div>').join("")+'</div></section>'}app.innerHTML=h;bind()}function bind(){document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>tab(b.dataset.tab));let f=document.getElementById("aiForm");if(f)f.onsubmit=async e=>{e.preventDefault();let p=await api("/api/records/plan",{method:"POST",body:JSON.stringify(Object.fromEntries(new FormData(f)))});await refresh("crm");openPlan(p.plan.planId)};let filter=document.getElementById("filterBtn");if(filter)filter.onclick=async()=>{let d=await api("/api/records?q="+encodeURIComponent(document.getElementById("crmFilter").value));S.records=d.records;render()};document.querySelectorAll("[data-plan]").forEach(b=>b.onclick=()=>openPlan(b.dataset.plan))}async function refresh(nextTab){await load();if(nextTab)S.tab=nextTab;render()}function openPlan(planId){S.plan=S.plans.find(p=>p.planId===planId);if(!S.plan)return;planTitle.textContent=S.plan.summary;planBody.innerHTML=S.plan.actions.map(a=>'<label class="item" style="display:grid;grid-template-columns:auto 1fr;gap:12px"><input type="checkbox" checked value="'+a.id+'"><span><b>'+esc(a.actionType)+' '+esc(a.recordType)+'</b><p class="muted">'+esc(a.reasoning)+'</p><pre>'+esc(JSON.stringify(a.fields,null,2))+'</pre></span></label>').join("");planDialog.showModal()}async function signout(){if(DEMO){location.href="/";return}await fetch("/api/auth/logout",{method:"POST"});location.href="/"}document.getElementById("settingsIcon").onclick=()=>settingsDialog.showModal();document.getElementById("signoutIcon").onclick=()=>signoutDialog.showModal();document.getElementById("closeSettings").onclick=()=>settingsDialog.close();document.getElementById("cancelSignout").onclick=()=>signoutDialog.close();document.getElementById("confirmSignout").onclick=signout;document.getElementById("closePlan").onclick=()=>planDialog.close();document.getElementById("commitPlan").onclick=async()=>{let ids=[...document.querySelectorAll("#planBody input:checked")].map(i=>i.value);await api("/api/records/commit",{method:"POST",body:JSON.stringify({planId:S.plan.planId,actionIds:ids})});planDialog.close();await refresh("crm")};document.getElementById("aiAdd").onclick=()=>tab("crm");document.getElementById("search").onkeydown=async e=>{if(e.key==="Enter"){let d=await api("/api/search/natural",{method:"POST",body:JSON.stringify({query:search.value})});S.records=d.records;tab("crm")}};refresh("analytics");
</script></body></html>`;
}

async function auth(req, res, url, storeData) {
  if (req.method === "GET" && url.pathname === "/api/auth/me") {
    const user = currentUser(req, storeData);
    return send(res, user ? 200 : 401, { user: publicUser(user), developerAccountConfigured: Boolean(process.env[DEV_LOGIN_KEY_ENV]) });
  }
  if (req.method === "POST" && url.pathname === "/api/auth/logout") {
    const sessionId = parseCookies(req).constrava_session;
    storeData.sessions = storeData.sessions.filter((entry) => entry.id !== sessionId);
    await save(storeData);
    return send(res, 200, { ok: true }, { "set-cookie": sessionCookie("", true) });
  }
  if (req.method === "POST" && (url.pathname === "/api/auth/signup" || url.pathname === "/api/auth/login")) {
    const body = await readBody(req);
    const email = clean(body.email).toLowerCase();
    const password = String(body.password || "");
    if (!email.includes("@")) return send(res, 400, { error: "Enter a valid email address." });
    if (password.length < 6) return send(res, 400, { error: "Password must be at least 6 characters." });

    let user = storeData.users.find((candidate) => candidate.email === email);
    if (url.pathname === "/api/auth/signup") {
      if (email === DEV_EMAIL) return send(res, 403, { error: "The developer account is managed by the server login key." });
      if (user) return send(res, 409, { error: "An account with that email already exists. Sign in instead." });
      const pass = passwordHash(password);
      user = { id: id("user"), email, name: clean(body.name) || email.split("@")[0], role: "user", workspaceId: "", passwordSalt: pass.salt, passwordHash: pass.hash, createdAt: new Date().toISOString() };
      user.workspaceId = `workspace_${user.id}`;
      storeData.users.push(user);
      ensureUserWorkspace(storeData, user);
    } else if (email === DEV_EMAIL) {
      if (!process.env[DEV_LOGIN_KEY_ENV]) return send(res, 503, { error: `${DEV_LOGIN_KEY_ENV} is not configured on the server.` });
      if (!safeEqualText(password, process.env[DEV_LOGIN_KEY_ENV])) return send(res, 401, { error: "Developer login key is incorrect." });
      user = ensureDeveloperAccount(storeData);
    } else {
      if (!user || !verifyPassword(password, user)) return send(res, 401, { error: "Email or password is incorrect." });
      ensureUserWorkspace(storeData, user);
    }

    const session = { id: id("session"), userId: user.id, createdAt: new Date().toISOString() };
    storeData.sessions.push(session);
    await save(storeData);
    return send(res, 200, { ok: true, user: publicUser(user) }, { "set-cookie": sessionCookie(session.id) });
  }
  return send(res, 404, { error: "Auth route not found" });
}

async function api(req, res, url) {
  const storeData = await store();
  if (url.pathname.startsWith("/api/auth/")) return await auth(req, res, url, storeData);
  if (req.method === "GET" && url.pathname === "/api/health") return send(res, 200, { ok: true, aiConfigured: Boolean(process.env.OPENAI_API_KEY), developerAccount: DEV_EMAIL, developerLoginKeyVariable: DEV_LOGIN_KEY_ENV, developerAccountConfigured: Boolean(process.env[DEV_LOGIN_KEY_ENV]), homepage: "/", demo: "/demo", signin: "/signin", dashboard: "/dashboard" });

  const ctx = requestContext(req, url, storeData);
  if (!ctx) return send(res, 401, { error: "Sign in required." });

  if (req.method === "GET" && url.pathname === "/api/dashboard/summary") return send(res, 200, dashboardSummary(storeData, ctx.workspaceId));
  if (req.method === "GET" && url.pathname === "/api/records") return send(res, 200, { records: filtered(storeData, Object.fromEntries(url.searchParams.entries()), ctx.workspaceId) });
  if (req.method === "GET" && url.pathname === "/api/sources") return send(res, 200, { sources: storeData.sources, snippet: snippet() });
  if (req.method === "GET" && url.pathname === "/api/plans") return send(res, 200, { plans: storeData.plans.filter((plan) => plan.workspaceId === ctx.workspaceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "GET" && url.pathname === "/api/reports") return send(res, 200, { reports: storeData.reports.filter((report) => report.workspaceId === ctx.workspaceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "GET" && url.pathname === "/api/analytics/events") return send(res, 200, { events: storeData.events.filter((event) => event.workspaceId === ctx.workspaceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });

  if (req.method === "POST" && url.pathname === "/api/records/plan") {
    const plan = await makePlan(storeData, await readBody(req), ctx.workspaceId);
    storeData.plans.push(plan);
    await save(storeData);
    return send(res, 200, { plan });
  }
  if (req.method === "POST" && url.pathname === "/api/records/commit") {
    const body = await readBody(req);
    const result = commitPlan(storeData, body.planId, body.actionIds, ctx.workspaceId);
    await save(storeData);
    return send(res, 200, result);
  }
  if (req.method === "POST" && url.pathname === "/api/analytics/events") {
    const body = await readBody(req);
    const event = { id: id("event"), workspaceId: ctx.workspaceId, type: clean(body.type || "custom"), siteId: clean(body.siteId || "site_demo"), sessionId: clean(body.sessionId || id("session")), sourceUrl: clean(body.sourceUrl || ""), referrer: clean(body.referrer || ""), metadata: body.metadata || {}, createdAt: new Date().toISOString() };
    storeData.events.push(event);
    await save(storeData);
    return send(res, 202, { accepted: true, eventId: event.id });
  }
  if (req.method === "POST" && url.pathname === "/api/sources/form") {
    const body = await readBody(req);
    const plan = await makePlan(storeData, { kind: "website_form", sourceId: "source_website", rawText: body.rawText || JSON.stringify(body.fields || body) }, ctx.workspaceId);
    storeData.plans.push(plan);
    await save(storeData);
    return send(res, 202, { accepted: true, plan });
  }
  if (req.method === "POST" && url.pathname === "/api/uploads/import") {
    const body = await readBody(req);
    const plan = await makePlan(storeData, { kind: "upload", rawText: String(body.csv || body.text || "").split(/\r?\n/).slice(0, 100).join("\n") }, ctx.workspaceId);
    storeData.plans.push(plan);
    await save(storeData);
    return send(res, 200, { plan });
  }
  if (req.method === "POST" && url.pathname === "/api/search/natural") {
    const body = await readBody(req);
    const q = clean(body.query).toLowerCase();
    return send(res, 200, { plan: { q, explanation: "Converted plain English into safe filters." }, records: filtered(storeData, { q, type: /deal|quote/.test(q) ? "Deal" : /task|follow/.test(q) ? "Task" : "" }, ctx.workspaceId) });
  }
  if (req.method === "POST" && url.pathname === "/api/reports/generate") {
    const summary = dashboardSummary(storeData, ctx.workspaceId);
    const content = { title: "Business Activity Report", factualSummary: [`${summary.metrics.newLeads} lead/contact records are tracked.`, `${summary.metrics.activeDeals} active deals represent $${summary.metrics.revenueOpportunity.toLocaleString()} in opportunity.`, `${summary.metrics.trafficEvents} analytics events have been captured.`], recommendations: summary.recommendedActions.map((entry) => `${entry.title}: ${entry.reason}`) };
    const report = { id: id("report"), workspaceId: ctx.workspaceId, title: content.title, content, createdAt: new Date().toISOString() };
    storeData.reports.push(report);
    await save(storeData);
    return send(res, 200, { report });
  }
  return send(res, 404, { error: "API route not found" });
}

http.createServer(async (req, res) => {
  try {
    const storeData = await store();
    const url = new URL(req.url, ORIGIN);
    if (url.pathname.startsWith("/api/")) return await api(req, res, url);
    if (url.pathname === "/demo") return html(res, appPage({ demo: true }));
    if (["/dashboard", "/app"].includes(url.pathname)) {
      const user = currentUser(req, storeData);
      if (!user) return redirect(res, "/signin");
      ensureUserWorkspace(storeData, user);
      await save(storeData);
      return html(res, appPage({ demo: false, user }));
    }
    if (["/signin", "/login"].includes(url.pathname)) return html(res, signInPage());
    return html(res, publicPage());
  } catch (error) {
    send(res, error.status || 500, { error: error.message });
  }
}).listen(PORT, () => console.log(`Constrava is running at ${ORIGIN}`));
