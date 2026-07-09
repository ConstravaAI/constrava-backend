import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const storeFile = path.join(root, "data", "store.json");
const PORT = Number(process.env.PORT || 3000);
const ORIGIN = process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`;
const COOKIE_NAME = "constrava_session";
const DEV_EMAIL = "constrava@constravaai.com";
const DEV_LOGIN_KEY_ENV = "DEV_LOGIN_KEY";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

const id = (prefix) => `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
const clean = (value) => String(value || "").replace(/\s+/g, " ").trim();
const esc = (value) => String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[char]));
const clamp = (value) => Math.max(0, Math.min(100, Number(value) || 0));

function isSecure(req) {
  return String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https" || ORIGIN.startsWith("https://");
}

function sessionCookie(req, sessionId, clear = false) {
  const secure = isSecure(req) ? "; Secure" : "";
  if (clear) return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=0`;
  return `${COOKIE_NAME}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${SESSION_MAX_AGE_SECONDS}`;
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const index = part.indexOf("=");
    return [decodeURIComponent(index >= 0 ? part.slice(0, index) : part), decodeURIComponent(index >= 0 ? part.slice(index + 1) : "")];
  }));
}

function baseRecord(type, title, fields = {}, priorityScore = 40, tags = [], workspaceId = "demo") {
  const now = new Date().toISOString();
  return { id: id(type.toLowerCase()), workspaceId, type, title, status: type === "Task" || type === "Deal" ? "open" : "active", priorityScore, priorityReasons: ["Seeded workspace context"], tags, fields, relationships: [], sourceIds: ["source_manual"], createdAt: now, updatedAt: now, metadata: {} };
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
    plans: [], reports: [], users: [], sessions: []
  };
}

function ensureUserWorkspace(storeData, user) {
  if (!user.workspaceId) user.workspaceId = `workspace_${user.id}`;
  if (!storeData.records.some((record) => record.workspaceId === user.workspaceId)) storeData.records.push(...starterRecords(user.workspaceId));
}

function ensureDeveloperAccount(storeData) {
  if (!process.env[DEV_LOGIN_KEY_ENV]) return null;
  let user = storeData.users.find((candidate) => candidate.email === DEV_EMAIL);
  if (!user) {
    user = { id: "user_developer", email: DEV_EMAIL, name: "Constrava Developer", role: "developer", workspaceId: "workspace_developer", createdAt: new Date().toISOString(), authProvider: DEV_LOGIN_KEY_ENV };
    storeData.users.push(user);
  }
  user.role = "developer";
  user.authProvider = DEV_LOGIN_KEY_ENV;
  user.workspaceId ||= "workspace_developer";
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
  for (const source of fresh.sources) if (!storeData.sources.some((entry) => entry.id === source.id)) storeData.sources.push(source);
  for (const collection of [storeData.records, storeData.events, storeData.plans, storeData.reports]) for (const item of collection) item.workspaceId ||= "demo";
  if (!storeData.records.some((record) => record.workspaceId === "demo")) storeData.records.push(...starterRecords("demo"));
  ensureDeveloperAccount(storeData);
  return storeData;
}

async function store() {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });
  try { return normalize(JSON.parse(await fs.readFile(storeFile, "utf8"))); }
  catch { const fresh = normalize(seed()); await fs.writeFile(storeFile, `${JSON.stringify(fresh, null, 2)}\n`); return fresh; }
}

async function save(storeData) {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });
  await fs.writeFile(storeFile, `${JSON.stringify(normalize(storeData), null, 2)}\n`);
}

async function readBody(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return { rawText: raw }; }
}

function json(res, status, data, headers = {}) {
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

function passwordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(String(password || ""), salt, 32).toString("hex") };
}

function safeEqualText(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, user) {
  if (!user?.passwordSalt || !user?.passwordHash) return false;
  const { hash } = passwordHash(password, user.passwordSalt);
  return safeEqualText(hash, user.passwordHash);
}

function currentUser(req, storeData) {
  const sessionId = parseCookies(req)[COOKIE_NAME];
  if (!sessionId) return null;
  const session = storeData.sessions.find((entry) => entry.id === sessionId);
  if (!session) return null;
  const user = storeData.users.find((entry) => entry.id === session.userId) || null;
  if (user) ensureUserWorkspace(storeData, user);
  return user;
}

function publicUser(user) {
  return user ? { id: user.id, email: user.email, name: user.name, role: user.role || "user", workspaceId: user.workspaceId } : null;
}

function context(req, url, storeData) {
  if (url.searchParams.get("demo") === "1") return { workspaceId: "demo", demo: true, user: null };
  const user = currentUser(req, storeData);
  return user ? { workspaceId: user.workspaceId, demo: false, user } : null;
}

function records(storeData, query = {}, workspaceId = "demo") {
  let rows = storeData.records.filter((record) => record.workspaceId === workspaceId);
  if (query.type) rows = rows.filter((record) => record.type.toLowerCase() === query.type.toLowerCase());
  if (query.q) rows = rows.filter((record) => JSON.stringify(record).toLowerCase().includes(String(query.q).toLowerCase()));
  rows = [...rows];
  rows.sort(query.sort === "newest" ? (a, b) => b.createdAt.localeCompare(a.createdAt) : (a, b) => Number(b.priorityScore || 0) - Number(a.priorityScore || 0));
  return rows;
}

function summary(storeData, workspaceId) {
  const rows = records(storeData, {}, workspaceId);
  const deals = rows.filter((record) => record.type === "Deal");
  const tasks = rows.filter((record) => record.type === "Task");
  const leads = rows.filter((record) => ["Lead", "Person", "Intake"].includes(record.type));
  const opportunity = deals.reduce((sum, deal) => sum + Number(deal.fields?.value || 0), 0);
  const highPriority = rows.filter((record) => record.priorityScore >= 75).slice(0, 6);
  return { metrics: { newLeads: leads.length, activeDeals: deals.length, overdueTasks: tasks.filter((task) => task.fields?.dueDate && task.fields.dueDate < new Date().toISOString().slice(0, 10)).length, conversionRate: leads.length ? Math.round((deals.length / leads.length) * 100) : 0, trafficEvents: storeData.events.filter((event) => event.workspaceId === workspaceId).length, revenueOpportunity: opportunity, aiCreatedRecords: rows.filter((record) => record.metadata?.aiProvider).length }, highPriority, recommendedActions: highPriority.slice(0, 4).map((record) => ({ title: `Review ${record.title}`, reason: record.priorityReasons?.[0] || "High priority", recordId: record.id })), recentRecords: rows.slice(0, 8) };
}

function snippet() {
  return '<script>(function(){var endpoint=' + JSON.stringify(ORIGIN + '/api/analytics/events?demo=1') + ';var sid=localStorage.getItem("constrava_session_id")||Math.random().toString(36).slice(2);localStorage.setItem("constrava_session_id",sid);function send(type,metadata){fetch(endpoint,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({workspaceId:"demo",siteId:"site_demo",type:type,sessionId:sid,sourceUrl:location.href,referrer:document.referrer,metadata:metadata||{}})}).catch(function(){})}send("page_view",{title:document.title});document.addEventListener("submit",function(e){var data={};Array.prototype.forEach.call(e.target.elements||[],function(i){if(i.name)data[i.name]=i.value});send("form_submission",{fields:data})},true)})();</script>';
}

function publicPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Constrava</title><style>:root{--blue:#061a33;--soft:#eaf2ff;--line:#d9e3f2;--ink:#071629;--muted:#607089}*{box-sizing:border-box}body{margin:0;background:#f7fbff;color:var(--ink);font-family:Inter,system-ui,sans-serif}.wrap{width:min(1100px,calc(100% - 36px));margin:auto}.nav{height:72px;display:flex;align-items:center;justify-content:space-between}.brand{font-size:24px;font-weight:950;color:var(--blue);text-decoration:none}.links{display:flex;gap:12px;align-items:center}.links a,.btn{color:var(--blue);font-weight:900;text-decoration:none}.btn{border:1px solid var(--line);border-radius:999px;padding:12px 16px;background:white}.primary{background:var(--blue)!important;color:white!important}.hero{padding:82px 0}.heroGrid{display:grid;grid-template-columns:1.05fr .95fr;gap:44px;align-items:center}h1{font-size:clamp(44px,7vw,76px);line-height:.96;letter-spacing:-.075em;margin:18px 0;color:var(--blue)}.lead{font-size:20px;color:var(--muted)}.actions{display:flex;gap:12px;flex-wrap:wrap}.preview,.card{background:white;border:1px solid var(--line);border-radius:28px;padding:22px;box-shadow:0 18px 48px rgba(6,26,51,.08)}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.cta{background:var(--blue);color:white;border-radius:34px;padding:34px;margin:48px 0}footer{border-top:1px solid var(--line);padding:26px 0;color:#71829b}@media(max-width:850px){.heroGrid,.cards{grid-template-columns:1fr}}</style></head><body><header><div class="wrap nav"><a class="brand" href="/">Constrava</a><nav class="links"><a href="#features">Features</a><a class="btn" href="/demo">View demo</a><a class="btn primary" href="/signin">Sign in</a></nav></div></header><main><section class="wrap hero"><div class="heroGrid"><div><p><b>Simple AI workspace for business records</b></p><h1>Turn messy business activity into organized records.</h1><p class="lead">Constrava helps capture leads, notes, forms, and follow-ups, then organizes them into records, tasks, deals, and priorities so a business knows what to act on next.</p><div class="actions"><a class="btn primary" href="/signin">Sign in to dashboard</a><a class="btn" href="/demo">View demo</a></div></div><div class="preview"><h2>Priority Command Center</h2><p>New leads · Open deals · Tasks · Recommended actions</p></div></div></section><section id="features" class="wrap"><h2>What the tool does</h2><div class="cards"><article class="card"><h3>Capture records</h3><p>Store leads, companies, people, deals, tasks, notes, and website form activity.</p></article><article class="card"><h3>Use AI to sort</h3><p>AI suggests records, tags, priorities, and follow-ups.</p></article><article class="card"><h3>Act faster</h3><p>The dashboard highlights what needs attention next.</p></article></div><div class="cta"><h2>Try the demo or sign in.</h2><a class="btn" href="/signin">Sign in</a> <a class="btn" href="/demo">Demo</a></div></section></main><footer><div class="wrap">© 2026 Constrava</div></footer></body></html>`;
}

function signInPage() {
  const devConfigured = Boolean(process.env[DEV_LOGIN_KEY_ENV]);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in | Constrava</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7fbff;color:#071629;font-family:Inter,system-ui,sans-serif}.card{width:min(460px,calc(100% - 36px));background:white;border:1px solid #d9e3f2;border-radius:28px;padding:28px;box-shadow:0 24px 70px rgba(6,26,51,.10)}h1{color:#061a33;font-size:42px;letter-spacing:-.06em}label{font-weight:900;color:#263d5c}input{width:100%;border:1px solid #d9e3f2;border-radius:14px;padding:13px;margin:6px 0 12px;font:inherit}.tabs{display:flex;gap:8px}.tabs button,.submit,.back{flex:1;border:1px solid #d9e3f2;border-radius:999px;padding:12px;font:inherit;font-weight:900;cursor:pointer}.active,.submit{background:#061a33!important;color:white}.back{display:flex;justify-content:center;text-decoration:none;color:#061a33;margin-top:12px}.status{min-height:22px;color:#9d2b2b}.hint{font-size:13px;background:#eaf2ff;border:1px solid #d9e3f2;padding:10px;border-radius:14px}</style></head><body><main class="card"><h1 id="title">Sign in</h1><p id="copy">Enter your saved account details to open your dashboard.</p>${devConfigured ? `<p class="hint">Developer login is enabled for ${DEV_EMAIL}. Use the configured ${DEV_LOGIN_KEY_ENV} value as the password.</p>` : ""}<div class="tabs"><button id="loginTab" class="active">Sign in</button><button id="signupTab">Create account</button></div><form id="authForm"><div id="nameWrap" style="display:none"><label>Name</label><input name="name" autocomplete="name" placeholder="Your name"></div><label>Email</label><input name="email" type="email" autocomplete="email" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="submit" id="submitBtn">Sign in</button></form><p class="status" id="status"></p><a class="back" href="/">Back to homepage</a></main><script>localStorage.removeItem("constrava_session_token");let mode="login";function setMode(next){mode=next;loginTab.classList.toggle("active",mode==="login");signupTab.classList.toggle("active",mode==="signup");nameWrap.style.display=mode==="signup"?"block":"none";title.textContent=mode==="signup"?"Create account":"Sign in";copy.textContent=mode==="signup"?"Create a saved account and open your dashboard.":"Enter your saved account details to open your dashboard.";submitBtn.textContent=mode==="signup"?"Create account":"Sign in";status.textContent=""}loginTab.onclick=function(){setMode("login")};signupTab.onclick=function(){setMode("signup")};authForm.onsubmit=async function(e){e.preventDefault();status.textContent="";submitBtn.disabled=true;try{const payload=Object.fromEntries(new FormData(authForm));const r=await fetch(mode==="signup"?"/api/auth/signup":"/api/auth/login",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});const data=await r.json();if(!r.ok)throw new Error(data.error||"Authentication failed");location.href="/dashboard/"}catch(err){status.textContent=err.message}finally{submitBtn.disabled=false}};</script></body></html>`;
}

function appPage({ demo = false, user = null } = {}) {
  const workspaceLabel = demo ? "Demo workspace" : `Personal workspace${user?.email ? " · " + user.email : ""}`;
  const apiSuffix = demo ? "demo=1" : "";
  const signoutCopy = demo ? "Exit demo" : "Log out";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Constrava Dashboard</title><style>:root{--blue:#061a33;--soft:#eaf2ff;--line:#d9e3f2;--muted:#607089;--bg:#f7fbff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#071629;font-family:Inter,system-ui,sans-serif}.topbar{background:var(--blue);color:white;display:flex;align-items:center;justify-content:space-between;padding:14px 18px;position:sticky;top:0}.leftTools,.rightTools,.tabs{display:flex;align-items:center;gap:10px}.brand{font-weight:950;font-size:20px}.tab{border:0;background:transparent;color:#d8e6f8;font:inherit;font-weight:900;padding:11px 14px;border-radius:999px;cursor:pointer}.tab.active,.tab:hover{background:white;color:var(--blue)}.settingsIcon{width:42px;height:42px;border-radius:999px;border:1px solid rgba(255,255,255,.28);background:rgba(255,255,255,.08);color:white;font-size:19px;cursor:pointer}.settingsIcon.active,.settingsIcon:hover{background:white;color:var(--blue)}.logoutText{border:1px solid rgba(255,255,255,.28);background:white;color:var(--blue);border-radius:999px;padding:10px 15px;font:inherit;font-weight:950;cursor:pointer}.shell{width:min(1180px,calc(100% - 36px));margin:28px auto}.workspace{display:flex;justify-content:space-between;gap:14px;align-items:end;margin-bottom:18px}.workspace h1{margin:0;color:var(--blue);font-size:40px;letter-spacing:-.055em}.muted{color:var(--muted)}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,1fr)}.two{grid-template-columns:1.1fr .9fr}.card{background:white;border:1px solid var(--line);border-radius:18px;box-shadow:0 16px 40px rgba(6,26,51,.08)}.in{padding:18px}.metricValue{font-size:32px;font-weight:950;color:var(--blue)}.pill{display:inline-flex;padding:4px 9px;border-radius:999px;background:var(--soft);border:1px solid #bed0ea;color:var(--blue);font-size:12px;font-weight:900}.item{padding:13px 0;border-top:1px solid var(--line)}.item:first-child{border-top:0}.primary{background:var(--blue);color:white;border:0;padding:10px 14px;font-weight:900;border-radius:10px;cursor:pointer}.secondary,input,select,textarea{border:1px solid var(--line);background:white;padding:10px;border-radius:10px;font:inherit}.resource{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center}.resourceIcon{width:42px;height:42px;border-radius:14px;background:var(--soft);display:grid;place-items:center;color:var(--blue);font-size:20px}pre{white-space:pre-wrap;background:#061a33;color:#eef6ff;padding:14px;border-radius:12px;overflow:auto}.empty{min-height:280px;display:grid;place-items:center;text-align:center;padding:34px}.empty h2{font-size:34px;margin:0 0 8px;color:var(--blue)}.empty p{max-width:560px;margin:0 auto;color:var(--muted)}dialog{border:1px solid var(--line);border-radius:18px;padding:0;box-shadow:0 24px 80px rgba(6,26,51,.22)}.modalHead,.modalBody,.modalFoot{padding:18px}.modalFoot{border-top:1px solid var(--line);display:flex;justify-content:flex-end;gap:10px}@media(max-width:850px){.topbar{display:block}.leftTools{display:block}.tabs,.rightTools{margin-top:12px;overflow:auto}.workspace,.metrics,.two{display:block}.card{margin-bottom:16px}}</style></head><body><header class="topbar"><div class="leftTools"><div class="brand">Constrava</div><nav class="tabs"><button class="tab active" data-tab="analytics">Analytics</button><button class="tab" data-tab="crm">CRM</button><button class="tab" data-tab="resources">Connected Resources</button></nav></div><div class="rightTools"><button class="settingsIcon" id="settingsButton" title="Settings">⚙</button><button class="logoutText" id="logoutButton">${signoutCopy}</button></div></header><main class="shell"><section class="workspace"><div><p class="muted">${esc(workspaceLabel)}</p><h1 id="pageTitle">Analytics</h1></div><div><input id="search" placeholder="Search records, tasks, leads..."> <button class="primary" id="aiAdd">AI Add</button></div></section><section id="app"></section></main><dialog id="signoutDialog"><div class="modalHead"><h2>Are you sure?</h2></div><div class="modalBody"><p class="muted">This will ${demo ? "leave the demo" : "log you out"} and return you to the public homepage.</p></div><div class="modalFoot"><button class="secondary" id="cancelSignout">Cancel</button><button class="primary" id="confirmSignout">${signoutCopy}</button></div></dialog><dialog id="planDialog"><div class="modalHead"><h2 id="planTitle"></h2></div><div class="modalBody" id="planBody"></div><div class="modalFoot"><button class="secondary" id="closePlan">Cancel</button><button class="primary" id="commitPlan">Commit selected</button></div></dialog><script>localStorage.removeItem("constrava_session_token");const DEMO=${JSON.stringify(demo)};const API_SUFFIX=${JSON.stringify(apiSuffix)};const WORKSPACE_LABEL=${JSON.stringify(workspaceLabel)};let S={tab:"analytics",records:[],plans:[],plan:null,summary:null};const esc=function(v){return String(v==null?"":v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;")};function url(p){return API_SUFFIX?p+(p.includes("?")?"&":"?")+API_SUFFIX:p}async function api(p,o){o=o||{};const r=await fetch(url(p),{...o,credentials:"include",headers:{"content-type":"application/json",...(o.headers||{})}});const d=await r.json();if(r.status===401){location.href="/signin";return null}if(!r.ok)throw Error(d.error||"Request failed");return d}function money(v){return Number(v||0).toLocaleString(undefined,{style:"currency",currency:"USD",maximumFractionDigits:0})}function metric(n,v,t){return '<div class="card"><div class="in"><p class="muted">'+n+'</p><div class="metricValue">'+v+'</div><p class="muted">'+t+'</p></div></div>'}async function load(){let out=await Promise.all([api("/api/dashboard/summary"),api("/api/records"),api("/api/sources"),api("/api/plans"),api("/api/reports"),api("/api/analytics/events")]);S.summary=out[0];S.records=out[1].records;S.sources=out[2].sources;S.snippet=out[2].snippet;S.plans=out[3].plans;S.reports=out[4].reports;S.events=out[5].events}function tab(name){S.tab=name;document.querySelectorAll(".tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));document.getElementById("settingsButton").classList.toggle("active",name==="settings");pageTitle.textContent=name==="crm"?"CRM":name==="resources"?"Connected Resources":name==="settings"?"Settings":"Analytics";render()}function render(){let h="",m=S.summary.metrics;if(S.tab==="analytics"){h='<div class="grid metrics">'+metric("New leads",m.newLeads,"Intakes and contacts")+metric("Active deals",m.activeDeals,money(m.revenueOpportunity))+metric("Traffic events",m.trafficEvents,"Captured activity")+metric("AI-created",m.aiCreatedRecords,"Committed records")+'</div><div class="grid two" style="margin-top:16px"><section class="card"><div class="in"><h2>Recommended actions</h2>'+S.summary.recommendedActions.map(a=>'<div class="item"><b>'+esc(a.title)+'</b><p class="muted">'+esc(a.reason)+'</p></div>').join("")+'</div></section><section class="card"><div class="in"><h2>Recent analytics events</h2>'+S.events.slice(0,8).map(e=>'<div class="item"><b>'+esc(e.type)+'</b><p class="muted">'+esc(e.sourceUrl||e.siteId||"")+'</p></div>').join("")+'</div></section></div>'}if(S.tab==="crm"){h='<section class="card empty"><div><span class="pill">CRM</span><h2>CRM tab cleared</h2><p>This space has been cleared out. The underlying records and APIs are still available in the backend, but the CRM tab no longer shows the record cards, filters, or AI creation form.</p></div></section>'}if(S.tab==="resources"){h='<div class="grid two"><section class="card"><div class="in"><h2>Outside resources</h2>'+S.sources.map(s=>'<div class="item resource"><div class="resourceIcon">'+(s.type.includes("email")?"✉":s.type.includes("website")?"⌁":"●")+'</div><div><b>'+esc(s.name)+'</b><p class="muted">'+esc(s.type)+' · '+esc(s.status)+'</p></div><button class="secondary">Configure</button></div>').join("")+'</div></section><section class="card"><div class="in"><h2>Website tracker</h2><p class="muted">Use this snippet on an outside website to send analytics events into the demo source.</p><pre>'+esc(S.snippet)+'</pre></div></section></div><section class="card" style="margin-top:16px"><div class="in"><h2>Recent plans</h2>'+S.plans.slice(0,8).map(p=>'<div class="item"><b>'+esc(p.summary)+'</b><p class="muted">'+esc(p.aiProvider)+' · '+p.actions.length+' actions</p><button class="secondary" data-plan="'+esc(p.planId)+'">Review</button></div>').join("")+'</div></section>'}if(S.tab==="settings"){h='<div class="grid two"><section class="card"><div class="in"><h2>Workspace settings</h2><label>Workspace</label><input value="'+esc(WORKSPACE_LABEL)+'"><label>Theme</label><select><option>White and dark blue</option></select><button class="primary">Save settings</button></div></section><section class="card"><div class="in"><h2>Account</h2><p class="muted">Your login is kept by a persistent browser cookie. Reloading the page should keep this dashboard open until you log out.</p><div class="item"><b>Session</b><p class="muted">Saved in this browser for up to 30 days.</p></div></div></section></div>'}app.innerHTML=h;bind()}function bind(){document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>tab(b.dataset.tab));document.querySelectorAll("[data-plan]").forEach(b=>b.onclick=()=>openPlan(b.dataset.plan))}async function refresh(nextTab){await load();if(nextTab)S.tab=nextTab;render()}function openPlan(planId){S.plan=S.plans.find(p=>p.planId===planId);if(!S.plan)return;planTitle.textContent=S.plan.summary;planBody.innerHTML=S.plan.actions.map(a=>'<label class="item" style="display:grid;grid-template-columns:auto 1fr;gap:12px"><input type="checkbox" checked value="'+a.id+'"><span><b>'+esc(a.actionType)+' '+esc(a.recordType)+'</b><p class="muted">'+esc(a.reasoning)+'</p><pre>'+esc(JSON.stringify(a.fields,null,2))+'</pre></span></label>').join("");planDialog.showModal()}async function signout(){localStorage.removeItem("constrava_session_token");if(DEMO){location.href="/";return}await fetch("/api/auth/logout",{method:"POST",credentials:"include"});location.href="/"}document.getElementById("settingsButton").onclick=()=>tab("settings");document.getElementById("logoutButton").onclick=()=>signoutDialog.showModal();document.getElementById("cancelSignout").onclick=()=>signoutDialog.close();document.getElementById("confirmSignout").onclick=signout;document.getElementById("closePlan").onclick=()=>planDialog.close();document.getElementById("commitPlan").onclick=async()=>{let ids=[...document.querySelectorAll("#planBody input:checked")].map(i=>i.value);await api("/api/records/commit",{method:"POST",body:JSON.stringify({planId:S.plan.planId,actionIds:ids})});planDialog.close();await refresh("resources")};document.getElementById("aiAdd").onclick=()=>tab("crm");document.getElementById("search").onkeydown=async e=>{if(e.key==="Enter"){let d=await api("/api/search/natural",{method:"POST",body:JSON.stringify({query:search.value})});S.records=d.records;tab("crm")}};refresh("analytics");</script></body></html>`;
}

async function auth(req, res, route, storeData) {
  if (req.method === "GET" && route === "/api/auth/me") return json(res, currentUser(req, storeData) ? 200 : 401, { user: publicUser(currentUser(req, storeData)), developerAccountConfigured: Boolean(process.env[DEV_LOGIN_KEY_ENV]) });
  if (req.method === "POST" && route === "/api/auth/logout") {
    const sessionId = parseCookies(req)[COOKIE_NAME];
    storeData.sessions = storeData.sessions.filter((entry) => entry.id !== sessionId);
    await save(storeData);
    return json(res, 200, { ok: true }, { "set-cookie": sessionCookie(req, "", true) });
  }
  if (req.method === "POST" && (route === "/api/auth/signup" || route === "/api/auth/login")) {
    const body = await readBody(req);
    const email = clean(body.email).toLowerCase();
    const password = String(body.password || "");
    if (!email.includes("@")) return json(res, 400, { error: "Enter a valid email address." });
    if (password.length < 6) return json(res, 400, { error: "Password must be at least 6 characters." });
    let user = storeData.users.find((candidate) => candidate.email === email);
    if (route === "/api/auth/signup") {
      if (email === DEV_EMAIL) return json(res, 403, { error: "The developer account is managed by the server login key." });
      if (user) return json(res, 409, { error: "An account with that email already exists. Sign in instead." });
      const pass = passwordHash(password);
      user = { id: id("user"), email, name: clean(body.name) || email.split("@")[0], role: "user", workspaceId: "", passwordSalt: pass.salt, passwordHash: pass.hash, createdAt: new Date().toISOString() };
      user.workspaceId = `workspace_${user.id}`;
      storeData.users.push(user);
      ensureUserWorkspace(storeData, user);
    } else if (email === DEV_EMAIL) {
      if (!process.env[DEV_LOGIN_KEY_ENV]) return json(res, 503, { error: `${DEV_LOGIN_KEY_ENV} is not configured on the server.` });
      if (!safeEqualText(password, process.env[DEV_LOGIN_KEY_ENV])) return json(res, 401, { error: "Developer login key is incorrect." });
      user = ensureDeveloperAccount(storeData);
    } else {
      if (!user || !verifyPassword(password, user)) return json(res, 401, { error: "Email or password is incorrect." });
      ensureUserWorkspace(storeData, user);
    }
    const session = { id: id("session"), userId: user.id, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + SESSION_MAX_AGE_SECONDS * 1000).toISOString() };
    storeData.sessions.push(session);
    await save(storeData);
    return json(res, 200, { ok: true, user: publicUser(user) }, { "set-cookie": sessionCookie(req, session.id) });
  }
  return json(res, 404, { error: "Auth route not found" });
}

async function api(req, res, url, route) {
  const storeData = await store();
  if (route.startsWith("/api/auth/")) return await auth(req, res, route, storeData);
  if (req.method === "GET" && route === "/api/health") return json(res, 200, { ok: true, cookieName: COOKIE_NAME, sessionMaxAgeDays: 30, secureCookie: isSecure(req), developerAccountConfigured: Boolean(process.env[DEV_LOGIN_KEY_ENV]), homepage: "/", demo: "/demo", signin: "/signin", dashboard: "/dashboard" });
  const ctx = context(req, url, storeData);
  if (!ctx) return json(res, 401, { error: "Sign in required." });
  if (req.method === "GET" && route === "/api/dashboard/summary") return json(res, 200, summary(storeData, ctx.workspaceId));
  if (req.method === "GET" && route === "/api/records") return json(res, 200, { records: records(storeData, Object.fromEntries(url.searchParams.entries()), ctx.workspaceId) });
  if (req.method === "GET" && route === "/api/sources") return json(res, 200, { sources: storeData.sources, snippet: snippet() });
  if (req.method === "GET" && route === "/api/plans") return json(res, 200, { plans: storeData.plans.filter((plan) => plan.workspaceId === ctx.workspaceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "GET" && route === "/api/reports") return json(res, 200, { reports: storeData.reports.filter((report) => report.workspaceId === ctx.workspaceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "GET" && route === "/api/analytics/events") return json(res, 200, { events: storeData.events.filter((event) => event.workspaceId === ctx.workspaceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "POST" && route === "/api/records/commit") return json(res, 200, { plan: null, committed: [] });
  return json(res, 404, { error: "API route not found" });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, ORIGIN);
    const route = url.pathname.replace(/\/+$/, "") || "/";
    if (route.startsWith("/api/")) return await api(req, res, url, route);
    const storeData = await store();
    if (route === "/demo") return html(res, appPage({ demo: true }));
    if (["/dashboard", "/app"].includes(route)) {
      const user = currentUser(req, storeData);
      if (!user) return redirect(res, "/signin");
      ensureUserWorkspace(storeData, user);
      await save(storeData);
      return html(res, appPage({ demo: false, user }));
    }
    if (["/signin", "/login"].includes(route)) return html(res, signInPage());
    return html(res, publicPage());
  } catch (error) {
    json(res, error.status || 500, { error: error.message });
  }
}).listen(PORT, () => console.log(`Constrava is running at ${ORIGIN}`));
