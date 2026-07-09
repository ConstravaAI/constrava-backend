import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const file = path.join(root, "data", "store.json");
const PORT = Number(process.env.PORT || 3000);
const ORIGIN = process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`;
const TYPES = ["Lead", "Person", "Company", "Deal", "Task", "Note", "Intake"];
const ACTIONS = ["create", "update", "attach_note", "create_task", "create_deal", "ignore"];
const id = (p) => `${p}_${crypto.randomBytes(5).toString("hex")}`;
const clean = (v) => String(v || "").replace(/\s+/g, " ").trim();
const score = (v) => Math.max(0, Math.min(100, Number(v) || 0));

function baseRecord(type, title, fields = {}, priorityScore = 40, tags = []) {
  const at = new Date().toISOString();
  return {
    id: id(type.toLowerCase()),
    workspaceId: "demo",
    type,
    title,
    status: type === "Task" || type === "Deal" ? "open" : "active",
    priorityScore,
    priorityReasons: ["Seeded demo context"],
    tags,
    fields,
    relationships: [],
    sourceIds: ["source_manual"],
    createdAt: at,
    updatedAt: at,
    metadata: {}
  };
}

function seed() {
  return {
    sources: [
      { id: "source_manual", workspaceId: "demo", name: "Manual Notes", type: "manual_note", status: "connected", metadata: {} },
      { id: "source_website", workspaceId: "demo", name: "Website Contact Form", type: "website_form", status: "connected", metadata: { siteId: "site_demo" } }
    ],
    records: [
      baseRecord("Company", "Green Valley Roofing", { name: "Green Valley Roofing" }, 82, ["high intent"]),
      baseRecord("Person", "John Parker", { email: "john@greenvalley.example", companyName: "Green Valley Roofing" }, 76, ["needs follow-up"]),
      baseRecord("Deal", "Scheduling app quote", { value: 4000, stage: "qualified" }, 90, ["budget mentioned"]),
      baseRecord("Task", "Follow up with Green Valley Roofing", { taskType: "email" }, 88, ["needs follow-up"])
    ],
    events: [{ id: id("event"), type: "page_view", siteId: "site_demo", sessionId: "sample", sourceUrl: "/", referrer: "direct", metadata: {}, createdAt: new Date().toISOString() }],
    plans: [],
    reports: []
  };
}

async function store() {
  await fs.mkdir(path.dirname(file), { recursive: true });
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    const fresh = seed();
    await fs.writeFile(file, JSON.stringify(fresh, null, 2));
    return fresh;
  }
}

async function save(s) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, `${JSON.stringify(s, null, 2)}\n`);
}

async function read(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return { rawText: raw }; }
}

function send(res, status, data) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(data, null, 2));
}

function html(res, markup) {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(markup);
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
  let n = 38;
  const reasons = [];
  if (fields.value || /\$|budget|approved/.test(lower)) { n += fields.value >= 8000 ? 24 : 18; reasons.push(fields.value ? `Budget/value around $${fields.value.toLocaleString()}` : "Budget mentioned"); }
  if (/urgent|asap|deadline|tomorrow|this week|end of the month/.test(lower)) { n += 20; reasons.push("Urgency or deadline language"); }
  if (/quote|proposal|estimate|contract|ready|hire/.test(lower)) { n += 18; reasons.push("Buying intent detected"); }
  if (/follow up|follow-up|call|email|schedule|meeting/.test(lower)) { n += 12; reasons.push("Clear next action"); }
  return { score: score(n), reasons: reasons.length ? reasons : ["General activity"] };
}

function tag(text, fields) {
  const lower = text.toLowerCase();
  const out = new Set();
  if (fields.value || /\$|budget/.test(lower)) out.add("budget mentioned");
  if (/urgent|deadline|tomorrow|this week/.test(lower)) out.add("urgent");
  if (/quote|proposal|estimate/.test(lower)) out.add("quote requested");
  if (/follow|call|email|schedule/.test(lower)) out.add("needs follow-up");
  if (!out.size) out.add("needs review");
  return [...out];
}

function action(type, recordType, fields, p, tags, reasoning) {
  return { id: id("action"), actionType: type, recordType, targetRecordId: null, confidence: 0.82, fields, relationships: [], tags, priorityScore: p.score, priorityReasons: p.reasons, reasoning, duplicateCandidates: [] };
}

async function makePlan(s, input) {
  const rawText = clean(input.rawText || input.text || JSON.stringify(input.fields || input));
  const fields = extract(rawText);
  const p = priority(rawText, fields);
  const tags = tag(rawText, fields);
  const fallback = {
    planId: id("plan"),
    workspaceId: "demo",
    source: { kind: input.kind || "manual", sourceId: input.sourceId || "source_manual", rawText },
    summary: "Prepared structured business records from the incoming information.",
    riskLevel: "review",
    aiProvider: "local-fallback",
    createdAt: new Date().toISOString(),
    actions: []
  };
  fallback.actions.push(action("create", "Intake", { title: `Intake from ${input.kind || "manual input"}`, rawText }, p, tags, "Preserve the raw submission."));
  if (fields.companyName) fallback.actions.push(action("create", "Company", { name: fields.companyName }, p, tags, "Company-like name detected."));
  if (fields.name || fields.email) fallback.actions.push(action("create", "Person", { name: fields.name || fields.email.split("@")[0] || "New Contact", email: fields.email, companyName: fields.companyName }, p, tags, "Contact details detected."));
  if (/quote|proposal|estimate|budget|project|contract|automation|website|app|build/i.test(rawText)) fallback.actions.push(action("create_deal", "Deal", { title: fields.request || "New opportunity", value: fields.value, stage: p.score > 75 ? "qualified" : "new" }, p, tags, "Opportunity language found."));
  if (/follow|call|email|schedule|meeting|tomorrow|monday|tuesday|wednesday|thursday|friday/i.test(rawText)) fallback.actions.push(action("create_task", "Task", { title: fields.companyName ? `Follow up with ${fields.companyName}` : "Follow up on new intake", taskType: /call|meeting|schedule/i.test(rawText) ? "call" : "email" }, p, ["needs follow-up", ...tags], "Next-action language found."));
  fallback.actions.push(action("attach_note", "Note", { title: "Source note", body: rawText }, p, tags, "Keep the original context attached."));

  if (!process.env.OPENAI_API_KEY) return fallback;
  try {
    const r = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { authorization: `Bearer ${process.env.OPENAI_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-5.5-mini",
        instructions: "Return JSON only for a Constrava record action plan with summary, riskLevel, and actions. Use the allowed record and action types.",
        input: JSON.stringify({ rawText, existingRecords: s.records.slice(-30), allowedTypes: TYPES, allowedActions: ACTIONS })
      })
    });
    if (!r.ok) return fallback;
    const out = await r.json();
    const text = out.output_text || out.output?.flatMap((x) => x.content || []).find((x) => x.text)?.text;
    const ai = JSON.parse(text);
    if (!Array.isArray(ai.actions)) return fallback;
    return { ...fallback, ...ai, planId: id("plan"), workspaceId: "demo", source: fallback.source, aiProvider: "openai", createdAt: new Date().toISOString() };
  } catch {
    return fallback;
  }
}

function commit(s, planId, ids) {
  const plan = s.plans.find((p) => p.planId === planId);
  if (!plan) throw Object.assign(new Error("Plan not found"), { status: 404 });
  const selected = new Set(ids || plan.actions.map((a) => a.id));
  const at = new Date().toISOString();
  const committed = [];
  for (const a of plan.actions.filter((x) => selected.has(x.id) && x.actionType !== "ignore")) {
    const title = clean(a.fields.title || a.fields.name || a.fields.companyName || a.fields.request || `${a.recordType} record`);
    const record = { id: id(a.recordType.toLowerCase()), workspaceId: "demo", type: a.recordType, title, status: a.recordType === "Task" || a.recordType === "Deal" ? "open" : "active", priorityScore: score(a.priorityScore), priorityReasons: a.priorityReasons || [], tags: a.tags || [], fields: a.fields || {}, relationships: a.relationships || [], sourceIds: [plan.source?.sourceId].filter(Boolean), createdAt: at, updatedAt: at, metadata: { planId, aiProvider: plan.aiProvider, reasoning: a.reasoning } };
    s.records.push(record);
    committed.push(record);
  }
  plan.status = "committed";
  plan.committedAt = at;
  plan.committedRecordIds = committed.map((r) => r.id);
  return { plan, committed };
}

function filtered(s, q = {}) {
  let rows = s.records;
  if (q.type) rows = rows.filter((r) => r.type.toLowerCase() === q.type.toLowerCase());
  if (q.q) rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q.q.toLowerCase()));
  rows = [...rows];
  rows.sort(q.sort === "newest" ? (a, b) => b.createdAt.localeCompare(a.createdAt) : (a, b) => Number(b.priorityScore || 0) - Number(a.priorityScore || 0));
  return rows;
}

function dash(s) {
  const rows = filtered(s);
  const deals = rows.filter((r) => r.type === "Deal");
  const tasks = rows.filter((r) => r.type === "Task");
  const leads = rows.filter((r) => ["Lead", "Person", "Intake"].includes(r.type));
  const opportunity = deals.reduce((sum, d) => sum + Number(d.fields?.value || 0), 0);
  const high = rows.filter((r) => r.priorityScore >= 75).slice(0, 6);
  return {
    metrics: { newLeads: leads.length, activeDeals: deals.length, overdueTasks: tasks.filter((t) => t.fields?.dueDate && t.fields.dueDate < new Date().toISOString().slice(0, 10)).length, conversionRate: leads.length ? Math.round((deals.length / leads.length) * 100) : 0, trafficEvents: s.events.length, revenueOpportunity: opportunity, aiCreatedRecords: rows.filter((r) => r.metadata?.aiProvider).length },
    sourcePerformance: s.sources.map((x) => ({ ...x, records: rows.filter((r) => r.sourceIds?.includes(x.id)).length, events: s.events.filter((e) => e.siteId === x.metadata?.siteId).length })),
    highPriority: high,
    recommendedActions: high.slice(0, 4).map((r) => ({ title: `Review ${r.title}`, reason: r.priorityReasons?.[0] || "High priority", recordId: r.id })),
    recentRecords: rows.slice(0, 8)
  };
}

function snippet() {
  return '<script>(function(){var endpoint=' + JSON.stringify(ORIGIN + '/api/analytics/events') + ';var sid=localStorage.getItem("constrava_session_id")||Math.random().toString(36).slice(2);localStorage.setItem("constrava_session_id",sid);function send(type,metadata){fetch(endpoint,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({workspaceId:"demo",siteId:"site_demo",type:type,sessionId:sid,sourceUrl:location.href,referrer:document.referrer,metadata:metadata||{}})}).catch(function(){})}send("page_view",{title:document.title});document.addEventListener("submit",function(e){var data={};Array.prototype.forEach.call(e.target.elements||[],function(i){if(i.name)data[i.name]=i.value});send("form_submission",{fields:data})},true)})();</script>';
}

function publicPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Constrava</title>
  <style>
    :root{--blue:#061a33;--blue2:#0d2b52;--blue3:#174675;--soft:#eaf2ff;--line:#d9e3f2;--ink:#071629;--muted:#607089;--bg:#f7fbff}
    *{box-sizing:border-box}html{scroll-behavior:smooth}
    body{margin:0;background:radial-gradient(circle at 15% 0%,#dbeaff 0,#f7fbff 34%,#ffffff 100%);color:var(--ink);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.55}
    .wrap{width:min(1100px,calc(100% - 36px));margin:auto}
    header{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.88);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}
    .nav{height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}
    .brand{display:flex;align-items:center;gap:12px;font-size:24px;font-weight:950;letter-spacing:-.04em;text-decoration:none;color:var(--blue)}
    .mark{width:42px;height:42px;border-radius:15px;background:linear-gradient(135deg,var(--blue),var(--blue3));color:white;display:grid;place-items:center;box-shadow:0 14px 32px rgba(6,26,51,.22)}
    .links{display:flex;gap:18px;align-items:center}.links a{color:#263d5c;text-decoration:none;font-weight:850;font-size:14px}
    .btn{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;padding:13px 18px;border:1px solid var(--line);text-decoration:none;font-weight:950;background:white;color:var(--blue);box-shadow:0 12px 30px rgba(6,26,51,.08)}
    .btn.primary{background:var(--blue);color:white;border-color:var(--blue)}
    .hero{padding:82px 0 56px}.heroGrid{display:grid;grid-template-columns:1.05fr .95fr;gap:44px;align-items:center}
    .eyebrow{display:inline-flex;align-items:center;border:1px solid #bed0ea;background:var(--soft);color:var(--blue);border-radius:999px;padding:7px 12px;font-size:13px;font-weight:950}
    h1{font-size:clamp(44px,7vw,76px);line-height:.96;letter-spacing:-.075em;margin:18px 0 18px;color:var(--blue)}
    .lead{font-size:20px;color:var(--muted);max-width:650px}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}.note{font-size:14px;color:#71829b;margin-top:18px}
    .preview{background:white;border:1px solid rgba(6,26,51,.16);border-radius:34px;padding:18px;box-shadow:0 34px 90px rgba(6,26,51,.14)}
    .chrome{background:var(--blue);border-radius:24px;padding:14px}.dots{display:flex;gap:7px;margin-bottom:12px}.dots span{width:10px;height:10px;border-radius:999px;background:#8fa7c7}
    .screen{background:#f9fbff;border-radius:18px;padding:18px}.screenTop{display:flex;justify-content:space-between;gap:12px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:14px}
    .badge{display:inline-flex;background:var(--soft);color:var(--blue);border:1px solid #bed0ea;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:950}
    .metricGrid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.metric{background:white;border:1px solid var(--line);border-radius:16px;padding:12px}.metric b{display:block;font-size:24px;color:var(--blue)}
    .record{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;background:white;border:1px solid var(--line);border-radius:16px;padding:12px;margin-top:10px}.score{background:var(--soft);color:var(--blue);border-radius:999px;padding:5px 8px;font-weight:950}
    section{padding:62px 0}h2{font-size:clamp(32px,5vw,52px);line-height:1;letter-spacing:-.055em;margin:0 0 14px;color:var(--blue)}.sectionLead{font-size:18px;color:var(--muted);max-width:760px}
    .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:24px}.card{background:rgba(255,255,255,.94);border:1px solid var(--line);border-radius:24px;padding:22px;box-shadow:0 18px 48px rgba(6,26,51,.08)}.card h3{margin:0 0 8px;font-size:22px;color:var(--blue)}.card p{margin:0;color:var(--muted)}
    .cta{background:linear-gradient(135deg,var(--blue),var(--blue2));color:white;border-radius:34px;padding:34px;display:flex;align-items:center;justify-content:space-between;gap:22px}.cta h2{color:white}.cta p{color:#d8e6f8;margin:0}
    footer{border-top:1px solid var(--line);padding:26px 0;color:#71829b;font-size:14px}
    @media(max-width:850px){.heroGrid,.cards{grid-template-columns:1fr}.links a:not(.btn){display:none}.cta{display:block}.cta .actions{margin-top:18px}.metricGrid{grid-template-columns:1fr}.record{grid-template-columns:1fr}.nav{height:auto;padding:14px 0;align-items:flex-start}}
  </style>
</head>
<body>
  <header><div class="wrap nav"><a class="brand" href="/"><span class="mark">C</span>Constrava</a><nav class="links"><a href="#features">Features</a><a href="#how">How it works</a><a class="btn" href="/demo">View demo</a><a class="btn primary" href="/dashboard">Sign in</a></nav></div></header>
  <main>
    <section class="hero"><div class="wrap heroGrid"><div><span class="eyebrow">Simple AI workspace for business records</span><h1>Turn messy business activity into organized records.</h1><p class="lead">Constrava helps capture leads, notes, forms, and follow-ups, then organizes them into records, tasks, deals, and priorities so a business knows what to act on next.</p><div class="actions"><a class="btn primary" href="/dashboard">Sign in to dashboard</a><a class="btn" href="/demo">View demo</a></div><p class="note">Demo: constravaai.com/demo · Dashboard: constravaai.com/dashboard</p></div><div class="preview" aria-label="Constrava dashboard preview"><div class="chrome"><div class="dots"><span></span><span></span><span></span></div><div class="screen"><div class="screenTop"><div><span class="badge">Dashboard</span><h3 style="margin:8px 0 0;color:#061a33">Priority Command Center</h3></div><span class="score">AI</span></div><div class="metricGrid"><div class="metric"><small>New leads</small><b>18</b></div><div class="metric"><small>Open deals</small><b>$42k</b></div><div class="metric"><small>Tasks</small><b>7</b></div></div><div class="record"><span class="badge">Deal</span><div><b>Scheduling app quote</b><br><small>Budget mentioned · follow-up needed</small></div><span class="score">90</span></div><div class="record"><span class="badge">Task</span><div><b>Follow up with new intake</b><br><small>Clear next action detected</small></div><span class="score">88</span></div></div></div></div></div></section>
    <section id="features"><div class="wrap"><h2>What the tool does</h2><p class="sectionLead">Constrava is meant to be a lightweight operating dashboard for customer and business activity, not a complicated enterprise CRM.</p><div class="cards"><article class="card"><h3>Capture records</h3><p>Store leads, companies, people, deals, tasks, notes, and website form activity in one place.</p></article><article class="card"><h3>Use AI to sort</h3><p>AI reviews messy text and suggests useful records, tags, priorities, and follow-ups.</p></article><article class="card"><h3>Act faster</h3><p>The dashboard highlights high-priority records, recommended actions, and business reports.</p></article></div></div></section>
    <section id="how"><div class="wrap cta"><div><h2 style="margin-bottom:10px">Try the demo or enter the dashboard.</h2><p>The public demo shows the current Constrava workspace. The dashboard link is the main app entry point for a signed-in account.</p></div><div class="actions"><a class="btn primary" href="/dashboard">Dashboard</a><a class="btn" href="/demo">Demo</a></div></div></section>
  </main>
  <footer><div class="wrap">© 2026 Constrava · <a href="/demo">Demo</a> · <a href="/dashboard">Dashboard</a></div></footer>
</body>
</html>`;
}

function signInPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in | Constrava</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7fbff;color:#071629;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:24px}.card{width:min(420px,100%);background:white;border:1px solid #d9e3f2;border-radius:24px;padding:28px;box-shadow:0 20px 60px rgba(6,26,51,.10)}h1{margin:0 0 10px;font-size:38px;letter-spacing:-.06em;color:#061a33}p{color:#607089;line-height:1.55}input{width:100%;border:1px solid #d9e3f2;border-radius:14px;padding:13px;margin:8px 0 12px;font:inherit}a{width:100%;display:flex;justify-content:center;border:0;border-radius:999px;padding:13px 16px;background:#061a33;color:white;text-decoration:none;font-weight:900;font:inherit}.back{margin-top:12px;background:white;color:#061a33;border:1px solid #d9e3f2}</style></head><body><section class="card"><h1>Sign in</h1><p>Use this entry point for the Constrava dashboard. Full account authentication can be connected here later.</p><input placeholder="Email"><input type="password" placeholder="Password"><a href="/dashboard">Continue to dashboard</a><a class="back" href="/">Back to homepage</a></section></body></html>`;
}

function appPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Constrava Dashboard</title>
  <style>
    :root{--blue:#061a33;--blue2:#0d2b52;--blue3:#174675;--soft:#eaf2ff;--line:#d9e3f2;--ink:#071629;--muted:#607089;--bg:#f7fbff}
    body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,system-ui,sans-serif;display:grid;grid-template-columns:220px 1fr;min-height:100vh}
    .side{background:var(--blue);color:white;padding:18px;display:flex;flex-direction:column}.brand{font-size:21px;font-weight:900}.brand span{display:block;color:#b7c8dd;font-size:12px}.home{color:#d8e6f8;text-decoration:none;font-size:13px;margin-top:6px;font-weight:800}
    .nav{display:grid;gap:5px;margin-top:18px}.nav button,.foot button{background:transparent;color:#e6effb;border:0;text-align:left;padding:10px;border-radius:8px;cursor:pointer}.nav button.active,.nav button:hover,.foot button:hover{background:#12345f;color:white}.foot{margin-top:auto;border-top:1px solid #25486f;padding-top:12px}
    .top{position:sticky;top:0;background:rgba(247,251,255,.92);backdrop-filter:blur(14px);border-bottom:1px solid var(--line);padding:22px 28px;display:flex;justify-content:space-between;gap:12px}.content{padding:24px 28px}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,1fr)}.two{grid-template-columns:1.1fr .9fr}.three{grid-template-columns:repeat(3,1fr)}
    .card{background:white;border:1px solid var(--line);border-radius:12px;box-shadow:0 16px 40px rgba(6,26,51,.08)}.in{padding:18px}.row{display:flex;justify-content:space-between;gap:12px}.muted{color:var(--muted)}.metric{font-size:30px;font-weight:900;color:var(--blue)}.item{padding:13px 0;border-top:1px solid var(--line)}.item:first-child{border-top:0}
    .pill{display:inline-block;padding:2px 8px;border-radius:99px;background:var(--soft);border:1px solid #bed0ea;color:var(--blue);font-size:12px;font-weight:800}.hot{background:#dceaff;color:var(--blue)}.primary{background:var(--blue);color:white;border:0;padding:10px 14px;font-weight:900;border-radius:8px;cursor:pointer}.secondary,input,select,textarea{border:1px solid var(--line);background:white;padding:10px;border-radius:8px;font:inherit}textarea{min-height:140px;width:100%}.stack{display:grid;gap:12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}pre{white-space:pre-wrap;background:#061a33;color:#eef6ff;padding:14px;border-radius:10px;overflow:auto}dialog{width:min(880px,calc(100vw - 32px));border:1px solid var(--line);border-radius:12px;padding:0}.dh,.da{padding:18px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between}.da{border-top:1px solid var(--line);border-bottom:0;justify-content:flex-end}.db{padding:18px;max-height:65vh;overflow:auto}.plan{display:grid;grid-template-columns:auto 1fr;gap:12px;border:1px solid var(--line);border-radius:10px;padding:12px;margin-bottom:10px}@media(max-width:850px){body{display:block}.metrics,.two,.three{grid-template-columns:1fr}.top{display:block}.side{min-height:auto}.nav{display:flex;overflow:auto}}
  </style>
</head>
<body>
  <aside class="side"><div class="brand">Constrava<span>Dashboard</span></div><a class="home" href="/">← Homepage</a><nav class="nav" id="nav"></nav><div class="foot"><button id="settingsBtn">Settings</button><button id="signoutBtn">Sign out</button></div></aside>
  <main><header class="top"><div><p class="muted">Workspace</p><h1 id="title">Dashboard</h1></div><div><input id="search" placeholder="Ask for records, tasks, leads..."> <button class="primary" id="aiBtn">AI Add</button></div></header><section class="content" id="app"></section></main>
  <dialog id="dlg"><div class="dh"><h2 id="pt"></h2><button class="secondary" id="closeDlg">x</button></div><div class="db" id="pb"></div><div class="da"><button class="primary" id="commitBtn">Commit selected</button></div></dialog>
<script>
let S={view:"dashboard",records:[],plans:[],plan:null,summary:null};
const views=["dashboard","sources","crm","records","deals","tasks","ai","reports","analytics","automations"];
const esc=function(v){return String(v==null?"":v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")};
const api=function(p,o){o=o||{};return fetch(p,{...o,headers:{"content-type":"application/json",...(o.headers||{})}}).then(async function(r){let d=await r.json();if(!r.ok)throw Error(d.error||"Request failed");return d})};
function money(v){return Number(v||0).toLocaleString(undefined,{style:"currency",currency:"USD",maximumFractionDigits:0})}
function metric(n,v,t){return '<div class="card"><div class="in"><p class="muted">'+n+'</p><div class="metric">'+v+'</div><p class="muted">'+t+'</p></div></div>'}
function row(r){return '<div class="item"><div class="row"><div><span class="pill">'+esc(r.type)+'</span> <b>'+esc(r.title)+'</b><p class="muted">'+esc((r.priorityReasons||[])[0]||"")+'</p></div><span class="pill hot">'+Math.round(r.priorityScore||0)+'</span></div></div>'}
async function load(){let out=await Promise.all([api("/api/dashboard/summary"),api("/api/records"),api("/api/sources"),api("/api/plans"),api("/api/reports"),api("/api/analytics/events")]);S.summary=out[0];S.records=out[1].records;S.sources=out[2].sources;S.snippet=out[2].snippet;S.plans=out[3].plans;S.reports=out[4].reports;S.events=out[5].events}
function renderNav(){document.getElementById("nav").innerHTML=views.map(function(v){return '<button class="'+(S.view===v?'active':'')+'" data-view="'+v+'">'+v[0].toUpperCase()+v.slice(1)+'</button>'}).join("");document.querySelectorAll("#nav button").forEach(function(b){b.onclick=function(){view(b.dataset.view)}})}
function view(v){S.view=v;render()}async function refresh(v){await load();S.view=v||S.view;render()}
function bind(){let f=document.getElementById("aiForm");if(f)f.onsubmit=async function(e){e.preventDefault();let p=await api("/api/records/plan",{method:"POST",body:JSON.stringify(Object.fromEntries(new FormData(f)))});await refresh("ai");openPlan(p.plan.planId)};document.querySelectorAll("[data-plan]").forEach(function(b){b.onclick=function(){openPlan(b.dataset.plan)}})}
function list(t){let r=t?S.records.filter(function(x){return x.type===t}):S.records;return '<div class="toolbar"><input id="q" placeholder="Filter"><button class="primary" id="filterBtn">Apply</button></div><section class="card"><div class="in"><h2>Records</h2>'+r.map(row).join("")+'</div></section>'}
async function filterRecords(){let d=await api("/api/records?q="+encodeURIComponent(document.getElementById("q").value));S.records=d.records;render()}
function render(){renderNav();document.getElementById("title").textContent=S.view[0].toUpperCase()+S.view.slice(1);let h="",m=S.summary.metrics;if(S.view==="dashboard")h='<div class="grid metrics">'+metric("New leads",m.newLeads,"Intakes and contacts")+metric("Active deals",m.activeDeals,money(m.revenueOpportunity))+metric("Overdue tasks",m.overdueTasks,"Tasks past due")+metric("AI-created",m.aiCreatedRecords,"Committed records")+'</div><div class="grid two" style="margin-top:16px"><section class="card"><div class="in"><h2>Recommended Actions</h2>'+S.summary.recommendedActions.map(function(a){return '<div class="item"><b>'+esc(a.title)+'</b><p class="muted">'+esc(a.reason)+'</p></div>'}).join("")+'</div></section><section class="card"><div class="in"><h2>High Priority Records</h2>'+S.summary.highPriority.map(row).join("")+'</div></section></div>';if(S.view==="sources")h='<div class="grid two"><section class="card"><div class="in"><h2>Sources</h2>'+S.sources.map(function(s){return '<div class="item"><b>'+esc(s.name)+'</b><p class="muted">'+esc(s.type)+' - '+esc(s.status)+'</p></div>'}).join("")+'</div></section><section class="card"><div class="in"><h2>Analytics Snippet</h2><pre>'+esc(S.snippet)+'</pre></div></section></div>';if(S.view==="crm")h='<div class="grid three">'+["Person","Company","Intake"].map(function(t){return '<section class="card"><div class="in"><h2>'+t+'</h2>'+S.records.filter(function(r){return r.type===t}).map(row).join("")+'</div></section>'}).join("")+'</div>';if(S.view==="records"||S.view==="tasks")h=list(S.view==="tasks"?"Task":"");if(S.view==="deals")h='<section class="card"><div class="in"><h2>Deals</h2>'+S.records.filter(function(r){return r.type==="Deal"}).map(row).join("")+'</div></section>';if(S.view==="ai")h='<div class="grid two"><section class="card"><div class="in stack"><h2>AI Add From Text</h2><form id="aiForm"><textarea name="rawText" required placeholder="Paste a lead, email, form submission, or messy note"></textarea><button class="primary">Create AI plan</button></form></div></section><section class="card"><div class="in"><h2>Recent Plans</h2>'+S.plans.map(function(p){return '<div class="item"><b>'+esc(p.summary)+'</b><p class="muted">'+esc(p.aiProvider)+' - '+p.actions.length+' actions</p><button class="secondary" data-plan="'+esc(p.planId)+'">Review</button></div>'}).join("")+'</div></section></div>';if(S.view==="reports")h='<button class="primary" id="reportBtn">Generate report</button>'+S.reports.map(function(r){return '<section class="card"><div class="in"><h2>'+esc(r.title)+'</h2>'+(r.content.factualSummary||[]).map(function(x){return '<p class="muted">- '+esc(x)+'</p>'}).join("")+'</div></section>'}).join("");if(S.view==="analytics")h='<section class="card"><div class="in"><h2>Events</h2>'+S.events.map(function(e){return '<div class="item"><b>'+esc(e.type)+'</b><p class="muted">'+esc(e.sourceUrl||e.siteId)+'</p></div>'}).join("")+'</div></section>';if(S.view==="automations")h='<div class="grid three">'+["Duplicate Scan","Stale Lead Alert","Deal Next Step"].map(function(x){return '<section class="card"><div class="in"><h2>'+x+'</h2><p class="muted">Ready for scheduled jobs.</p></div></section>'}).join("")+'</div>';if(S.view==="settings")h='<section class="card"><div class="in stack"><h2>Settings</h2><input value="Constrava Demo Workspace"><button class="primary">Save settings</button><button class="secondary" id="settingsSignout">Sign out</button></div></section>';document.getElementById("app").innerHTML=h;if(document.getElementById("filterBtn"))document.getElementById("filterBtn").onclick=filterRecords;if(document.getElementById("reportBtn"))document.getElementById("reportBtn").onclick=report;if(document.getElementById("settingsSignout"))document.getElementById("settingsSignout").onclick=signout;bind()}
function openPlan(id){S.plan=S.plans.find(function(p){return p.planId===id});document.getElementById("pt").textContent=S.plan.summary;document.getElementById("pb").innerHTML=S.plan.actions.map(function(a){return '<label class="plan"><input type="checkbox" checked value="'+a.id+'"><div><b>'+esc(a.actionType)+' '+esc(a.recordType)+'</b><p class="muted">'+esc(a.reasoning)+'</p><pre>'+esc(JSON.stringify(a.fields,null,2))+'</pre></div></label>'}).join("");dlg.showModal()}
async function commitPlan(){let ids=[...document.querySelectorAll("#pb input:checked")].map(function(i){return i.value});await api("/api/records/commit",{method:"POST",body:JSON.stringify({planId:S.plan.planId,actionIds:ids})});dlg.close();await refresh("records")}
async function report(){await api("/api/reports/generate",{method:"POST",body:"{}"});await refresh("reports")}
document.getElementById("aiBtn").onclick=function(){view("ai")};document.getElementById("settingsBtn").onclick=function(){view("settings")};document.getElementById("signoutBtn").onclick=signout;document.getElementById("closeDlg").onclick=function(){dlg.close()};document.getElementById("commitBtn").onclick=commitPlan;document.getElementById("search").onkeydown=async function(e){if(e.key==="Enter"){let d=await api("/api/search/natural",{method:"POST",body:JSON.stringify({query:search.value})});S.records=d.records;view("records")}};function signout(){location.href="/signin"}refresh("dashboard");
</script>
</body>
</html>`;
}

async function api(req, res, url) {
  const s = await store();
  if (req.method === "GET" && url.pathname === "/api/health") return send(res, 200, { ok: true, aiConfigured: Boolean(process.env.OPENAI_API_KEY), homepage: "/", demo: "/demo", dashboard: "/dashboard" });
  if (req.method === "GET" && url.pathname === "/api/dashboard/summary") return send(res, 200, dash(s));
  if (req.method === "GET" && url.pathname === "/api/records") return send(res, 200, { records: filtered(s, Object.fromEntries(url.searchParams.entries())) });
  if (req.method === "GET" && url.pathname === "/api/sources") return send(res, 200, { sources: s.sources, snippet: snippet() });
  if (req.method === "GET" && url.pathname === "/api/plans") return send(res, 200, { plans: s.plans.sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "GET" && url.pathname === "/api/reports") return send(res, 200, { reports: s.reports.sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "GET" && url.pathname === "/api/analytics/events") return send(res, 200, { events: s.events.sort((a, b) => b.createdAt.localeCompare(a.createdAt)) });
  if (req.method === "POST" && url.pathname === "/api/records/plan") { const p = await makePlan(s, await read(req)); s.plans.push(p); await save(s); return send(res, 200, { plan: p }); }
  if (req.method === "POST" && url.pathname === "/api/records/commit") { const b = await read(req); const out = commit(s, b.planId, b.actionIds); await save(s); return send(res, 200, out); }
  if (req.method === "POST" && url.pathname === "/api/analytics/events") { const b = await read(req); const e = { id: id("event"), type: clean(b.type || "custom"), siteId: clean(b.siteId || "site_demo"), sessionId: clean(b.sessionId || id("session")), sourceUrl: clean(b.sourceUrl || ""), referrer: clean(b.referrer || ""), metadata: b.metadata || {}, createdAt: new Date().toISOString() }; s.events.push(e); await save(s); return send(res, 202, { accepted: true, eventId: e.id }); }
  if (req.method === "POST" && url.pathname === "/api/sources/form") { const b = await read(req); const p = await makePlan(s, { kind: "website_form", sourceId: "source_website", rawText: b.rawText || JSON.stringify(b.fields || b) }); s.plans.push(p); await save(s); return send(res, 202, { accepted: true, plan: p }); }
  if (req.method === "POST" && url.pathname === "/api/uploads/import") { const b = await read(req); const p = await makePlan(s, { kind: "upload", rawText: String(b.csv || b.text || "").split(/\r?\n/).slice(0, 100).join("\n") }); s.plans.push(p); await save(s); return send(res, 200, { plan: p }); }
  if (req.method === "POST" && url.pathname === "/api/search/natural") { const b = await read(req); const q = clean(b.query).toLowerCase(); return send(res, 200, { plan: { q, explanation: "Converted plain English into safe filters." }, records: filtered(s, { q, type: /deal|quote/.test(q) ? "Deal" : /task|follow/.test(q) ? "Task" : "" }) }); }
  if (req.method === "POST" && url.pathname === "/api/reports/generate") { const d = dash(s); const content = { title: "Business Activity Report", factualSummary: [`${d.metrics.newLeads} lead/contact records are tracked.`, `${d.metrics.activeDeals} active deals represent $${d.metrics.revenueOpportunity.toLocaleString()} in opportunity.`, `${d.metrics.trafficEvents} analytics events have been captured.`], recommendations: d.recommendedActions.map((x) => `${x.title}: ${x.reason}`) }; const r = { id: id("report"), title: content.title, content, createdAt: new Date().toISOString() }; s.reports.push(r); await save(s); return send(res, 200, { report: r }); }
  return send(res, 404, { error: "API route not found" });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, ORIGIN);
    if (url.pathname.startsWith("/api/")) return await api(req, res, url);
    if (["/dashboard", "/app"].includes(url.pathname)) return html(res, appPage());
    if (url.pathname === "/demo") return html(res, appPage());
    if (["/signin", "/login"].includes(url.pathname)) return html(res, signInPage());
    return html(res, publicPage());
  } catch (e) {
    send(res, e.status || 500, { error: e.message });
  }
}).listen(PORT, () => console.log(`Constrava is running at ${ORIGIN}`));