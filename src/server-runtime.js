import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(here, "server.js");
const runtimePath = path.join(here, ".server.generated.js");

const fixedSignInPage = String.raw`function signInPage() {
  const devConfigured = Boolean(process.env[DEV_LOGIN_KEY_ENV]);
  const hint = devConfigured ? '<p class="hint">Developer login is enabled for ' + esc(DEV_EMAIL) + '. Use the configured ' + esc(DEV_LOGIN_KEY_ENV) + ' value as the password.</p>' : '';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in | Constrava</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7fbff;color:#071629;font-family:Inter,system-ui,sans-serif}.card{width:min(640px,calc(100% - 24px));background:white;border:1px solid #d9e3f2;border-radius:28px;padding:32px;box-shadow:0 24px 70px rgba(6,26,51,.10)}h1{color:#061a33;font-size:42px;letter-spacing:-.06em}label{font-weight:900;color:#263d5c}input{width:100%;border:1px solid #d9e3f2;border-radius:14px;padding:13px;margin:6px 0 12px;font:inherit}.submit,.back{border:1px solid #d9e3f2;border-radius:999px;padding:12px;font:inherit;font-weight:900;cursor:pointer}.submit{background:#061a33;color:white;min-width:128px}.back{display:flex;justify-content:center;text-decoration:none;color:#061a33;margin-top:36px}.status{min-height:22px;color:#9d2b2b}.hint{font-size:13px;background:#eaf2ff;border:1px solid #d9e3f2;padding:10px;border-radius:14px}</style></head><body><main class="card"><h1 id="title">Sign in</h1><p id="copy">Enter your saved account details to open your dashboard.</p>' + hint + '<form id="authForm"><label>Email</label><input name="email" type="email" autocomplete="email" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="submit" id="submitBtn">Sign in</button></form><p class="status" id="status"></p><a class="back" href="/">Back to homepage</a></main><script>localStorage.removeItem("constrava_session_token");authForm.onsubmit=async function(e){e.preventDefault();status.textContent="";submitBtn.disabled=true;try{const payload=Object.fromEntries(new FormData(authForm));const r=await fetch("/api/auth/login",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});const data=await r.json();if(!r.ok)throw new Error(data.error||"Authentication failed");location.href="/dashboard/"}catch(err){status.textContent=err.message}finally{submitBtn.disabled=false}};</script></body></html>';
}`;

const manualRecordServerCode = String.raw`function manualRecordFromBody(body, workspaceId) {
  const allowedTypes = new Set(["Person", "Company", "Deal", "Task", "Intake", "Note"]);
  const type = clean(body.type || body.recordType);
  if (!allowedTypes.has(type)) throw Object.assign(new Error("Choose a valid record type."), { status: 400 });
  const title = clean(body.title || body.name || body.companyName);
  if (!title) throw Object.assign(new Error("Title or name is required."), { status: 400 });
  const level = clean(body.priorityLevel || body.priority || "normal").toLowerCase();
  const priorityMap = { low: 25, normal: 50, high: 75, highest: 95 };
  const now = new Date().toISOString();
  const associatedDate = clean(body.associatedDate || body.dueDate || "");
  const fields = {
    recordType: type,
    description: clean(body.description || body.body || body.rawText || ""),
    associatedDate,
    email: clean(body.email || ""),
    phone: clean(body.phone || ""),
    companyName: clean(body.companyName || ""),
    role: clean(body.role || ""),
    industry: clean(body.industry || ""),
    website: clean(body.website || ""),
    contactEmail: clean(body.contactEmail || ""),
    value: Number(String(body.value || "").replace(/[$,\s]/g, "")) || 0,
    stage: clean(body.stage || ""),
    taskType: clean(body.taskType || ""),
    dueDate: type === "Task" ? associatedDate : clean(body.dueDate || ""),
    source: clean(body.source || ""),
    category: clean(body.category || "")
  };
  for (const key of Object.keys(fields)) if (fields[key] === "" || fields[key] === 0) delete fields[key];
  const tags = clean(body.tags || "").split(",").map((tag) => clean(tag)).filter(Boolean);
  const record = {
    id: id(type.toLowerCase()),
    workspaceId,
    type,
    title,
    status: clean(body.status || (type === "Task" || type === "Deal" ? "open" : "active")),
    priorityScore: priorityMap[level] || priorityMap.normal,
    priorityReasons: [level === "highest" ? "Manually marked highest priority" : "Manual " + (level || "normal") + " priority"],
    tags,
    fields,
    relationships: [],
    sourceIds: ["source_manual"],
    createdAt: now,
    updatedAt: now,
    metadata: { createdBy: "manual", priorityLevel: level, editHistory: [{ at: now, action: "created", source: "manual editor" }] }
  };
  return record;
}`;

const updateRecordServerCode = String.raw`function updateRecordFromBody(storeData, body, workspaceId) {
  const allowedTypes = new Set(["Person", "Company", "Deal", "Task", "Intake", "Note"]);
  const recordId = clean(body.id || body.recordId);
  if (!recordId) throw Object.assign(new Error("Record ID is required."), { status: 400 });
  const record = storeData.records.find((entry) => entry.id === recordId && entry.workspaceId === workspaceId);
  if (!record) throw Object.assign(new Error("Record not found."), { status: 404 });
  const type = clean(body.type || record.type);
  if (!allowedTypes.has(type)) throw Object.assign(new Error("Choose a valid record type."), { status: 400 });
  const title = clean(body.title || record.title);
  if (!title) throw Object.assign(new Error("Title or name is required."), { status: 400 });
  const priorityMap = { low: 25, normal: 50, high: 75, highest: 95 };
  const level = clean(body.priorityLevel || body.priority || record.metadata?.priorityLevel || "normal").toLowerCase();
  const now = new Date().toISOString();
  const associatedDate = clean(body.associatedDate || body.dueDate || "");
  const fields = { ...(record.fields || {}) };
  const stringFields = ["description", "email", "phone", "companyName", "role", "industry", "website", "contactEmail", "stage", "taskType", "source", "category", "status"];
  for (const key of stringFields) if (Object.prototype.hasOwnProperty.call(body, key)) fields[key] = clean(body[key]);
  if (associatedDate || Object.prototype.hasOwnProperty.call(body, "associatedDate")) fields.associatedDate = associatedDate;
  if (type === "Task") fields.dueDate = associatedDate || clean(body.dueDate || fields.dueDate || "");
  if (Object.prototype.hasOwnProperty.call(body, "value")) fields.value = Number(String(body.value || "").replace(/[$,\s]/g, "")) || 0;
  fields.recordType = type;
  for (const key of Object.keys(fields)) if (fields[key] === "" || fields[key] === 0) delete fields[key];
  record.type = type;
  record.title = title;
  record.status = clean(body.status || record.status || (type === "Task" || type === "Deal" ? "open" : "active"));
  if (priorityMap[level]) {
    record.priorityScore = priorityMap[level];
    record.priorityReasons = [level === "highest" ? "Manually marked highest priority" : "Manual " + level + " priority"];
  }
  if (Object.prototype.hasOwnProperty.call(body, "tags")) record.tags = clean(body.tags || "").split(",").map((tag) => clean(tag)).filter(Boolean);
  record.fields = fields;
  record.updatedAt = now;
  record.metadata ||= {};
  record.metadata.priorityLevel = priorityMap[level] ? level : record.metadata.priorityLevel;
  record.metadata.editHistory ||= [];
  record.metadata.editHistory.push({ at: now, action: "edited", source: "record editor" });
  return record;
}`;

const openAiPriorityServerCode = String.raw`function extractOpenAIText(data) {
  if (data && typeof data.output_text === "string") return data.output_text;
  const parts = [];
  for (const item of data && data.output ? data.output : []) {
    for (const content of item.content || []) {
      if (typeof content.text === "string") parts.push(content.text);
      if (typeof content.output_text === "string") parts.push(content.output_text);
    }
  }
  return parts.join("");
}

async function runOpenAIPriorityCheck(storeData, workspaceId) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw Object.assign(new Error("OPENAI_API_KEY is not configured on the server."), { status: 503 });
  const rows = filtered(storeData, {}, workspaceId);
  if (!rows.length) return { checked: 0, updated: 0, updates: [] };
  const records = rows.map((record) => ({ id: record.id, type: record.type, title: record.title, status: record.status, priorityScore: record.priorityScore, currentReasons: record.priorityReasons || [], tags: record.tags || [], fields: record.fields || {}, createdAt: record.createdAt, updatedAt: record.updatedAt }));
  const schema = { type: "object", additionalProperties: false, required: ["updates"], properties: { updates: { type: "array", items: { type: "object", additionalProperties: false, required: ["id", "priorityLevel", "reason"], properties: { id: { type: "string" }, priorityLevel: { type: "string", enum: ["low", "normal", "high", "highest"] }, reason: { type: "string" } } } } } };
  const payload = {
    model: process.env.OPENAI_PRIORITY_MODEL || process.env.OPENAI_MODEL || "gpt-4.1-mini",
    input: [
      { role: "system", content: "You are a CRM operations assistant. Review every record and assign one of exactly four priority levels: low, normal, high, highest. Highest is only for urgent, high-value, deadline-driven, or immediate-action records that should appear in notifications. Return JSON only." },
      { role: "user", content: "Run a fresh priority check for these records. Consider urgency, deadlines, deal value, follow-up need, buying intent, task due dates, and missing important information. Keep reasons short. Records: " + JSON.stringify(records).slice(0, 70000) }
    ],
    text: { format: { type: "json_schema", name: "priority_review", strict: true, schema } },
    store: false
  };
  const response = await fetch("https://api.openai.com/v1/responses", { method: "POST", headers: { "content-type": "application/json", "authorization": "Bearer " + apiKey }, body: JSON.stringify(payload) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(data.error && data.error.message ? data.error.message : "OpenAI priority check failed."), { status: response.status || 502 });
  const text = extractOpenAIText(data);
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw Object.assign(new Error("OpenAI priority check did not return valid JSON."), { status: 502 }); }
  const priorityMap = { low: 25, normal: 50, high: 75, highest: 95 };
  const byId = new Map(rows.map((record) => [record.id, record]));
  const now = new Date().toISOString();
  const applied = [];
  for (const item of parsed.updates || []) {
    const record = byId.get(clean(item.id));
    const level = clean(item.priorityLevel).toLowerCase();
    if (!record || !(level in priorityMap)) continue;
    const reason = clean(item.reason || "OpenAI priority check").slice(0, 240);
    record.priorityScore = priorityMap[level];
    record.priorityReasons = [reason];
    record.updatedAt = now;
    record.metadata ||= {};
    record.metadata.priorityLevel = level;
    record.metadata.aiPriorityCheckedAt = now;
    record.metadata.aiPriorityModel = data.model || payload.model;
    record.metadata.editHistory ||= [];
    record.metadata.editHistory.push({ at: now, action: "openai_priority_check", source: "OpenAI", reason });
    applied.push({ id: record.id, title: record.title, priorityLevel: level, priorityScore: record.priorityScore, reason });
  }
  return { checked: rows.length, updated: applied.length, model: data.model || payload.model, updates: applied };
}`;

const recordEditorClientCode = String.raw`function editorTypeConfig(type){return {Person:{title:'Name',note:'People and contacts.',extra:[['email','Email','email'],['phone','Phone','text'],['companyName','Company','text'],['role','Role','text']]},Company:{title:'Company name',note:'Organizations, customers, vendors, or accounts.',extra:[['industry','Industry','text'],['website','Website','url'],['contactEmail','Main contact email','email']]},Deal:{title:'Deal title',note:'Opportunities, quotes, proposals, or sales.',extra:[['companyName','Company','text'],['value','Value','number'],['stage','Stage','text']]},Task:{title:'Task title',note:'Follow-ups and work that needs to be completed.',extra:[['taskType','Task type','text'],['status','Status','text']]},Intake:{title:'Intake title',note:'Incoming requests, form submissions, or raw leads.',extra:[['source','Source','text']]},Note:{title:'Note title',note:'Saved context, observations, or internal notes.',extra:[['category','Category','text']]}}[type]||{title:'Title',note:'General record.',extra:[]}}
function priorityLevelForRecord(r){const score=Number(r.priorityScore||0);if((r.metadata||{}).priorityLevel)return r.metadata.priorityLevel;if(score>=95)return 'highest';if(score>=75)return 'high';if(score>=50)return 'normal';return 'low'}
function manualSpecificFields(type){const c=editorTypeConfig(type);return '<p class="muted">'+esc(c.note)+'</p>'+c.extra.map(function(f){return '<label>'+esc(f[1])+'</label><input name="'+esc(f[0])+'" type="'+esc(f[2])+'">'}).join('')}
function editSpecificFields(type,record){const c=editorTypeConfig(type),fields=(record&&record.fields)||{};return '<p class="muted">'+esc(c.note)+'</p>'+c.extra.map(function(f){return '<label>'+esc(f[1])+'</label><input name="'+esc(f[0])+'" type="'+esc(f[2])+'" value="'+esc(fields[f[0]]||'')+'">'}).join('')}
function updateManualForm(){const type=(document.getElementById('manualType')||{}).value||'Person';const label=document.getElementById('manualTitleLabel');if(label)label.textContent=editorTypeConfig(type).title;const fields=document.getElementById('manualSpecificFields');if(fields)fields.innerHTML=manualSpecificFields(type)}
function updateEditFormFields(){const type=(document.getElementById('editType')||{}).value||'Person';const r=S.editingRecord||{};const label=document.getElementById('editTitleLabel');if(label)label.textContent=editorTypeConfig(type).title;const fields=document.getElementById('editSpecificFields');if(fields)fields.innerHTML=editSpecificFields(type,r)}
function crmCount(type){if(type==='all')return S.records.length;if(type==='overview'||type==='edit')return '';return S.records.filter(function(r){return r.type===type}).length}
function crmShell(content){const items=[['overview','Overview'],['all','All Records'],['Person','Contacts'],['Company','Companies'],['Deal','Deals'],['Task','Tasks'],['Intake','Intakes'],['Note','Notes'],['edit','Edit Records']];return '<div class="crmShell"><aside class="crmSide"><div class="crmSideTitle">CRM sections</div>'+items.map(function(item){const id=item[0],label=item[1];return '<button class="crmTab '+(S.crmView===id?'active':'')+'" data-crm="'+id+'"><span>'+label+'</span><span>'+crmCount(id)+'</span></button>'}).join('')+'</aside><div>'+content+'</div></div>'}
function recordRow(r){return '<div class="item recordCard"><div><span class="pill">'+esc(r.type)+'</span> <b>'+esc(r.title)+'</b><div class="fieldLine">ID: '+esc(r.id)+' · Added: '+esc((r.createdAt||'').slice(0,10))+' · Edited: '+esc((r.updatedAt||'').slice(0,10))+'</div><div class="fieldLine">'+esc(recordFields(r)||((r.tags||[]).join(' · ')))+'</div><div class="fieldLine">'+esc((r.priorityReasons||[])[0]||'')+'</div></div><div style="display:grid;gap:8px;justify-items:end"><span class="pill">'+Math.round(r.priorityScore||0)+'</span><button class="secondary" data-edit-record="'+esc(r.id)+'">Edit</button></div></div>'}
function ensureEditDialog(){if(document.getElementById('editRecordDialog'))return;document.body.insertAdjacentHTML('beforeend','<dialog id="editRecordDialog"><form id="editRecordForm"><div class="modalHead"><h2>Edit record</h2><p class="muted" id="editRecordIdLabel"></p></div><div class="modalBody"><input type="hidden" name="id" id="editRecordId"><label>Type of record</label><select name="type" id="editType"><option value="Person">Person</option><option value="Company">Company</option><option value="Deal">Deal</option><option value="Task">Task</option><option value="Intake">Intake</option><option value="Note">Note</option></select><label id="editTitleLabel">Title</label><input name="title" id="editTitle" required><label>Priority</label><select name="priorityLevel" id="editPriority"><option value="low">Low</option><option value="normal">Normal</option><option value="high">High</option><option value="highest">Highest - show in notifications</option></select><label>Associated date</label><input name="associatedDate" id="editAssociatedDate" type="date"><label>Description</label><textarea name="description" id="editDescription"></textarea><label>Tags</label><input name="tags" id="editTags" placeholder="Optional, comma separated"><div id="editSpecificFields"></div><p class="status" id="editStatus"></p></div><div class="modalFoot"><button class="secondary" type="button" id="cancelEditRecord">Cancel</button><button class="primary">Save changes</button></div></form></dialog>');document.getElementById('cancelEditRecord').onclick=function(){editRecordDialog.close()};document.getElementById('editType').onchange=updateEditFormFields;document.getElementById('editRecordForm').onsubmit=async function(e){e.preventDefault();const status=document.getElementById('editStatus');if(status)status.textContent='Saving changes...';try{let payload=Object.fromEntries(new FormData(e.target));await api('/api/records/update',{method:'POST',body:JSON.stringify(payload)});editRecordDialog.close();await load();render()}catch(err){if(status)status.textContent=err.message||'Could not save changes.'}}}
function openRecordEditor(recordId){ensureEditDialog();const r=S.records.find(function(row){return row.id===recordId});if(!r)return;S.editingRecord=r;const f=r.fields||{};document.getElementById('editRecordId').value=r.id;document.getElementById('editRecordIdLabel').textContent='Record ID: '+r.id;document.getElementById('editType').value=r.type;document.getElementById('editTitle').value=r.title||'';document.getElementById('editPriority').value=priorityLevelForRecord(r);document.getElementById('editAssociatedDate').value=(f.associatedDate||f.dueDate||'').slice(0,10);document.getElementById('editDescription').value=f.description||f.body||f.rawText||'';document.getElementById('editTags').value=(r.tags||[]).join(', ');updateEditFormFields();editRecordDialog.showModal()}
function editRecordsContent(){return crmShell('<div class="grid two"><section class="card"><div class="in"><h2>Edit Records</h2><p class="muted">Create a manual record with the required type and title. Constrava generates the record ID, date added, and edit history automatically.</p><form id="manualRecordForm"><label>Type of record</label><select name="type" id="manualType"><option value="Person">Person</option><option value="Company">Company</option><option value="Deal">Deal</option><option value="Task">Task</option><option value="Intake">Intake</option><option value="Note">Note</option></select><label id="manualTitleLabel">Name</label><input name="title" required placeholder="Required"><label>Priority</label><select name="priorityLevel"><option value="low">Low</option><option value="normal" selected>Normal</option><option value="high">High</option><option value="highest">Highest - show in notifications</option></select><label>Associated date</label><input name="associatedDate" type="date"><label>Description</label><textarea name="description" placeholder="Optional notes or saved text for this record"></textarea><label>Tags</label><input name="tags" placeholder="Optional, comma separated"><div id="manualSpecificFields"></div><br><button class="primary">Create manual record</button><p class="status" id="manualStatus"></p></form></div></section><section class="card"><div class="in"><h2>AI Add</h2><p class="muted">Paste a lead, note, email, or form submission. Constrava will draft records for review before committing them.</p><form id="aiForm"><textarea name="rawText" required placeholder="Example: Sarah from Bluebird Dental wants a website quote, budget $6,000, follow up tomorrow."></textarea><br><br><button class="primary">Create AI plan</button></form></div></section></div><div style="margin-top:16px">'+list('Recently edited records',S.records.slice(0,6),'No records yet')+'</div>')}
function crmContent(){if(S.crmView==='overview'){return crmShell('<div class="grid metrics">'+metric('All records',S.records.length,'CRM objects')+metric('Contacts',crmCount('Person'),'People')+metric('Deals',crmCount('Deal'),money(S.summary.metrics.revenueOpportunity))+metric('Tasks',crmCount('Task'),'Follow-ups')+'</div><div style="margin-top:16px">'+list('High-priority CRM records',S.summary.highPriority,'No high priority records')+'</div>')}if(S.crmView==='all')return crmShell(list('All CRM Records',S.records,'No CRM records yet'));if(S.crmView==='edit')return editRecordsContent();return crmShell(list(({Person:'Contacts',Company:'Companies',Deal:'Deals',Task:'Tasks',Intake:'Intakes',Note:'Notes'})[S.crmView]||S.crmView,S.records.filter(function(r){return r.type===S.crmView}),'This section is empty'))}`;

const recordEditorBindCode = String.raw`function bind(){document.querySelectorAll('.tab').forEach(function(b){b.onclick=function(){tab(b.dataset.tab)}});document.querySelectorAll('[data-crm]').forEach(function(b){b.onclick=function(){S.crmView=b.dataset.crm;render()}});document.querySelectorAll('[data-plan]').forEach(function(b){b.onclick=function(){openPlan(S.plans.find(function(p){return p.planId===b.dataset.plan}))}});document.querySelectorAll('[data-edit-record]').forEach(function(b){b.onclick=function(){openRecordEditor(b.dataset.editRecord)}});let typeSelect=document.getElementById('manualType');if(typeSelect){typeSelect.onchange=updateManualForm;updateManualForm()}let manualForm=document.getElementById('manualRecordForm');if(manualForm)manualForm.onsubmit=async function(e){e.preventDefault();const status=document.getElementById('manualStatus');if(status)status.textContent='Saving record...';try{let payload=Object.fromEntries(new FormData(manualForm));await api('/api/records/manual',{method:'POST',body:JSON.stringify(payload)});await load();S.crmView='edit';render()}catch(err){if(status)status.textContent=err.message||'Could not save record.'}};let f=document.getElementById('aiForm');if(f)f.onsubmit=async function(e){e.preventDefault();let p=await api('/api/records/plan',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(f)))});S.plan=p.plan;openPlan(S.plan);await load();S.crmView='edit';render()};let pc=document.getElementById('priorityCheck');if(pc)pc.onclick=async function(){const old=pc.textContent;pc.disabled=true;pc.textContent='Checking priorities...';try{const result=await api('/api/records/priority-check',{method:'POST',body:JSON.stringify({})});await load();pc.textContent='Updated '+result.updated+' records';render();setTimeout(function(){const next=document.getElementById('priorityCheck');if(next){next.textContent=old;next.disabled=false}},1800)}catch(err){pc.textContent=err.message||'Priority check failed';setTimeout(function(){const next=document.getElementById('priorityCheck');if(next){next.textContent=old;next.disabled=false}},3000)}}}`;

let source = await fs.readFile(serverPath, "utf8");
const start = source.indexOf("function signInPage() {");
const end = source.indexOf("\n\nfunction appPage", start);

if (start === -1 || end === -1) {
  throw new Error("Could not locate signInPage() in src/server.js");
}

source = source.slice(0, start) + fixedSignInPage + source.slice(end);
source = source
  .replaceAll("width:min(1100px,calc(100% - 36px));margin:auto", "width:min(1360px,calc(100% - 24px));margin:auto")
  .replaceAll("width:min(1180px,calc(100% - 36px));margin:28px auto", "width:min(1500px,calc(100% - 24px));margin:20px auto")
  .replaceAll("padding:82px 0", "padding:64px 0")
  .replaceAll("gap:44px", "gap:28px")
  .replaceAll('<input id="search" placeholder="Search records, tasks, leads..."> <button class="primary" id="aiAdd">AI Add</button>', '<input id="search" placeholder="Search records, tasks, leads..."> <button class="secondary" id="priorityCheck">AI Priority Check</button> <button class="primary" id="aiAdd">Edit Records</button>')
  .replaceAll("S.crmView='ai'", "S.crmView='edit'");

source = source.replace("\nasync function api(req, res, url, route) {", "\n" + manualRecordServerCode + "\n\n" + updateRecordServerCode + "\n\n" + openAiPriorityServerCode + "\n\nasync function api(req, res, url, route) {");
source = source.replace('if (req.method === "POST" && route === "/api/records/plan") {', 'if (req.method === "POST" && route === "/api/records/manual") { const record = manualRecordFromBody(await readBody(req), ctx.workspaceId); storeData.records.push(record); await saveStore(storeData); return send(res, 201, { record }); } if (req.method === "POST" && route === "/api/records/update") { const record = updateRecordFromBody(storeData, await readBody(req), ctx.workspaceId); await saveStore(storeData); return send(res, 200, { record }); } if (req.method === "POST" && route === "/api/records/priority-check") { const result = await runOpenAIPriorityCheck(storeData, ctx.workspaceId); await saveStore(storeData); return send(res, 200, result); } if (req.method === "POST" && route === "/api/records/plan") {');
source = source.replace("function render(){", recordEditorClientCode + "\nfunction render(){");
source = source.replace("async function refresh(nextTab)", recordEditorBindCode + "\nasync function refresh(nextTab)");

await fs.writeFile(runtimePath, source);
await import(`${pathToFileURL(runtimePath).href}?v=${Date.now()}`);
