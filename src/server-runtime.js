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
const projectAwareSignInPage = fixedSignInPage
  .replace("Enter your saved account details to open your dashboard.", "Enter your saved account details to choose a CRM project.")
  .replace('location.href="/dashboard/"', 'location.href=data.next||"/projects"');

const manualRecordServerCode = String.raw`function manualRecordFromBody(body, workspaceId) {
  const allowedTypes = new Set(["Person", "Company", "Deal", "Task", "Note"]);
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
  return {
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
}`;

const updateRecordServerCode = String.raw`function updateRecordFromBody(storeData, body, workspaceId) {
  const allowedTypes = new Set(["Person", "Company", "Deal", "Task", "Note"]);
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

const settingsServerCode = String.raw`function defaultWorkspaceSettings(workspaceId) {
  return {
    workspaceId,
    workspaceName: "Personal workspace",
    theme: "white-blue",
    density: "comfortable",
    defaultCrmView: "overview",
    notifications: true,
    updatedAt: null
  };
}
function settingsForWorkspace(storeData, workspaceId) {
  storeData.settings ||= {};
  const current = storeData.settings[workspaceId] || {};
  const settings = { ...defaultWorkspaceSettings(workspaceId), ...current, workspaceId };
  storeData.settings[workspaceId] = settings;
  return settings;
}
function updateSettingsFromBody(storeData, workspaceId, body) {
  const settings = settingsForWorkspace(storeData, workspaceId);
  const name = clean(body.workspaceName || body.name || settings.workspaceName).slice(0, 90);
  if (name) settings.workspaceName = name;
  const theme = clean(body.theme || settings.theme);
  if (["white-blue", "green-white", "compact-dark"].includes(theme)) settings.theme = theme;
  const density = clean(body.density || settings.density);
  if (["comfortable", "compact"].includes(density)) settings.density = density;
  const view = clean(body.defaultCrmView || settings.defaultCrmView);
  if (["overview", "all", "Person", "Company", "Deal", "Task", "Note", "edit"].includes(view)) settings.defaultCrmView = view;
  settings.notifications = body.notifications === false || body.notifications === "false" ? false : true;
  settings.updatedAt = new Date().toISOString();
  return settings;
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

const recordEditorClientCode = String.raw`function editorTypeConfig(type){return {Person:{title:'Name',note:'People and contacts.',extra:[['email','Email','email'],['phone','Phone','text'],['companyName','Company','text'],['role','Role','text']]},Company:{title:'Company name',note:'Organizations, customers, vendors, or accounts.',extra:[['industry','Industry','text'],['website','Website','url'],['contactEmail','Main contact email','email']]},Deal:{title:'Deal title',note:'Opportunities, quotes, proposals, or sales.',extra:[['companyName','Company','text'],['value','Value','number'],['stage','Stage','text']]},Task:{title:'Task title',note:'Follow-ups and work that needs to be completed.',extra:[['taskType','Task type','text'],['status','Status','text']]},Note:{title:'Note title',note:'Saved context, observations, or internal notes.',extra:[['category','Category','text']]}}[type]||{title:'Title',note:'General record.',extra:[]}}
function priorityLevelForRecord(r){const score=Number(r.priorityScore||0);if((r.metadata||{}).priorityLevel)return r.metadata.priorityLevel;if(score>=95)return 'highest';if(score>=75)return 'high';if(score>=50)return 'normal';return 'low'}
function manualSpecificFields(type){const c=editorTypeConfig(type);return '<p class="muted">'+esc(c.note)+'</p>'+c.extra.map(function(f){return '<label>'+esc(f[1])+'</label><input name="'+esc(f[0])+'" type="'+esc(f[2])+'">'}).join('')}
function editSpecificFields(type,record){const c=editorTypeConfig(type),fields=(record&&record.fields)||{};return '<p class="muted">'+esc(c.note)+'</p>'+c.extra.map(function(f){return '<label>'+esc(f[1])+'</label><input name="'+esc(f[0])+'" type="'+esc(f[2])+'" value="'+esc(fields[f[0]]||'')+'">'}).join('')}
function updateManualForm(){const type=(document.getElementById('manualType')||{}).value||'Person';const label=document.getElementById('manualTitleLabel');if(label)label.textContent=editorTypeConfig(type).title;const fields=document.getElementById('manualSpecificFields');if(fields)fields.innerHTML=manualSpecificFields(type)}
function updateEditFormFields(){const type=(document.getElementById('editType')||{}).value||'Person';const r=S.editingRecord||{};const label=document.getElementById('editTitleLabel');if(label)label.textContent=editorTypeConfig(type).title;const fields=document.getElementById('editSpecificFields');if(fields)fields.innerHTML=editSpecificFields(type,r)}
function ensurePlainTextRecordDialog(){if(document.getElementById('plainTextRecordDialog'))return;document.body.insertAdjacentHTML('beforeend','<dialog id="plainTextRecordDialog"><form id="plainTextRecordForm"><div class="modalHead"><h2>Add record from plain text</h2><p class="muted">Paste unstructured business information. Constrava will infer specific CRM record types and place every proposal in Review &amp; Publish.</p></div><div class="modalBody"><label for="plainTextRecordInput">Plain text</label><textarea id="plainTextRecordInput" name="rawText" required placeholder="Example: Sarah from Bluebird Dental wants a website quote, budget $6,000, follow up tomorrow."></textarea><p class="status" id="plainTextRecordStatus" aria-live="polite"></p></div><div class="modalFoot"><button class="secondary" type="button" id="cancelPlainTextRecord">Cancel</button><button class="primary" type="submit" id="submitPlainTextRecord">Create records for review</button></div></form></dialog>');const dialog=document.getElementById('plainTextRecordDialog'),form=document.getElementById('plainTextRecordForm'),cancel=document.getElementById('cancelPlainTextRecord');if(cancel)cancel.onclick=function(){dialog.close()};form.onsubmit=async function(event){event.preventDefault();const button=document.getElementById('submitPlainTextRecord'),status=document.getElementById('plainTextRecordStatus'),rawText=String(new FormData(form).get('rawText')||'').trim();if(!rawText)return;if(button){button.disabled=true;button.textContent='Creating records...'}if(status)status.textContent='Constrava AI is organizing this text into draft CRM records.';try{await api('/api/records/plan',{method:'POST',body:JSON.stringify({rawText:rawText,kind:'manual_note',sourceId:'source_manual'})});dialog.close();await load();S.crmView='ai-records';render()}catch(error){if(button){button.disabled=false;button.textContent='Create records for review'}if(status)status.textContent=error.message||'Could not create CRM records from this text.'}}}
function openPlainTextRecordDialog(){ensurePlainTextRecordDialog();const dialog=document.getElementById('plainTextRecordDialog'),form=document.getElementById('plainTextRecordForm'),status=document.getElementById('plainTextRecordStatus'),button=document.getElementById('submitPlainTextRecord');if(form)form.reset();if(status)status.textContent='';if(button){button.disabled=false;button.textContent='Create records for review'}dialog.showModal();document.getElementById('plainTextRecordInput').focus()}
function settingsContent(){const s=S.settings||{};const selected=function(name,value){return String(s[name]||'')===value?' selected':''};const checked=s.notifications===false?'':' checked';return '<div class="grid two"><section class="card"><div class="in"><h2>Workspace settings</h2><p class="muted">These settings are saved to your signed-in account and restored when you log back in.</p><form id="workspaceSettingsForm"><label>Workspace name</label><input name="workspaceName" value="'+esc(s.workspaceName||WORKSPACE_LABEL||'Personal workspace')+'"><label>Theme</label><select name="theme"><option value="white-blue"'+selected('theme','white-blue')+'>White and dark blue</option><option value="green-white"'+selected('theme','green-white')+'>Green and white</option><option value="compact-dark"'+selected('theme','compact-dark')+'>Compact dark</option></select><label>Layout density</label><select name="density"><option value="comfortable"'+selected('density','comfortable')+'>Comfortable</option><option value="compact"'+selected('density','compact')+'>Compact</option></select><label>Default CRM section</label><select name="defaultCrmView"><option value="overview"'+selected('defaultCrmView','overview')+'>Ove…44295 tokens truncated…t api('/api/email-connections/'+encodeURIComponent(state.connection.id)+'/sync',{method:'POST'});state.connection={...state.connection,...(result.connection||{})};if(state.inboxMode){await constravaLoadEmailInbox();return}button.textContent='Processed '+result.processed+' message'+(result.processed===1?'':'s')}catch(error){if(/permission|scope/i.test(error.message||'')){state.connection.authorizationStatus='reauthorization_required';state.connection.status='reauthorization_required';state.connection.lastSyncError=error.message;render();return}button.disabled=false;button.textContent='Sync new email';alert(error.message||'Could not sync the inbox.')}}});\nconst websiteEmptyStepForm=document.getElementById('websiteEmptyStepForm');if(websiteEmptyStepForm)websiteEmptyStepForm.onsubmit=function(event){event.preventDefault();const state=constravaWebsiteSetupState();if(state.step<5){state.step+=1;state.unlocked=Math.max(state.unlocked,state.step);render()}};\ndocument.querySelectorAll('[data-resource-action]').forEach(function(button){button.onclick=async function(){const action=button.dataset.resourceAction;if(action==='copy-snippet'){try{await navigator.clipboard.writeText(S.snippet||'');button.textContent='Copied'}catch(error){button.textContent='Select the snippet to copy'}return}button.textContent='Setup coming next';button.disabled=true}});\n";
source = source.replace("<button class=\"tab\" data-tab=\"resources\">Connected Resources</button>", "<button class=\"tab\" data-tab=\"resources\">Connect Resources</button>");
source = source.replace("name==='resources'?'Connected Resources'", "name==='resources'?'Connect Resources'");
source = source.replace("</style>\n</head>\n<body>\n<header class=\"topbar\">", constravaResourcesCss + constravaActivationCss + constravaFormsCss + constravaEmailCss + constravaFileUploadCss + "\n</style>\n</head>\n<body>\n<header class=\"topbar\">");
source = source.replace("function render(){", constravaResourcesClientCode + "\n" + "function render(){document.body.style.background='';const workspace=document.querySelector('.workspace');if(workspace)workspace.style.display='';");
source = source.replace(/if\(S\.tab==='resources'\)\{h=[\s\S]*?\}if\(S\.tab==='settings'\)/, "if(S.tab==='resources'){h=constravaResourcesContent()}if(S.tab==='settings')");
source = source.replaceAll("function bind(){", "function bind(){" + constravaResourcesBindCode);
if (!source.includes("<button class=\"tab\" data-tab=\"resources\">Connect Resources</button>")) throw new Error("Connect Resources tab button was not installed.");
if (!source.includes("function constravaResourcesContent")) throw new Error("Connect Resources directory was not installed.");
if (!source.includes("data-resource-action")) throw new Error("Connect Resources setup actions were not installed.");
if (!source.includes("/api/file-uploads/analyze") || !source.includes("data-file-open-review")) throw new Error("File Uploads workflow was not installed.");
// colorful-workspaces-runtime-v1
const constravaColorfulWorkspaceStyles = "\n      /* colorful-workspaces-v1 */\n      .crmPage,.resourcesPage{--workspace-violet:#7357ff;--workspace-cyan:#00c2ff;--workspace-pink:#ff5d8f;--workspace-amber:#ffb020;--workspace-mint:#20c997;color:#282342!important}\n      .crmPage{display:grid!important;gap:20px!important;padding-bottom:38px!important}.crmHero{position:relative!important;overflow:hidden!important;border:1px solid rgba(255,255,255,.16)!important;border-radius:28px!important;background:radial-gradient(circle at 12% 0%,rgba(0,194,255,.34),transparent 31%),radial-gradient(circle at 90% 8%,rgba(255,93,143,.31),transparent 30%),linear-gradient(135deg,#171132 0%,#34216d 48%,#08637c 100%)!important;box-shadow:0 28px 70px rgba(31,24,78,.23)!important;color:#fff!important}.crmHeroGlow{position:absolute!important;border-radius:999px!important;pointer-events:none!important}.crmHeroGlowOne{width:260px!important;height:260px!important;right:20%!important;top:-190px!important;background:rgba(115,87,255,.42)!important}.crmHeroGlowTwo{width:190px!important;height:190px!important;right:-70px!important;bottom:-120px!important;background:rgba(32,201,151,.3)!important}.crmHeroContent{position:relative!important;z-index:1!important;display:flex!important;justify-content:space-between!important;align-items:center!important;gap:28px!important;padding:28px 30px!important}.crmHeroCopy{max-width:650px!important}.crmHeroActions{display:flex!important;align-items:center!important;gap:9px!important;flex-wrap:wrap!important;margin:0 0 16px!important}.crmHeroAction{min-height:38px!important;border-radius:12px!important;padding:8px 13px!important;font-size:11px!important;font-weight:950!important;letter-spacing:.01em!important;box-shadow:none!important}.crmHeroActionSecondary{border:1px solid rgba(255,255,255,.24)!important;background:rgba(255,255,255,.11)!important;color:#fff!important;backdrop-filter:blur(12px)!important}.crmHeroActionSecondary:hover{border-color:rgba(255,255,255,.48)!important;background:rgba(255,255,255,.18)!important}.crmHeroActionPrimary{border:1px solid rgba(109,255,207,.28)!important;background:linear-gradient(135deg,#6dffcf,#20c997)!important;color:#0b3b37!important;box-shadow:0 10px 24px rgba(32,201,151,.22)!important}.crmHeroActionPrimary:hover{filter:brightness(1.05)!important}.crmEyebrow{display:inline-flex!important;align-items:center!important;gap:9px!important;color:#dfe8ff!important;font-size:11px!important;font-weight:950!important;letter-spacing:.12em!important;text-transform:uppercase!important}.crmEyebrow i{width:9px!important;height:9px!important;border-radius:999px!important;background:#6dffcf!important;box-shadow:0 0 0 5px rgba(109,255,207,.13)!important}.crmHeroCopy h2{margin:10px 0 0!important;color:#fff!important;font-size:clamp(32px,4vw,52px)!important;line-height:1!important;letter-spacing:-.055em!important}.crmHeroCopy p{max-width:610px!important;margin:12px 0 0!important;color:rgba(237,244,255,.76)!important;font-size:14px!important;line-height:1.55!important}.crmHeroStats{display:grid!important;grid-template-columns:repeat(3,minmax(105px,1fr))!important;gap:9px!important;min-width:390px!important}.crmHeroStats span{display:block!important;border:1px solid rgba(255,255,255,.16)!important;border-radius:16px!important;background:rgba(255,255,255,.1)!important;padding:13px!important;backdrop-filter:blur(14px)!important}.crmHeroStats span:nth-child(2){background:rgba(0,194,255,.12)!important}.crmHeroStats span:nth-child(3){background:rgba(255,93,143,.12)!important}.crmHeroStats b{display:block!important;color:#fff!important;font-size:22px!important;line-height:1!important;font-weight:950!important}.crmHeroStats small{display:block!important;margin-top:6px!important;color:rgba(237,244,255,.7)!important;font-size:10px!important;font-weight:900!important;letter-spacing:.04em!important;text-transform:uppercase!important}\n      .crmPage .crmShell{gap:16px!important}.crmPage .crmSide{border:1px solid #e4e0f0!important;border-radius:22px!important;background:linear-gradient(180deg,#fff 0%,#f7f5ff 54%,#effaff 100%)!important;box-shadow:0 18px 46px rgba(68,52,135,.1)!important;padding:12px!important}.crmPage .crmSideTitle{margin:6px 9px 10px!important;color:#756d8f!important;font-size:10px!important;letter-spacing:.12em!important}.crmSideIntro{margin:0 7px 13px!important;border-radius:14px!important;background:#efecff!important;padding:11px!important;color:#6f668e!important;font-size:11px!important;line-height:1.45!important}.crmSideIntro b{color:#5943c2!important}.crmPage .crmTab{min-height:43px!important;margin-top:3px!important;border:1px solid transparent!important;border-radius:13px!important;color:#4d4765!important;padding:10px 11px!important;transition:transform .16s ease,background .16s ease,border-color .16s ease!important}.crmPage .crmTab>span:last-child{display:grid!important;place-items:center!important;min-width:24px!important;height:24px!important;border-radius:8px!important;background:#eceaf4!important;color:#716a86!important;padding:0 6px!important;font-size:10px!important}.crmPage .crmTab:hover{transform:translateX(2px)!important;border-color:#ddd7f2!important;background:#fff!important;color:#4e38bd!important}.crmPage .crmTab.active{border-color:transparent!important;background:linear-gradient(135deg,#7357ff,#4f46e5)!important;color:#fff!important;box-shadow:0 10px 22px rgba(93,72,202,.24)!important}.crmPage .crmTab.active>span:last-child{background:rgba(255,255,255,.17)!important;color:#fff!important}.crmCanvas{min-width:0!important}.crmCanvas>.card,.crmCanvas>.grid>.card,.crmCanvas>div>.card{border:1px solid #e7e4ef!important;border-radius:22px!important;box-shadow:0 16px 42px rgba(66,51,125,.08)!important}.crmCanvas .metrics{gap:12px!important}.crmCanvas .metrics .card{position:relative!important;overflow:hidden!important;min-height:146px!important;border:0!important;background:linear-gradient(145deg,#f1edff,#fff)!important}.crmCanvas .metrics .card:nth-child(2){background:linear-gradient(145deg,#e9faff,#fff)!important}.crmCanvas .metrics .card:nth-child(3){background:linear-gradient(145deg,#fff0f5,#fff)!important}.crmCanvas .metrics .card:nth-child(4){background:linear-gradient(145deg,#fff8e7,#fff)!important}.crmCanvas .metrics .card:before{content:''!important;position:absolute!important;left:0!important;right:0!important;top:0!important;height:4px!important;background:linear-gradient(90deg,#7357ff,#9d8cff)!important}.crmCanvas .metrics .card:nth-child(2):before{background:linear-gradient(90deg,#00c2ff,#20c997)!important}.crmCanvas .metrics .card:nth-child(3):before{background:linear-gradient(90deg,#ff5d8f,#ff8ab0)!important}.crmCanvas .metrics .card:nth-child(4):before{background:linear-gradient(90deg,#ffb020,#ff5d8f)!important}.crmCanvas .metrics .in{padding:18px!important}.crmCanvas .metrics .muted:first-child{color:#77708d!important;font-size:10px!important;font-weight:950!important;letter-spacing:.09em!important;text-transform:uppercase!important}.crmCanvas .metricValue{color:#282052!important;font-size:34px!important;letter-spacing:-.045em!important}.crmCanvas h2{color:#282052!important;letter-spacing:-.025em!important}.crmCanvas .crmToolbar{border:1px solid #ebe8f2!important;border-radius:15px!important;background:#f8f7fc!important;padding:10px!important}.crmCanvas .crmToolbar input,.crmCanvas .crmToolbar select{border-color:#ded9eb!important;background:#fff!important;color:#37304f!important}.crmCanvas .recordCard{margin-top:9px!important;border:0!important;border-radius:16px!important;background:#f6f4ff!important;padding:14px!important}.crmCanvas .recordCard:nth-child(3n+2){background:#effaff!important}.crmCanvas .recordCard:nth-child(3n+3){background:#fff2f6!important}.crmCanvas .recordCard>b,.crmCanvas .recordCard b{color:#332b55!important}.crmCanvas .fieldLine{color:#777f96!important}.crmCanvas .pill{border:0!important;background:#e7e2ff!important;color:#5943c2!important}.crmCanvas .recordCard:nth-child(3n+2) .pill{background:#dff8ff!important;color:#087ba4!important}.crmCanvas .recordCard:nth-child(3n+3) .pill{background:#ffe4ed!important;color:#bd3562!important}.crmPage .primary{background:linear-gradient(135deg,#7357ff,#4f46e5)!important;box-shadow:0 9px 20px rgba(93,72,202,.2)!important}.crmPage .secondary{border-color:#ddd8eb!important;background:#fff!important;color:#554d70!important}.crmPage .secondary:hover{border-color:#bdb4e8!important;background:#f5f2ff!important}.crmPage .crmEmpty,.crmPage .empty{border:1px dashed #d8d1ed!important;border-radius:18px!important;background:linear-gradient(145deg,#faf9ff,#f2fbff)!important;color:#77708d!important}\n      .resourcesPage{max-width:1260px!important;padding-bottom:38px!important}.resourcesIntro{position:relative!important;align-items:center!important;overflow:hidden!important;margin-bottom:16px!important;border:1px solid rgba(255,255,255,.15)!important;border-radius:28px!important;background:radial-gradient(circle at 10% 0%,rgba(32,201,151,.34),transparent 31%),radial-gradient(circle at 90% 5%,rgba(255,176,32,.3),transparent 28%),linear-gradient(135deg,#14112f 0%,#253875 52%,#087a72 100%)!important;box-shadow:0 28px 70px rgba(31,24,78,.22)!important;padding:30px!important;color:#fff!important}.resourcesIntro:after{content:''!important;position:absolute!important;width:220px!important;height:220px!important;right:18%!important;top:-165px!important;border-radius:999px!important;background:rgba(0,194,255,.28)!important}.resourcesIntro>div,.resourcesIntro>.pill{position:relative!important;z-index:1!important}.resourcesIntro h2{color:#fff!important;font-size:clamp(32px,4vw,50px)!important;line-height:1!important;letter-spacing:-.055em!important}.resourcesIntro p{max-width:720px!important;color:rgba(237,244,255,.77)!important;font-size:14px!important;line-height:1.55!important}.resourcesIntro>.pill{border:1px solid rgba(255,255,255,.18)!important;border-radius:15px!important;background:rgba(255,255,255,.11)!important;color:#fff!important;padding:10px 13px!important;backdrop-filter:blur(12px)!important}.resourceViewTabs{display:inline-flex!important;border:1px solid #e4e0ef!important;border-radius:15px!important;background:#f5f3fa!important;padding:4px!important}.resourceViewTab{border:0!important;border-radius:11px!important;background:transparent!important;color:#756e8c!important;padding:9px 14px!important}.resourceViewTab.active{background:linear-gradient(135deg,#20c997,#079c87)!important;color:#fff!important;box-shadow:0 8px 18px rgba(18,151,126,.22)!important}.resourceDirectory{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:14px!important;overflow:visible!important;border:0!important;background:transparent!important;box-shadow:none!important}.resourceRow{position:relative!important;display:grid!important;grid-template-columns:52px minmax(0,1fr)!important;grid-template-rows:auto 1fr!important;gap:12px!important;align-items:start!important;min-height:185px!important;overflow:hidden!important;border:1px solid #e8e4ef!important;border-radius:22px!important;background:linear-gradient(145deg,#f2efff,#fff)!important;padding:18px!important;box-shadow:0 15px 38px rgba(68,52,135,.08)!important;transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease!important}.resourceRow:nth-child(3n+2){background:linear-gradient(145deg,#eafbff,#fff)!important}.resourceRow:nth-child(3n+3){background:linear-gradient(145deg,#fff0f5,#fff)!important}.resourceRow:nth-child(4n+4){background:linear-gradient(145deg,#fff8e7,#fff)!important}.resourceRow:before{content:''!important;position:absolute!important;left:0!important;right:0!important;top:0!important;height:4px!important;background:linear-gradient(90deg,#7357ff,#00c2ff)!important}.resourceRow:nth-child(3n+2):before{background:linear-gradient(90deg,#00c2ff,#20c997)!important}.resourceRow:nth-child(3n+3):before{background:linear-gradient(90deg,#ff5d8f,#ffb020)!important}.resourceRow:nth-child(4n+4):before{background:linear-gradient(90deg,#ffb020,#7357ff)!important}.resourceRow:hover,.resourceRow:focus-visible{transform:translateY(-4px)!important;border-color:#cfc7ed!important;background-color:#fff!important;box-shadow:0 22px 48px rgba(68,52,135,.14)!important}.resourceGlyph{width:50px!important;height:50px!important;border:0!important;border-radius:16px!important;background:linear-gradient(135deg,#7357ff,#4f46e5)!important;color:#fff!important;box-shadow:0 10px 22px rgba(94,72,201,.24)!important}.resourceRow:nth-child(3n+2) .resourceGlyph{background:linear-gradient(135deg,#00c2ff,#089bbf)!important}.resourceRow:nth-child(3n+3) .resourceGlyph{background:linear-gradient(135deg,#ff5d8f,#db3e72)!important}.resourceRow:nth-child(4n+4) .resourceGlyph{background:linear-gradient(135deg,#ffb020,#ef8b12)!important}.resourceRow>span:nth-child(2){grid-column:1/-1!important}.resourceRow h3{color:#302852!important;font-size:18px!important;letter-spacing:-.02em!important}.resourceRow p{color:#7d849a!important;font-size:12px!important}.resourceRowStatus{position:absolute!important;right:14px!important;top:14px!important}.resourceArrow{display:grid!important;place-items:center!important;width:30px!important;height:30px!important;border-radius:10px!important;background:rgba(255,255,255,.72)!important;color:#6550da!important;padding:0!important}.resourceConnected{background:#dff8ee!important;color:#087d5a!important}.resourcesFinePrint{color:#8a91a8!important;text-align:center!important}.connectedResourcesEmpty{border:1px dashed #d7d1e9!important;border-radius:22px!important;background:linear-gradient(145deg,#faf9ff,#effcff)!important}.resourcesPage>.card:not(.resourceDirectory),.resourceDetail>.card,.resourceDetailWebsite>.card{border:1px solid #e7e3ef!important;border-radius:24px!important;box-shadow:0 20px 54px rgba(66,51,125,.1)!important}.resourceBack{color:#6049cb!important}.resourceDetailHead .resourceGlyph{background:linear-gradient(135deg,#7357ff,#00a9d8)!important}.resourceDetailHead h2,.resourceSetup h3,.websiteStepPanel h3,.installExperienceHead h4,.constravaInboxHead h3{color:#302852!important}.resourceStatus,.developerBrief{border:1px solid #dfdaee!important;background:#f5f2ff!important;color:#625a79!important}.websiteStepNav{border-color:#e4e0ef!important;border-radius:20px!important;background:linear-gradient(180deg,#fff,#f5f3ff)!important;box-shadow:0 15px 36px rgba(68,52,135,.08)!important}.websiteStepButton{border-radius:13px!important}.websiteStepButton.active{background:linear-gradient(135deg,#20c997,#079c87)!important;box-shadow:0 9px 20px rgba(18,151,126,.2)!important}.websiteStepPanel,.installExperience,.connectionEvents,.constravaInboxGrid{border-color:#e7e3ef!important;border-radius:20px!important;box-shadow:0 14px 36px rgba(66,51,125,.07)!important}.websiteTrackOption,.formsMethodCard,.emailProviderCard,.emailScopeOption,.connectionCheck{border-color:#e4e0ef!important;border-radius:15px!important;background:#faf9ff!important}.websiteTrackOption:hover,.formsMethodCard:hover,.emailProviderCard:hover{border-color:#c9c0ed!important;background:#f3f0ff!important}.installMethodCard.active,.constravaInboxFilter.active{background:linear-gradient(135deg,#7357ff,#4f46e5)!important;border-color:transparent!important}.resourcesPage .primary,.resourceDetail .primary{background:linear-gradient(135deg,#20c997,#079c87)!important;box-shadow:0 9px 20px rgba(18,151,126,.2)!important}.resourcesPage .secondary,.resourceDetail .secondary{border-color:#ddd8eb!important;background:#fff!important;color:#554d70!important}\n      @media(max-width:1120px){.crmHeroContent{display:grid!important}.crmHeroStats{min-width:0!important;width:100%!important}.resourceDirectory{grid-template-columns:repeat(2,minmax(0,1fr))!important}}\n      @media(max-width:760px){.crmHeroContent,.resourcesIntro{padding:22px 18px!important}.crmHeroStats{grid-template-columns:1fr!important}.crmPage .crmSide{overflow-x:auto!important}.crmPage .crmTab{min-width:165px!important}.resourceDirectory{grid-template-columns:1fr!important}.resourceRow{min-height:165px!important}.resourcesIntro{display:grid!important;gap:18px!important}.resourcesIntro>.pill{justify-self:start!important}}\n    ";
const constravaDashboardTitleIndex = source.indexOf("<title>Constrava Dashboard</title>");
const constravaDashboardStyleEndIndex = source.indexOf("</style>", constravaDashboardTitleIndex);
if (constravaDashboardTitleIndex < 0 || constravaDashboardStyleEndIndex < 0) throw new Error("Could not find the dashboard stylesheet.");
source = source.slice(0, constravaDashboardStyleEndIndex) + constravaColorfulWorkspaceStyles + source.slice(constravaDashboardStyleEndIndex);
if (!source.slice(constravaDashboardTitleIndex).includes("colorful-workspaces-v1")) throw new Error("Could not install the colorful workspace styles.");
await fs.writeFile(runtimePath, source);
await import(`${pathToFileURL(runtimePath).href}?v=${Date.now()}`);

// live-analytics-display-v2
