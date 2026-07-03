import fs from "fs";

const serverFile = "server.js";
const clientFile = "crm-distinct-tabs.js";

function patchServer() {
  if (!fs.existsSync(serverFile)) return console.warn("[crm-llm-action-planner] server.js not found.");
  let source = fs.readFileSync(serverFile, "utf8");
  if (source.includes("__crmLlmActionPlanner_v1")) return console.log("CRM LLM action planner server patch already applied.");

  const block = `
// __crmLlmActionPlanner_v1
const CRM_ACTION_TYPES = ["Lead", "Person", "Company", "Deal", "Task", "Intake", "Note"];
function cleanCrmActionType(value) {
  const key = String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  if (["lead", "leads", "prospect", "prospects"].includes(key)) return "Lead";
  if (["person", "people", "contact", "contacts", "customer", "client"].includes(key)) return "Person";
  if (["company", "companies", "business", "businesses", "organization", "organisation", "account"].includes(key)) return "Company";
  if (["deal", "deals", "sale", "sales", "opportunity", "proposal"].includes(key)) return "Deal";
  if (["task", "tasks", "todo", "to do", "follow up", "followup", "reminder"].includes(key)) return "Task";
  if (["intake", "form", "submission", "request"].includes(key)) return "Intake";
  if (["note", "notes", "memo"].includes(key)) return "Note";
  return "";
}
function compactActionText(value) { return String(value ?? "").trim(); }
function normalizeExistingCrmContext(list) {
  const input = Array.isArray(list) ? list : [];
  return input.slice(0, 60).map((r, i) => ({
    record_id: compactActionText(r.record_id || r.lead_id || r.id || "CTX-" + (i + 1)),
    record_type: cleanCrmActionType(r.record_type || r.type) || compactActionText(r.record_type || r.type || ""),
    name: compactActionText(r.name || r.title || ""),
    company: compactActionText(r.company || ""),
    email: compactActionText(r.email || ""),
    phone: compactActionText(r.phone || r.mobile || ""),
    status: compactActionText(r.status || r.stage || ""),
    priority: compactActionText(r.priority || ""),
    value: Number(r.value || 0) || 0,
    deal_name: compactActionText(r.deal_name || ""),
    next_step: compactActionText(r.next_step || "").slice(0, 180),
    notes: compactActionText(r.notes || r.message || r.description || "").slice(0, 220)
  }));
}
function fallbackCrmActions(text) {
  const t = String(text || "").toLowerCase();
  const records = [];
  const add = (record_type, reason) => records.push({ action: "create", record_type, name: "", company: "", email: "", phone: "", status: "New", priority: /urgent|soon|high/.test(t) ? "High" : "Normal", value: 0, deal_name: "", next_step: "", notes: compactActionText(text), source: "AI Text Add", target_record_id: "", reason, confidence: 0.6 });
  if (/lead|prospect|reached out|website|pricing|quote|estimate|potential client|custom dashboard/.test(t)) add("Lead", "Fallback detected a new sales lead.");
  if (/company record|business record|organization record|account record|company|business|organization|^[A-Z]/.test(String(text || ""))) add("Company", "Fallback detected a company or account.");
  if (/\\$|deal|proposal|contract|purchase|opportunity|project value|budget|paid project|worth around|estimate/.test(t)) add("Deal", "Fallback detected deal or revenue language.");
  let tasks = (t.match(/follow up|follow-up|call back|remind|reminder|next step|schedule|send .*example|ask .*tomorrow|ask .*friday|ask .*monday/g) || []).length;
  if (/second reminder|another reminder|two tasks|2 tasks|two follow ups|both reminders/.test(t)) tasks = Math.max(tasks, 2);
  for (let i = 0; i < Math.min(4, tasks); i++) add("Task", i ? "Fallback detected another requested task." : "Fallback detected a follow-up task.");
  if (!records.length) add("Lead", "Fallback default action.");
  return records.slice(0, 10);
}
function normalizeCrmActions(records, text) {
  const input = Array.isArray(records) ? records : [];
  const output = [];
  for (const item of input) {
    if (!item || typeof item !== "object") continue;
    const actionKey = String(item.action || "create").toLowerCase().trim();
    const action = actionKey === "update" || actionKey === "edit" ? "update" : actionKey === "none" || actionKey === "ignore" ? "none" : "create";
    if (action === "none") continue;
    const type = cleanCrmActionType(item.record_type || item.type);
    if (!CRM_ACTION_TYPES.includes(type)) continue;
    output.push({
      action,
      target_record_id: compactActionText(item.target_record_id || item.target_id || ""),
      record_type: type,
      name: compactActionText(item.name || ""),
      company: compactActionText(item.company || ""),
      email: compactActionText(item.email || ""),
      phone: compactActionText(item.phone || ""),
      status: compactActionText(item.status || (action === "create" ? "New" : "")),
      priority: compactActionText(item.priority || "Normal"),
      value: Number(item.value || 0) || 0,
      deal_name: compactActionText(item.deal_name || ""),
      next_step: compactActionText(item.next_step || ""),
      notes: compactActionText(item.notes || text),
      source: compactActionText(item.source || "AI Text Add"),
      reason: compactActionText(item.reason || (action === "update" ? "LLM chose to update an existing CRM record." : "LLM chose to create a new CRM record.")),
      confidence: Math.max(0, Math.min(1, Number(item.confidence || 0.8) || 0.8))
    });
    if (output.length >= 12) break;
  }
  return output.length ? output : fallbackCrmActions(text);
}
app.post("/api/crm/llm-actions", async (req, res) => {
  try {
    const text = compactActionText(req.body && req.body.text);
    if (!text) return res.status(400).json({ ok: false, error: "Missing CRM text." });
    const existing_records = normalizeExistingCrmContext(req.body && req.body.existing_records);
    const fallback_records = fallbackCrmActions(text);
    if (!process.env.OPENAI_API_KEY) return res.json({ ok: true, using_fallback: true, model: "rules", records: fallback_records, record_types: fallback_records.map(r => r.record_type), prompt_version: "crm-action-planner-v1" });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const systemPrompt = "You are the CRM action planning engine for Constrava. Read a messy CRM instruction and a compact list of existing CRM records. Decide whether to CREATE new records or UPDATE existing records. Return exact formatted CRM action records for the dashboard. Allowed actions: create, update, none. Allowed record types: Lead, Person, Company, Deal, Task, Intake, Note. Use update when the text clearly refers to an existing record by company, person, email, deal, task, or context, or when the user says update, edit, change, mark, qualify, close, revise, add notes to, change status, change priority, change value, or add next step. Use create when the text describes a new lead/company/deal/task/intake/note that is not already represented. One prompt may return multiple actions, including updating one existing record and creating a new task. For update actions, set target_record_id to one of the provided existing_records record_id values. If you cannot confidently match an existing record, create a new record instead of updating. Do not invent people, companies, emails, phone numbers, budgets, or dates. Preserve existing data unless the text clearly changes it. Return only JSON: {\"records\":[{\"action\":\"create|update|none\",\"target_record_id\":\"existing id for update or empty\",\"record_type\":\"Lead|Person|Company|Deal|Task|Intake|Note\",\"name\":\"\",\"company\":\"\",\"email\":\"\",\"phone\":\"\",\"status\":\"\",\"priority\":\"\",\"value\":0,\"deal_name\":\"\",\"next_step\":\"\",\"notes\":\"\",\"source\":\"AI Text Add\",\"reason\":\"short reason\",\"confidence\":0.0}],\"summary\":\"short summary\"}.";
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.OPENAI_API_KEY },
      body: JSON.stringify({ model: process.env.OPENAI_MODEL || "gpt-4o-mini", temperature: 0, response_format: { type: "json_object" }, messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: JSON.stringify({ crm_text: text, existing_records, fallback_create_guess: fallback_records, instruction: "Return create/update actions. Update existing records when the note clearly refers to one of the existing_records." }) }
      ] })
    });
    clearTimeout(timer);
    const json = await response.json();
    if (!response.ok) return res.json({ ok: true, using_fallback: true, model: process.env.OPENAI_MODEL || "gpt-4o-mini", records: fallback_records, record_types: fallback_records.map(r => r.record_type), llm_error: json.error && json.error.message, prompt_version: "crm-action-planner-v1" });
    let parsed = {};
    try { parsed = JSON.parse(json.choices?.[0]?.message?.content || "{}"); } catch { parsed = {}; }
    const records = normalizeCrmActions(parsed.records, text);
    return res.json({ ok: true, using_fallback: false, model: process.env.OPENAI_MODEL || "gpt-4o-mini", records, record_types: records.map(r => r.record_type), summary: compactActionText(parsed.summary || ""), prompt_version: "crm-action-planner-v1" });
  } catch (error) {
    const text = compactActionText(req.body && req.body.text);
    const records = fallbackCrmActions(text);
    return res.json({ ok: true, using_fallback: true, model: "rules", records, record_types: records.map(r => r.record_type), error: String(error && error.message || error), prompt_version: "crm-action-planner-v1" });
  }
});

`;
  const marker = "app.get(\"/\"";
  const idx = source.indexOf(marker);
  if (idx === -1) return console.warn("[crm-llm-action-planner] Could not find insertion point.");
  source = source.slice(0, idx) + block + source.slice(idx);
  fs.writeFileSync(serverFile, source);
  console.log("CRM LLM action planner server endpoint applied.");
}

function patchClient() {
  if (!fs.existsSync(clientFile)) return console.warn("[crm-llm-action-planner] crm-distinct-tabs.js not found.");
  let source = fs.readFileSync(clientFile, "utf8");
  if (source.includes("__crmClientActionPlan_v1")) return console.log("CRM LLM action planner client patch already applied.");
  const aiStart = source.indexOf("async function aiAdd(){");
  const aiEnd = source.indexOf("function formValue", aiStart);
  if (aiStart === -1 || aiEnd === -1) return console.warn("[crm-llm-action-planner] Could not replace aiAdd.");

  const helperAndAiAdd = `
// __crmClientActionPlan_v1
function compactRecordForAi(e,i){return{record_id:String(e.record_id||e.lead_id||e.id||'CTX-'+(i+1)),record_type:Array.isArray(e.record_type)?e.record_type[0]:e.record_type,name:e.name||e.title||'',company:e.company||'',email:e.email||'',phone:e.phone||e.mobile||'',status:e.status||e.stage||'',priority:e.priority||'',value:Number(e.value||0)||0,deal_name:e.deal_name||'',next_step:e.next_step||'',notes:String(e.notes||e.message||e.description||'').slice(0,240)}}
async function llmActionPlan(text){
  const existing=dedupe(state.entries.concat(pageData())).slice(0,60).map(compactRecordForAi);
  try{
    const response=await fetch('/api/crm/llm-actions?token='+encodeURIComponent(token),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,text,existing_records:existing})});
    const data=await response.json();
    const actions=Array.isArray(data.records)?data.records.filter(r=>r&&r.record_type):[];
    if(data&&data.ok&&actions.length){return{actions,count:actions.length,typeParts:actions.map(a=>a.record_type),records:actions,model:data.model||'unknown',usingFallback:!!data.using_fallback,promptVersion:data.prompt_version||'crm-action-planner-v1'}};
  }catch(e){}
  const fallback=typeof llmPlan==='function'?await llmPlan(text):autoPlan(text);
  const actions=(fallback.records||fallback.suggestions||fallback.typeParts||[]).map((r,i)=>typeof r==='string'?{action:'create',record_type:r}:{action:'create',record_type:r.record_type||fallback.typeParts&&fallback.typeParts[i]||'Lead',...r});
  return{...fallback,actions,records:actions,typeParts:actions.map(a=>a.record_type),promptVersion:'crm-action-planner-fallback'};
}
function findActionTarget(action){
  const id=String(action.target_record_id||action.target_id||'').trim();
  const list=dedupe(state.entries.concat(pageData()));
  if(id){const found=list.find(e=>String(e.record_id||e.lead_id||e.id||'')===id);if(found)return found;}
  const type=String(action.record_type||'').toLowerCase(),company=clean(action.company),name=clean(action.name),email=clean(action.email);
  return list.find(e=>{const types=recordTypes(e).map(t=>String(t).toLowerCase());return(!type||types.includes(type))&&((email&&clean(e.email)===email)||(company&&clean(e.company)===company)||(name&&clean(e.name||e.title)===name));})||null;
}
function applyActionFields(record,action,index){
  const keep={lead_id:record.lead_id,record_id:record.record_id,related_record_ids:record.related_record_ids,raw_submission:record.raw_submission};
  const merged=Object.assign({},record);const cv=v=>String(v==null?'':v).trim();
  ['record_type','name','company','email','phone','status','priority','deal_name','next_step','notes','source'].forEach(k=>{if(action[k]!=null&&cv(action[k]))merged[k]=cv(action[k]);});
  if(action.value!=null&&!Number.isNaN(Number(action.value)))merged.value=Number(action.value)||0;
  merged.reason=cv(action.reason||merged.reason||'LLM action planner changed this record.');merged.confidence=Number(action.confidence||merged.confidence||0.8)||0.8;
  merged.raw_submission=Object.assign({},keep.raw_submission||{}, {llm_action_record:action, requested_record_number:index+1});
  merged.lead_id=keep.lead_id;merged.record_id=keep.record_id;merged.related_record_ids=keep.related_record_ids;
  return normalize(merged,index);
}
async function aiAdd(){
  const input=document.getElementById('cxWorkflowAiInput'),status=document.getElementById('cxWorkflowStatus'),text=input?input.value.trim():'';if(!text)return;
  if(status)status.textContent='AI is planning create/update actions...';
  const plan=await llmActionPlan(text);
  const actions=Array.isArray(plan.actions)?plan.actions:[];
  const updateActions=actions.filter(a=>String(a.action||'create').toLowerCase()==='update');
  const createActions=actions.filter(a=>String(a.action||'create').toLowerCase()!=='update'&&String(a.action||'create').toLowerCase()!=='none');
  let updatedCount=0;
  updateActions.forEach((action,i)=>{const target=findActionTarget(action);if(target){replaceRecord(target,applyActionFields(target,action,i));updatedCount++;}else{createActions.push({...action,action:'create'});}});
  const createPlan={count:createActions.length,typeParts:createActions.map(a=>a.record_type),records:createActions};
  const candidates=createActions.length?recordsFromPlan(text,createPlan).map((r,i)=>applyActionFields(r,createActions[i],i)):[];
  const checked=rejectDupes(candidates,state.entries.concat(pageData()));
  if(checked.kept.length)saveSession(checked.kept);
  state.entries=dedupe(checked.kept.concat(state.entries,pageData())).map(normalize);
  if(input)input.value='';state.active='all';render();
  const s=document.getElementById('cxWorkflowStatus');
  if(s)s.textContent='AI completed '+updatedCount+' update(s), saved '+checked.kept.length+' new record(s)'+(checked.skipped.length?', and skipped '+checked.skipped.length+' duplicate(s).':'.');
}
`;
  source = source.slice(0, aiStart) + helperAndAiAdd + source.slice(aiEnd);
  fs.writeFileSync(clientFile, source);
  console.log("CRM LLM action planner client hook applied.");
}

patchServer();
patchClient();
