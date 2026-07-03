import fs from "fs";

const serverFile = "server.js";
const clientFile = "crm-distinct-tabs.js";

function patchServer() {
  if (!fs.existsSync(serverFile)) {
    console.warn("[crm-llm-record-planner-patch] server.js not found.");
    return;
  }
  let source = fs.readFileSync(serverFile, "utf8");
  if (source.includes("__crmLlmRecordPlanner_v2")) {
    console.log("CRM LLM formatted record planner server patch already applied.");
    return;
  }

  const block = `
// __crmLlmRecordPlanner_v2
const CRM_RECORD_TYPES = ["Lead", "Person", "Company", "Deal", "Task", "Intake", "Note"];
function cleanCrmRecordType(value) {
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
function compactCrmText(value) { return String(value ?? "").trim(); }
function extractCrmEmail(value) { return (compactCrmText(value).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/i) || [""])[0]; }
function extractCrmPhone(value) { return (compactCrmText(value).match(/(?:\\+?1[\\s.-]?)?(?:\\(?\\d{3}\\)?[\\s.-]?)\\d{3}[\\s.-]?\\d{4}/) || [""])[0]; }
function extractCrmCompany(value) {
  const text = compactCrmText(value);
  const from = text.match(/from\\s+([A-Z][A-Za-z0-9& .'-]{2,70})(?:\\s+(?:reached|wants|needs|is|and|with|called|asked|said)|[.,]|$)/);
  const explicit = text.match(/(?:company|business|organization|account)\\s+(?:called|named|is|:)?\\s*([A-Z][A-Za-z0-9& .'-]{2,70})(?:\\s+(?:is|was|wants|needs|called|reached|asked|said|has|with)|[.,]|$)/i);
  const start = text.match(/^([A-Z][A-Za-z0-9& .'-]{2,70})(?:\\s+(?:is|was|wants|needs|called|reached|asked|said|has|with|interested)\\b|[.,])/);
  return compactCrmText((explicit && explicit[1]) || (from && from[1]) || (start && start[1]) || "");
}
function extractCrmPerson(value) {
  const text = compactCrmText(value);
  const m = text.match(/(?:named|name is|lead is|person is|contact is)\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+){0,2})/) || text.match(/^([A-Z][a-z]+(?:\\s+[A-Z][a-z]+){0,2})\\s+from\\s+/);
  return compactCrmText(m && m[1] || "");
}
function extractCrmValue(value) {
  const match = compactCrmText(value).replace(/,/g, "").match(/\\$\\s*(\\d{2,8})(?:\\.\\d{1,2})?|\\b(?:worth|budget|value|estimate|estimated at|around)\\s+(\\d{2,8})\\b/i);
  return match ? Number(match[1] || match[2] || 0) || 0 : 0;
}
function baseFormattedCrmRecord(type, text, reason = "Rule-based fallback") {
  const person = extractCrmPerson(text);
  const email = extractCrmEmail(text);
  const phone = extractCrmPhone(text);
  const company = extractCrmCompany(text);
  const value = extractCrmValue(text);
  const target = company || person || "CRM record";
  const record = { record_type: type, name: "", company: company || "", email: "", phone: "", status: "New", priority: /urgent|soon|ready|high/i.test(text) ? "High" : "Normal", value: 0, deal_name: "", next_step: "", notes: compactCrmText(text), source: "AI Text Add", reason, confidence: 0.65 };
  if (type === "Lead") { record.name = person || (company ? company + " lead" : "AI Text lead"); record.email = email; record.phone = phone; record.value = value; }
  if (type === "Person") { record.name = person || email || phone || "Unnamed Person"; record.email = email; record.phone = phone; }
  if (type === "Company") { record.name = company || "Company Record"; record.company = company || record.name; record.status = "Active"; }
  if (type === "Deal") { record.name = "Deal for " + target; record.deal_name = record.name; record.value = value; }
  if (type === "Task") { record.name = "Follow up with " + target; record.next_step = /follow up|follow-up|call back|remind|reminder|send|ask/i.test(text) ? compactCrmText(text).slice(0, 220) : "Follow up based on CRM note."; }
  if (type === "Intake") { record.name = "Intake from " + target; record.email = email; record.phone = phone; }
  if (type === "Note") { record.name = "Note about " + target; }
  return record;
}
function fallbackCrmPlan(text) {
  const t = String(text || "").toLowerCase();
  const records = [];
  const add = (type, reason) => records.push(baseFormattedCrmRecord(type, text, reason));
  if (/lead|prospect|reached out|website|pricing|quote|estimate|potential client|custom dashboard/.test(t)) add("Lead", "Looks like a sales lead or prospect.");
  if (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/i.test(String(text || "")) || /named|contact is|person is|from [A-Z]/.test(String(text || ""))) add("Person", "A specific contact appears to be present.");
  if (/company record|business record|organization record|account record|\\bllc\\b|\\binc\\b|\\bco\\b|company|business|organization/.test(t) || /^[A-Z][A-Za-z0-9& .'-]{2,70}\\s+(is|wants|needs|called|asked|said|has|interested)\\b/.test(String(text || ""))) add("Company", "A business or organization appears to be present.");
  if (/\\$|deal|proposal|contract|purchase|opportunity|project value|budget|paid project|worth around|estimate/.test(t)) add("Deal", "Potential revenue, estimate, budget, or deal language appears.");
  let tasks = (t.match(/follow up|follow-up|call back|remind|reminder|next step|schedule|send .*example|ask .*tomorrow|ask .*friday|ask .*monday/g) || []).length;
  if (/second reminder|another reminder|two tasks|2 tasks|two follow ups|both reminders/.test(t)) tasks = Math.max(tasks, 2);
  for (let i = 0; i < Math.min(4, tasks); i++) add("Task", i ? "Additional task/reminder requested." : "A follow-up or reminder is requested.");
  if (/form submission|website form|google form|intake|submission/.test(t)) add("Intake", "The text describes an intake or form submission.");
  if (/note|remember|keep track/.test(t)) add("Note", "The text asks to remember or note information.");
  if (!records.length) add("Lead", "Default fallback when the text is CRM-related but unclear.");
  return records.slice(0, 10);
}
function normalizeCrmPlanRecords(records, text) {
  const input = Array.isArray(records) ? records : [];
  const normalized = [];
  for (const item of input) {
    const rawType = typeof item === "string" ? item : item && (item.record_type || item.type);
    const type = cleanCrmRecordType(rawType);
    if (!CRM_RECORD_TYPES.includes(type)) continue;
    const base = baseFormattedCrmRecord(type, text, compactCrmText(item && item.reason) || "LLM selected this record type.");
    const record = { ...base };
    for (const key of ["name", "company", "email", "phone", "status", "priority", "deal_name", "next_step", "notes", "source", "reason"]) {
      if (item && item[key] !== undefined && item[key] !== null) record[key] = compactCrmText(item[key]);
    }
    record.record_type = type;
    record.value = Number(item && item.value || base.value || 0) || 0;
    record.confidence = Math.max(0, Math.min(1, Number(item && item.confidence || 0.8) || 0.8));
    if (!record.name) record.name = base.name;
    if (type === "Company" && !record.company) record.company = record.name;
    if (type === "Deal" && !record.deal_name) record.deal_name = record.name;
    if (!["Person", "Lead", "Intake"].includes(type)) { record.email = ""; record.phone = ""; }
    normalized.push(record);
    if (normalized.length >= 10) break;
  }
  return normalized.length ? normalized : fallbackCrmPlan(text);
}
app.post("/api/crm/llm-plan", async (req, res) => {
  try {
    const text = String((req.body && req.body.text) || "").trim();
    if (!text) return res.status(400).json({ ok: false, error: "Missing CRM text." });
    const fallback_records = fallbackCrmPlan(text);
    if (!process.env.OPENAI_API_KEY) {
      return res.json({ ok: true, using_fallback: true, model: "rules", records: fallback_records, record_types: fallback_records.map((r) => r.record_type), prompt_version: "crm-record-planner-v2" });
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const systemPrompt = "You are the CRM record planning and formatting engine for Constrava. Read a messy CRM note and return the exact CRM records that should be created, already formatted for the dashboard. Allowed record types: Lead, Person, Company, Deal, Task, Intake, Note. Every record must be a separate object. You may create multiple records of the same type when the note asks for multiple reminders/tasks. Do not create a Person record unless a real named person, email address, or phone number is present. Do not create a Lead just because a company exists; create a Lead only when there is sales/prospect intent. Never invent people, companies, emails, phone numbers, budgets, or dates. Use empty string when unknown and value 0 when unknown. Field format for every record: record_type, name, company, email, phone, status, priority, value, deal_name, next_step, notes, source, reason, confidence. Formatting rules: Lead = sales/prospect record with contact info if present; Person = only a real contact; Company = business/account record, name and company should be the business name; Deal = possible revenue/project/opportunity, include deal_name and value if stated; Task = specific follow-up/reminder, put action in next_step; Intake = form/submission/request intake; Note = general information to remember. Return only JSON: {\"records\":[{\"record_type\":\"Lead|Person|Company|Deal|Task|Intake|Note\",\"name\":\"\",\"company\":\"\",\"email\":\"\",\"phone\":\"\",\"status\":\"New|Active|Open|Qualified|Review\",\"priority\":\"Low|Normal|High\",\"value\":0,\"deal_name\":\"\",\"next_step\":\"\",\"notes\":\"\",\"source\":\"AI Text Add\",\"reason\":\"short reason\",\"confidence\":0.0}],\"summary\":\"short summary\"}.";
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.OPENAI_API_KEY },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        temperature: 0,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: JSON.stringify({ crm_text: text, existing_rule_guess: fallback_records, instruction: "Return exact formatted CRM records. The user will not be asked follow-up questions." }) }
        ]
      })
    });
    clearTimeout(timer);
    const json = await response.json();
    if (!response.ok) {
      return res.json({ ok: true, using_fallback: true, model: process.env.OPENAI_MODEL || "gpt-4o-mini", records: fallback_records, record_types: fallback_records.map((r) => r.record_type), llm_error: json.error && json.error.message, prompt_version: "crm-record-planner-v2" });
    }
    let parsed = {};
    try { parsed = JSON.parse(json.choices?.[0]?.message?.content || "{}"); } catch { parsed = {}; }
    const records = normalizeCrmPlanRecords(parsed.records, text);
    return res.json({ ok: true, using_fallback: false, model: process.env.OPENAI_MODEL || "gpt-4o-mini", records, record_types: records.map((r) => r.record_type), summary: String(parsed.summary || ""), prompt_version: "crm-record-planner-v2" });
  } catch (error) {
    const text = String((req.body && req.body.text) || "");
    const records = fallbackCrmPlan(text);
    return res.json({ ok: true, using_fallback: true, model: "rules", records, record_types: records.map((r) => r.record_type), error: String(error && error.message || error), prompt_version: "crm-record-planner-v2" });
  }
});

`;

  const marker = "app.get(\"/\"";
  const idx = source.indexOf(marker);
  if (idx === -1) {
    console.warn("[crm-llm-record-planner-patch] Could not find route insertion point.");
    return;
  }
  source = source.slice(0, idx) + block + source.slice(idx);
  fs.writeFileSync(serverFile, source);
  console.log("CRM LLM formatted record planner server endpoint applied.");
}

function patchClient() {
  if (!fs.existsSync(clientFile)) {
    console.warn("[crm-llm-record-planner-patch] crm-distinct-tabs.js not found.");
    return;
  }
  let source = fs.readFileSync(clientFile, "utf8");
  if (source.includes("__crmClientLlmPlan_v2")) {
    console.log("CRM LLM formatted planner client patch already applied.");
    return;
  }

  const marker = "async function aiAdd(){";
  const idx = source.indexOf(marker);
  if (idx === -1) {
    console.warn("[crm-llm-record-planner-patch] Could not find aiAdd function in crm-distinct-tabs.js.");
    return;
  }

  const helper = `
// __crmClientLlmPlan_v2
async function llmPlan(text){
  const fallback=autoPlan(text);
  try{
    const response=await fetch('/api/crm/llm-plan?token='+encodeURIComponent(token),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,text})});
    const data=await response.json();
    const records=Array.isArray(data.records)?data.records.filter(r=>r&&r.record_type):[];
    const parts=records.length?records.map(r=>r.record_type):(Array.isArray(data.record_types)?data.record_types.filter(Boolean):[]);
    if(data&&data.ok&&parts.length){return{count:parts.length,typeParts:parts,records,suggestions:records,model:data.model||'unknown',usingFallback:!!data.using_fallback,promptVersion:data.prompt_version||'crm-record-planner-v2'}};
  }catch(e){}
  return fallback;
}
function applyLlmRecordFields(record,llmRecord,index){
  if(!llmRecord||typeof llmRecord!=='object')return record;
  const keepIds={lead_id:record.lead_id,record_id:record.record_id,related_record_ids:record.related_record_ids,raw_submission:record.raw_submission};
  const cleanValue=v=>String(v==null?'':v).trim();
  const merged=Object.assign({},record);
  ['record_type','name','company','email','phone','status','priority','deal_name','next_step','notes','source'].forEach(k=>{if(llmRecord[k]!=null&&cleanValue(llmRecord[k]))merged[k]=cleanValue(llmRecord[k]);});
  if(llmRecord.value!=null&&!Number.isNaN(Number(llmRecord.value)))merged.value=Number(llmRecord.value)||0;
  merged.reason=cleanValue(llmRecord.reason||merged.reason||'LLM formatted this CRM record.');
  merged.confidence=Number(llmRecord.confidence||merged.confidence||0.8)||0.8;
  merged.raw_submission=Object.assign({},keepIds.raw_submission||{}, {llm_formatted_record:llmRecord, requested_record_number:index+1});
  merged.lead_id=keepIds.lead_id;merged.record_id=keepIds.record_id;merged.related_record_ids=keepIds.related_record_ids;
  return normalize(merged,index);
}
`;
  source = source.slice(0, idx) + helper + source.slice(idx);
  source = source.replace("const plan=autoPlan(text),candidates=recordsFromPlan(text,plan),checked=rejectDupes", "const plan=await llmPlan(text),candidates=recordsFromPlan(text,plan).map((r,i)=>applyLlmRecordFields(r,(plan.records||[])[i],i)),checked=rejectDupes");
  source = source.replace("if(status)status.textContent='AI will save: '+checked.kept.map", "if(status)status.textContent='AI formatted '+(plan.typeParts||[]).join(', ')+' — saving '+checked.kept.length+' new record(s).';if(status&&checked.skipped.length)status.textContent+=' Skipping '+checked.skipped.length+' duplicate(s).';if(status)status.dataset.model=plan.model||'';if(status)status.dataset.promptVersion=plan.promptVersion||'';if(status)status.dataset.usingFallback=String(!!plan.usingFallback);/* old status disabled */if(false)status.textContent='AI will save: '+checked.kept.map");
  fs.writeFileSync(clientFile, source);
  console.log("CRM LLM formatted record planner client hook applied.");
}

patchServer();
patchClient();
