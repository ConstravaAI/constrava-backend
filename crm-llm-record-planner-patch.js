import fs from "fs";

const serverFile = "server.js";
const clientFile = "crm-distinct-tabs.js";

function patchServer() {
  if (!fs.existsSync(serverFile)) {
    console.warn("[crm-llm-record-planner-patch] server.js not found.");
    return;
  }
  let source = fs.readFileSync(serverFile, "utf8");
  if (source.includes("__crmLlmRecordPlanner_v1")) {
    console.log("CRM LLM record planner server patch already applied.");
    return;
  }

  const block = `
// __crmLlmRecordPlanner_v1
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
function fallbackCrmPlan(text) {
  const t = String(text || "").toLowerCase();
  const records = [];
  const add = (type, reason = "Rule-based fallback") => records.push({ record_type: type, reason });
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
    normalized.push({
      record_type: type,
      reason: String((item && item.reason) || "LLM selected this record type."),
      confidence: Math.max(0, Math.min(1, Number((item && item.confidence) || 0.8) || 0.8))
    });
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
      return res.json({ ok: true, using_fallback: true, model: "rules", records: fallback_records, record_types: fallback_records.map((r) => r.record_type), prompt_version: "crm-record-planner-v1" });
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const systemPrompt = "You are the CRM record planning engine for Constrava. Read a messy CRM note and decide exactly which CRM records should be created. Allowed record types: Lead, Person, Company, Deal, Task, Intake, Note. Treat each record as separate. You may create zero, one, or multiple records of the same type when the note asks for multiple reminders/tasks. Do not create a Person record unless a real named person, email address, or phone number is present. Do not create a Lead just because a company exists; create a Lead only when there is sales/prospect intent. Do not invent people, companies, emails, phone numbers, budgets, or dates. Return only JSON with this shape: {\"records\":[{\"record_type\":\"Lead|Person|Company|Deal|Task|Intake|Note\",\"reason\":\"short reason\",\"confidence\":0.0}],\"summary\":\"short summary\"}.";
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
          { role: "user", content: JSON.stringify({ crm_text: text, existing_rule_guess: fallback_records, instruction: "Return the exact CRM records to create. The user will not be asked follow-up questions." }) }
        ]
      })
    });
    clearTimeout(timer);
    const json = await response.json();
    if (!response.ok) {
      return res.json({ ok: true, using_fallback: true, model: process.env.OPENAI_MODEL || "gpt-4o-mini", records: fallback_records, record_types: fallback_records.map((r) => r.record_type), llm_error: json.error && json.error.message, prompt_version: "crm-record-planner-v1" });
    }
    let parsed = {};
    try { parsed = JSON.parse(json.choices?.[0]?.message?.content || "{}"); } catch { parsed = {}; }
    const records = normalizeCrmPlanRecords(parsed.records, text);
    return res.json({ ok: true, using_fallback: false, model: process.env.OPENAI_MODEL || "gpt-4o-mini", records, record_types: records.map((r) => r.record_type), summary: String(parsed.summary || ""), prompt_version: "crm-record-planner-v1" });
  } catch (error) {
    const text = String((req.body && req.body.text) || "");
    const records = fallbackCrmPlan(text);
    return res.json({ ok: true, using_fallback: true, model: "rules", records, record_types: records.map((r) => r.record_type), error: String(error && error.message || error), prompt_version: "crm-record-planner-v1" });
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
  console.log("CRM LLM record planner server endpoint applied.");
}

function patchClient() {
  if (!fs.existsSync(clientFile)) {
    console.warn("[crm-llm-record-planner-patch] crm-distinct-tabs.js not found.");
    return;
  }
  let source = fs.readFileSync(clientFile, "utf8");
  if (source.includes("__crmClientLlmPlan_v1")) {
    console.log("CRM LLM planner client patch already applied.");
    return;
  }

  const marker = "async function aiAdd(){";
  const idx = source.indexOf(marker);
  if (idx === -1) {
    console.warn("[crm-llm-record-planner-patch] Could not find aiAdd function in crm-distinct-tabs.js.");
    return;
  }

  const helper = `
// __crmClientLlmPlan_v1
async function llmPlan(text){
  const fallback=autoPlan(text);
  try{
    const response=await fetch('/api/crm/llm-plan?token='+encodeURIComponent(token),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,text})});
    const data=await response.json();
    const parts=Array.isArray(data.record_types)?data.record_types.filter(Boolean):[];
    if(data&&data.ok&&parts.length){return{count:parts.length,typeParts:parts,suggestions:data.records||[],model:data.model||'unknown',usingFallback:!!data.using_fallback,promptVersion:data.prompt_version||'crm-record-planner-v1'}};
  }catch(e){}
  return fallback;
}
`;
  source = source.slice(0, idx) + helper + source.slice(idx);
  source = source.replace("const plan=autoPlan(text),candidates=recordsFromPlan(text,plan),checked=rejectDupes", "const plan=await llmPlan(text),candidates=recordsFromPlan(text,plan),checked=rejectDupes");
  source = source.replace("if(status)status.textContent='AI will save: '+checked.kept.map", "if(status)status.textContent='AI model plan: '+(plan.typeParts||[]).join(', ')+' — saving '+checked.kept.length+' new record(s).';if(status&&checked.skipped.length)status.textContent+=' Skipping '+checked.skipped.length+' duplicate(s).';if(status)status.dataset.model=plan.model||'';if(status)status.dataset.promptVersion=plan.promptVersion||'';if(status)status.dataset.usingFallback=String(!!plan.usingFallback);/* old status disabled */if(false)status.textContent='AI will save: '+checked.kept.map");
  fs.writeFileSync(clientFile, source);
  console.log("CRM LLM record planner client hook applied.");
}

patchServer();
patchClient();
