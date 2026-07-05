import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-add-llm-record-planner-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function insertBefore(anchor, block, label) {
  if (source.includes(block.split("\n")[0])) return;
  const index = source.indexOf(anchor);
  if (index < 0) {
    console.warn(`[crm-ai-add-llm-record-planner-patch] Could not find ${label}.`);
    return;
  }
  source = source.slice(0, index) + block + "\n" + source.slice(index);
  changed = true;
}

const helperBlock = [
  "// __crmAiAddLlmRecordPlanner_v1",
  "function crmCleanPrimaryRecordType(value) {",
  "  const raw = String(value || \"\").trim().toLowerCase().replace(/[^a-z0-9]+/g, \"_\").replace(/^_+|_+$/g, \"\");",
  "  if (!raw || raw === \"record\" || raw === \"crm_record\" || raw === \"item\" || raw === \"entry\") return \"lead\";",
  "  const aliases = { leads: \"lead\", person: \"contact\", people: \"contact\", contacts: \"contact\", companies: \"account\", company: \"account\", accounts: \"account\", deals: \"deal\", opportunities: \"deal\", opportunity: \"deal\", tasks: \"task\", activities: \"activity\", notes: \"note\", ai_entry: \"ai_text_lead\", ai_crm_entry: \"ai_text_lead\", form_lead: \"external_form_lead\", intake: \"external_form_lead\" };",
  "  return aliases[raw] || raw;",
  "}",
  "function crmModuleForType(type) {",
  "  const t = crmCleanPrimaryRecordType(type);",
  "  if ([\"deal\", \"opportunity\"].includes(t)) return \"deals\";",
  "  if ([\"contact\", \"person\"].includes(t)) return \"contacts\";",
  "  if ([\"account\", \"company\"].includes(t)) return \"accounts\";",
  "  if ([\"task\", \"activity\", \"call_log\", \"email_activity\", \"note\"].includes(t)) return \"activities\";",
  "  if ([\"document\", \"report\"].includes(t)) return t + \"s\";",
  "  return \"leads\";",
  "}",
  "function crmPrimaryRecordType(entry) {",
  "  const explicit = crmCleanPrimaryRecordType(entry?.record_type || entry?.type || entry?.kind || entry?.object_type);",
  "  if (explicit && explicit !== \"lead\") return explicit;",
  "  const text = [entry?.module, entry?.source, entry?.provider, entry?.deal_name, entry?.next_step, entry?.notes, entry?.message, entry?.title, entry?.company].join(\" \" ).toLowerCase();",
  "  if (/task|todo|follow up|call back|due date|meeting/.test(text)) return \"task\";",
  "  if (/call|voicemail|phone conversation/.test(text)) return \"call_log\";",
  "  if (/email|inbox|reply|thread/.test(text)) return \"email_activity\";",
  "  if (/note|memo/.test(text)) return \"note\";",
  "  if (/account|company|business|organization/.test(text) && entry?.company && !entry?.email && !entry?.phone) return \"account\";",
  "  if (Number(entry?.value || entry?.deal_value || entry?.budget || 0) > 0 || /deal|proposal|quote|estimate|opportunity|negotiation|closed won|closed lost/.test(text)) return \"deal\";",
  "  if (/google forms|typeform|tally|jotform|external form|form submission|intake/.test(text)) return \"external_form_lead\";",
  "  if (/website form|contact page|site form/.test(text)) return \"website_form_lead\";",
  "  if (entry?.email || entry?.phone || entry?.mobile) return \"contact\";",
  "  return \"lead\";",
  "}",
  "function crmAiIdentityKey(entry) {",
  "  const e = entry || {};",
  "  const leadId = String(e.lead_id || e.record_id || e.id || \"\").trim().toLowerCase();",
  "  if (leadId) return \"id:\" + leadId;",
  "  const email = String(e.email || e.lead_email || e.contact_email || \"\").trim().toLowerCase();",
  "  if (email) return \"email:\" + email;",
  "  const phone = String(e.phone || e.mobile || e.phone_number || \"\").replace(/\\D/g, \"\");",
  "  if (phone) return \"phone:\" + phone;",
  "  const nameCompany = String((e.name || e.full_name || \"\") + \"::\" + (e.company || e.organization || \"\")).trim().toLowerCase();",
  "  if (nameCompany && nameCompany !== \"::\") return \"name-company:\" + nameCompany;",
  "  return \"random:\" + Math.random();",
  "}",
  "function replaceMemoryCrmLead(lead) {",
  "  const key = crmAiIdentityKey(lead);",
  "  for (let i = memoryLeads.length - 1; i >= 0; i--) {",
  "    if (crmAiIdentityKey(memoryLeads[i]) === key) memoryLeads.splice(i, 1);",
  "  }",
  "  memoryLeads.unshift(lead);",
  "  while (memoryLeads.length > 250) memoryLeads.pop();",
  "}",
  "async function updateCrmLead(siteId, lead) {",
  "  replaceMemoryCrmLead(lead);",
  "  if (!hasDb()) return true;",
  "  try {",
  "    const info = await tableInfo(\"crm_leads\");",
  "    const c = cols(info);",
  "    if (!c.length) return false;",
  "    const idCol = firstExisting(c, [\"lead_id\", \"record_id\", \"crm_id\"]);",
  "    const siteCol = firstExisting(c, [\"site_id\", \"site\", \"client_site_id\", \"project_id\"]);",
  "    const leadId = String(lead.lead_id || lead.record_id || lead.id || \"\").trim();",
  "    if (!idCol || !leadId) return false;",
  "    const updates = [];",
  "    const values = [];",
  "    const add = (col, value) => { if (col && c.includes(col) && !updates.includes(col)) { updates.push(col); values.push(value); } };",
  "    add(firstExisting(c, [\"name\", \"full_name\", \"lead_name\", \"contact_name\"]), lead.name);",
  "    add(firstExisting(c, [\"email\", \"lead_email\", \"contact_email\"]), lead.email);",
  "    add(firstExisting(c, [\"phone\", \"phone_number\", \"mobile\"]), lead.phone || lead.mobile);",
  "    add(firstExisting(c, [\"company\", \"organization\"]), lead.company);",
  "    add(firstExisting(c, [\"status\", \"stage\", \"lead_status\"]), lead.status);",
  "    add(firstExisting(c, [\"source\", \"channel\", \"campaign\"]), lead.source);",
  "    add(firstExisting(c, [\"notes\", \"message\", \"body\"]), lead.notes);",
  "    add(firstExisting(c, [\"value\", \"deal_value\", \"amount\", \"budget\"]), Number(lead.value || 0));",
  "    const timeCol = firstExisting(c, [\"updated_at\", \"last_contacted\", \"timestamp\", \"received_at\"]);",
  "    if (timeCol) add(timeCol, new Date());",
  "    const payloadCol = firstExisting(c, [\"payload\", \"metadata\", \"data\", \"properties\", \"raw_submission\"]);",
  "    if (payloadCol) add(payloadCol, isJsonColumn(info, payloadCol) ? lead : JSON.stringify(lead));",
  "    if (!updates.length) return false;",
  "    let where = `${q(idCol)}=$${values.length + 1}`;",
  "    values.push(leadId);",
  "    if (siteCol) { where += ` AND ${q(siteCol)}=$${values.length + 1}`; values.push(String(siteId)); }",
  "    const sql = `UPDATE crm_leads SET ${updates.map((col, i) => `${q(col)}=$${i + 1}`).join(\", \")} WHERE ${where}`;",
  "    const result = await db().query(sql, values);",
  "    return result.rowCount > 0;",
  "  } catch { return false; }",
  "}",
].join("\n");

insertBefore("async function llmPlanCrmEntry(text, currentEntries) {", helperBlock, "AI entry planner function");

const llmStart = source.indexOf("async function llmPlanCrmEntry(text, currentEntries) {");
const fallbackStart = source.indexOf("function fallbackPlanCrmEntry(text) {", llmStart);
if (llmStart >= 0 && fallbackStart > llmStart) {
  const llmBlock = `async function llmPlanCrmEntry(text, currentEntries) {
  if (!process.env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY is required for AI Add.");
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.OPENAI_API_KEY },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      temperature: 0,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: "You are the CRM AI Add record planner for Constrava. Convert the user's plain English update into the exact CRM actions needed. Step 1: decide how many distinct CRM records are described. Step 2: for each one, decide whether to create a new record or update an existing record by comparing against current_entries. Use update when the text clearly refers to an existing person, company, deal, task, phone, email, lead_id, or company already in current_entries. Return JSON only with schema {actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company,deal_name}, entry:{record_type,module,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,owner,close_date}, reason:string}]}. Every entry must be a complete CRM record after the action. Use exactly one primary record_type, not a types array. Choose the best primary record_type from: lead, contact, account, deal, task, note, activity, external_form_lead, website_form_lead, ai_text_lead. Infer CRM fields like status, priority, probability, expected_revenue, next_step, source, and notes from the text. Do not invent contact details. Use empty strings for unknown contact fields and 0 for unknown money values." },
        { role: "user", content: JSON.stringify({ plain_text: text, current_entries: (currentEntries || []).slice(0, 80).map((e) => ({ lead_id: e.lead_id || e.record_id || e.id, record_type: e.record_type || e.type, module: e.module, name: e.name, email: e.email, phone: e.phone || e.mobile, company: e.company, status: e.status || e.stage, deal_name: e.deal_name, value: e.value, probability: e.probability, next_step: e.next_step, notes: String(e.notes || "").slice(0, 500) })) }) }
      ]
    })
  });
  const json = await response.json();
  if (!response.ok) throw new Error(json.error?.message || json.error || "OpenAI could not process this CRM update.");
  const parsed = JSON.parse(json.choices?.[0]?.message?.content || "null");
  if (!parsed || !Array.isArray(parsed.actions) || !parsed.actions.length) throw new Error("The LLM did not return any CRM actions.");
  parsed.actions = parsed.actions.map((action) => {
    const entry = action.entry && typeof action.entry === "object" ? action.entry : {};
    const recordType = crmPrimaryRecordType(entry);
    delete entry.types;
    return {
      action: String(action.action || "create").toLowerCase() === "update" ? "update" : "create",
      match: action.match && typeof action.match === "object" ? action.match : {},
      entry: { ...entry, type: recordType, record_type: recordType, module: entry.module || crmModuleForType(recordType) },
      reason: String(action.reason || "LLM interpreted CRM action.")
    };
  });
  return parsed;
}
`;
  const current = source.slice(llmStart, fallbackStart);
  if (current !== llmBlock) {
    source = source.slice(0, llmStart) + llmBlock + source.slice(fallbackStart);
    changed = true;
  }
}

const oldPlan = "const plan = await llmPlanCrmEntry(text, current) || fallbackPlanCrmEntry(text);";
const newPlan = "const plan = await llmPlanCrmEntry(text, current);\n    if (!plan || !Array.isArray(plan.actions) || plan.actions.length === 0) return res.status(502).json({ ok: false, error: \"The LLM did not return any CRM actions.\" });";
if (source.includes(oldPlan)) {
  source = source.replace(oldPlan, newPlan);
  changed = true;
}

const oldStore = `      finalEntry.dashboard_token = token;
      finalEntry.site_id = siteId;
      finalEntry.site_slug = siteId;
      await insertCrmLead(siteId, finalEntry);
      results.push({ action: kind, matched_lead_id: matched?.lead_id || null, lead_id: finalEntry.lead_id, reason: action.reason || "AI interpreted CRM entry.", entry: finalEntry });`;
const newStore = `      finalEntry.record_type = crmPrimaryRecordType(finalEntry);
      finalEntry.type = finalEntry.record_type;
      finalEntry.module = finalEntry.module || crmModuleForType(finalEntry.record_type);
      delete finalEntry.types;
      finalEntry.dashboard_token = token;
      finalEntry.site_id = siteId;
      finalEntry.site_slug = siteId;
      let stored = false;
      if (kind === "update") stored = await updateCrmLead(siteId, finalEntry);
      if (!stored) stored = await insertCrmLead(siteId, finalEntry);
      results.push({ action: kind, matched_lead_id: matched?.lead_id || null, lead_id: finalEntry.lead_id, stored, reason: action.reason || "AI interpreted CRM entry.", entry: finalEntry });`;
if (source.includes(oldStore)) {
  source = source.replace(oldStore, newStore);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("AI Add now requires the LLM to plan create/update actions and returns complete primary-type CRM records.");
} else {
  console.log("AI Add LLM record planner patch already applied or anchors not found.");
}
