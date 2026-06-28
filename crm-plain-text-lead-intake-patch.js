import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-plain-text-lead-intake-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldPrompt = `You are the AI operator for a CRM with one unified entries list. Read the user's plain text update. Decide whether to create one or more entries, update one or more existing entries, or both. Output JSON only: {actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company}, entry:{complete CRM fields}, reason:string}]}. Complete CRM fields include name,email,phone,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type. Use the existing entries to update the right record. Do not invent contact details not present or implied.`;
const newPrompt = `You are the AI operator for a CRM with one unified entries list. Read the user's plain text update like a real sales/admin note, not a structured form. People often omit words like lead, deal, status, email, or next step. If a note says someone called, emailed, asked, wants, needs, requested, submitted, reached out, or left contact information, infer a potential lead unless the note clearly says otherwise. Output JSON only: {actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company}, entry:{complete CRM fields}, reason:string}]}. Complete CRM fields include name,email,phone,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type. For inferred potential leads use module:'leads', record_type:'lead', status:'New', source:'AI Plain Text Note', priority:'Medium', probability:10, next_step:'Follow up with this potential lead.', and a useful deal_name based on company/name. Extract name/company/phone/email when present. Use existing entries to update the right record. Do not invent contact details not present or implied.`;
if (source.includes(oldPrompt)) {
  source = source.replace(oldPrompt, newPrompt);
  changed = true;
}

const oldFallback = `function fallbackPlanCrmEntry(text) {
  return { actions: [{ action: "create", match: {}, entry: { name: "CRM Entry", source: "AI CRM Entry", notes: text, message: text, record_type: "crm_entry", module: "leads" }, reason: "Fallback plain-text entry created without LLM." }] };
}`;

const newFallback = `function fallbackPlanCrmEntry(text) {
  const raw = String(text || "").trim();
  const clean = raw.replace(/\\s+/g, " ").trim();
  const phoneMatch = clean.match(/(?:\\+?1[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}/);
  const emailMatch = clean.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/i);
  const phone = phoneMatch ? phoneMatch[0] : "";
  const email = emailMatch ? emailMatch[0] : "";

  let name = "Potential Lead";
  let company = "Individual / Unknown Company";

  const fromMatch = clean.match(/^(.+?)\\s+from\\s+(.+?)(?:\\s+(?:called|emailed|texted|reached out|asked|wants|needs|requested|submitted)\\b|[().,;]|$)/i);
  if (fromMatch) {
    name = fromMatch[1].replace(/^(create|add|new|lead|contact)\\s+/i, "").trim() || name;
    company = fromMatch[2].trim() || company;
  } else {
    const calledMatch = clean.match(/^(.+?)\\s+(?:called|emailed|texted|reached out|asked|wants|needs|requested|submitted)\\b/i);
    if (calledMatch) name = calledMatch[1].trim() || name;
  }

  name = name.replace(/[()]/g, "").trim() || "Potential Lead";
  company = company.replace(/[()]/g, "").trim() || "Individual / Unknown Company";

  const hasLeadSignal = /called|emailed|texted|reached out|asked|wants|needs|requested|submitted|quote|proposal|website|project|interested|contact/i.test(clean) || !!phone || !!email;
  const dealName = company && company !== "Individual / Unknown Company" ? company + " opportunity" : name + " opportunity";

  return { actions: [{
    action: "create",
    match: { email, phone, name, company },
    entry: {
      name,
      email,
      phone,
      mobile: phone,
      company,
      source: "AI Plain Text Note",
      status: "New",
      priority: hasLeadSignal ? "Medium" : "Low",
      record_type: "lead",
      module: "leads",
      deal_name: dealName,
      value: 0,
      probability: 10,
      expected_revenue: 0,
      next_step: "Follow up with this potential lead.",
      notes: raw,
      message: raw,
      tags: ["plain-text", "ai-inferred", "potential-lead"]
    },
    reason: "Inferred a potential lead from a plain-text CRM note."
  }] };
}`;

if (source.includes(oldFallback)) {
  source = source.replace(oldFallback, newFallback);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Plain-text CRM lead inference patch applied.");
} else {
  console.log("Plain-text CRM lead inference patch already applied or anchor not found.");
}
