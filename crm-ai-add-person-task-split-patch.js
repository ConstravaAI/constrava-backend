import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-add-person-task-split-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const helperMarker = "// __crmAiPersonTaskSplitPatch_v1";
const helper = `${helperMarker}
function crmExtractPersonNameFromTaskText(text) {
  const clean = String(text || "").replace(/\s+/g, " ").trim();
  const patterns = [
    /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\s+(?:wants|wanted|asked|needs|need|requested|told|said)\b/,
    /\b(?:call|text|email|meet|follow up with|reach out to)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b/,
    /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b/
  ];
  for (const pattern of patterns) {
    const match = clean.match(pattern);
    if (match && match[1]) return match[1].trim();
  }
  return "";
}
function crmTextHasFollowupAction(text) {
  return /\b(call|text|email|meet|meeting|follow\s*up|reach\s*out|appointment|schedule|remind|todo|to do)\b/i.test(String(text || ""));
}
function crmExtractTaskTimeFromText(text) {
  const match = String(text || "").match(/\b(?:at\s*)?(\d{1,2}(?::\d{2})?\s*(?:am|pm))\b/i);
  return match ? match[1].replace(/\s+/g, "").toUpperCase() : "";
}
function crmPersonTaskSplitNeeded(text, actions) {
  if (!crmTextHasFollowupAction(text)) return false;
  const name = crmExtractPersonNameFromTaskText(text);
  if (!name) return false;
  const list = Array.isArray(actions) ? actions : [];
  if (list.length !== 1) return false;
  const entry = list[0]?.entry || {};
  const recordType = crmCleanPrimaryRecordType(entry.record_type || entry.type || "");
  const company = String(entry.company || entry.name || "");
  const looksPersonal = company === name || !/\b(llc|inc|corp|company|co\.|group|studio|agency|services|construction|manufacturing|shop|restaurant|clinic|school|labs)\b/i.test(company);
  return ["account", "company", "lead"].includes(recordType) && looksPersonal;
}
function crmPostprocessPersonTaskPlan(text, actions) {
  if (!crmPersonTaskSplitNeeded(text, actions)) return actions;
  const name = crmExtractPersonNameFromTaskText(text);
  const time = crmExtractTaskTimeFromText(text);
  const original = actions[0] || {};
  const entry = original.entry || {};
  const contact = {
    action: original.action === "update" ? "update" : "create",
    match: { name, email: entry.email || "", phone: entry.phone || entry.mobile || "" },
    entry: {
      record_type: "contact",
      type: "contact",
      module: "contacts",
      name,
      email: entry.email || "",
      phone: entry.phone || entry.mobile || "",
      mobile: entry.mobile || entry.phone || "",
      company: entry.company && entry.company !== name ? entry.company : "",
      title: entry.title || "",
      industry: entry.industry || "",
      source: entry.source || "AI CRM Entry",
      status: entry.status || "New",
      priority: entry.priority || "Medium",
      deal_name: "",
      value: 0,
      probability: 0,
      expected_revenue: 0,
      next_step: time ? "Call " + name + " at " + time + "." : "Follow up with " + name + ".",
      notes: "Created from plain-text AI Add: " + String(text || ""),
      tags: ["ai-add", "contact"],
      owner: entry.owner || "Constrava Demo Team",
      close_date: ""
    },
    reason: "The text names a person, so the person is stored as a contact record instead of a company."
  };
  const task = {
    action: "create",
    match: { name: "Call " + name, company: contact.entry.company || "" },
    entry: {
      record_type: "task",
      type: "task",
      module: "activities",
      name: time ? "Call " + name + " at " + time : "Call " + name,
      email: contact.entry.email,
      phone: contact.entry.phone,
      mobile: contact.entry.mobile,
      company: contact.entry.company,
      title: "Follow-up task",
      industry: "",
      source: "AI CRM Entry",
      status: "New",
      priority: "Medium",
      deal_name: "",
      value: 0,
      probability: 0,
      expected_revenue: 0,
      next_step: time ? "Call " + name + " at " + time + "." : "Call " + name + ".",
      notes: "Task created from plain-text AI Add: " + String(text || ""),
      tags: ["ai-add", "task", "call"],
      owner: entry.owner || "Constrava Demo Team",
      close_date: ""
    },
    reason: "The text includes a requested follow-up action, so a separate task record is created."
  };
  return [contact, task];
}
`;

if (!source.includes(helperMarker)) {
  const anchor = "async function llmPlanCrmEntry(text, currentEntries) {";
  const index = source.indexOf(anchor);
  if (index >= 0) {
    source = source.slice(0, index) + helper + "\n" + source.slice(index);
    changed = true;
  } else {
    console.warn("[crm-ai-add-person-task-split-patch] Could not find LLM planner anchor.");
  }
}

const oldReturn = "  return parsed;\n}\nfunction fallbackPlanCrmEntry(text)";
const newReturn = "  parsed.actions = crmPostprocessPersonTaskPlan(text, parsed.actions);\n  return parsed;\n}\nfunction fallbackPlanCrmEntry(text)";
if (source.includes(oldReturn)) {
  source = source.replace(oldReturn, newReturn);
  changed = true;
}

const oldPrompt = "Do not invent contact details. Use empty strings for unknown contact fields and 0 for unknown money values.";
const newPrompt = "Do not invent contact details. Use empty strings for unknown contact fields and 0 for unknown money values. Critical rule: when text names a person and describes a follow-up action such as call, text, email, meet, appointment, or follow up, return TWO actions unless one already exists: one contact/person record for the named person and one task/activity record for the requested action. Never turn a personal name into an account/company unless the text clearly says it is a company, business, organization, LLC, Inc, agency, studio, shop, school, clinic, or similar.";
if (source.includes(oldPrompt) && !source.includes("Critical rule: when text names a person")) {
  source = source.replace(oldPrompt, newPrompt);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("AI Add now splits person follow-up text into contact + task records.");
} else {
  console.log("AI Add person/task split patch already applied or anchors not found.");
}
