import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-add-person-task-split-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const helperMarker = "// __crmAiPersonTaskSplitPatch_v2";
const oldHelperMarker = "// __crmAiPersonTaskSplitPatch_v1";
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
function crmEntryPrimaryType(action) {
  const entry = action?.entry || action || {};
  return crmCleanPrimaryRecordType(entry.record_type || entry.type || entry.module || "");
}
function crmActionLooksLikePerson(action, personName) {
  const entry = action?.entry || {};
  const type = crmEntryPrimaryType(action);
  const text = [entry.name, entry.email, entry.phone, entry.mobile, entry.notes, entry.next_step].join(" ").toLowerCase();
  return ["contact", "person"].includes(type) || (personName && text.includes(String(personName).toLowerCase()) && (entry.email || entry.phone || entry.mobile));
}
function crmActionLooksLikeTask(action) {
  const entry = action?.entry || {};
  const type = crmEntryPrimaryType(action);
  const text = [entry.name, entry.title, entry.record_type, entry.module, entry.next_step, entry.notes].join(" ");
  return ["task", "activity", "call_log", "email_activity", "note"].includes(type) || crmTextHasFollowupAction(text);
}
function crmBuildPersonContactAction(text, existingAction) {
  const name = crmExtractPersonNameFromTaskText(text);
  const time = crmExtractTaskTimeFromText(text);
  const entry = existingAction?.entry || {};
  return {
    action: existingAction?.action === "update" ? "update" : "create",
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
      title: entry.title && !/follow-up|task/i.test(String(entry.title)) ? entry.title : "",
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
    reason: "The text names a person, so AI Add stores the person as a separate contact record."
  };
}
function crmBuildFollowupTaskAction(text, existingAction) {
  const name = crmExtractPersonNameFromTaskText(text);
  const time = crmExtractTaskTimeFromText(text);
  const entry = existingAction?.entry || {};
  return {
    action: existingAction?.action === "update" ? "update" : "create",
    match: existingAction?.match || { name: "Call " + name, company: entry.company || "" },
    entry: {
      ...entry,
      record_type: "task",
      type: "task",
      module: "activities",
      name: entry.name && crmTextHasFollowupAction(entry.name) ? entry.name : (time ? "Call " + name + " at " + time : "Call " + name),
      email: entry.email || "",
      phone: entry.phone || entry.mobile || "",
      mobile: entry.mobile || entry.phone || "",
      company: entry.company && entry.company !== name ? entry.company : "",
      title: entry.title || "Follow-up task",
      industry: entry.industry || "",
      source: entry.source || "AI CRM Entry",
      status: entry.status || "New",
      priority: entry.priority || "Medium",
      deal_name: entry.deal_name || "",
      value: Number(entry.value || 0) || 0,
      probability: Number(entry.probability || 0) || 0,
      expected_revenue: Number(entry.expected_revenue || 0) || 0,
      next_step: entry.next_step || (time ? "Call " + name + " at " + time + "." : "Call " + name + "."),
      notes: entry.notes || "Task created from plain-text AI Add: " + String(text || ""),
      tags: Array.isArray(entry.tags) && entry.tags.length ? entry.tags : ["ai-add", "task", "call"],
      owner: entry.owner || "Constrava Demo Team",
      close_date: entry.close_date || ""
    },
    reason: existingAction?.reason || "The text includes a requested follow-up action, so a task record is created."
  };
}
function crmPostprocessPersonTaskPlan(text, actions) {
  const list = Array.isArray(actions) ? actions : [];
  if (!crmTextHasFollowupAction(text)) return list;
  const name = crmExtractPersonNameFromTaskText(text);
  if (!name) return list;

  const hasPerson = list.some((action) => crmActionLooksLikePerson(action, name));
  const hasTask = list.some((action) => crmActionLooksLikeTask(action));
  if (hasPerson && hasTask) return list;

  const first = list[0] || { action: "create", match: {}, entry: {} };
  const firstType = crmEntryPrimaryType(first);
  const firstEntry = first.entry || {};
  const company = String(firstEntry.company || firstEntry.name || "");
  const looksPersonal = company === name || !/\b(llc|inc|corp|company|co\.|group|studio|agency|services|construction|manufacturing|shop|restaurant|clinic|school|labs)\b/i.test(company);

  if (!hasPerson && !hasTask) {
    if (["account", "company", "lead"].includes(firstType) && looksPersonal) return [crmBuildPersonContactAction(text, first), crmBuildFollowupTaskAction(text, null)];
    return [crmBuildPersonContactAction(text, null), crmBuildFollowupTaskAction(text, first)];
  }
  if (hasTask && !hasPerson) return [crmBuildPersonContactAction(text, first), ...list];
  if (hasPerson && !hasTask) return [...list, crmBuildFollowupTaskAction(text, null)];
  return list;
}
`;

function replaceOldHelper() {
  const start = source.indexOf(oldHelperMarker);
  if (start < 0) return false;
  const end = source.indexOf("async function llmPlanCrmEntry(text, currentEntries) {", start);
  if (end < 0) return false;
  source = source.slice(0, start) + helper + "\n" + source.slice(end);
  return true;
}

if (!source.includes(helperMarker)) {
  if (replaceOldHelper()) {
    changed = true;
  } else {
    const anchor = "async function llmPlanCrmEntry(text, currentEntries) {";
    const index = source.indexOf(anchor);
    if (index >= 0) {
      source = source.slice(0, index) + helper + "\n" + source.slice(index);
      changed = true;
    } else {
      console.warn("[crm-ai-add-person-task-split-patch] Could not find LLM planner anchor.");
    }
  }
}

const oldReturn = "  return parsed;\n}\nfunction fallbackPlanCrmEntry(text)";
const newReturn = "  parsed.actions = crmPostprocessPersonTaskPlan(text, parsed.actions);\n  return parsed;\n}\nfunction fallbackPlanCrmEntry(text)";
if (source.includes(oldReturn)) {
  source = source.replace(oldReturn, newReturn);
  changed = true;
}

const oldPrompt = "Critical rule: when text names a person and describes a follow-up action such as call, text, email, meet, appointment, or follow up, return TWO actions unless one already exists: one contact/person record for the named person and one task/activity record for the requested action. Never turn a personal name into an account/company unless the text clearly says it is a company, business, organization, LLC, Inc, agency, studio, shop, school, clinic, or similar.";
const newPrompt = "Critical rule: when text names a person and describes a follow-up action such as call, text, email, meet, appointment, or follow up, return TWO actions unless both already exist: one contact/person record for the named person and one task/activity record for the requested action. If you create or update only the task, also create or update the contact. If you create or update only the contact, also create the task. Never turn a personal name into an account/company unless the text clearly says it is a company, business, organization, LLC, Inc, agency, studio, shop, school, clinic, or similar.";
if (source.includes(oldPrompt)) {
  source = source.replace(oldPrompt, newPrompt);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("AI Add now preserves multi-record create/update plans and adds missing contact/task records when needed.");
} else {
  console.log("AI Add person/task split patch already applied or anchors not found.");
}
