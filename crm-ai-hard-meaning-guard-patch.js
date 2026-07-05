import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-hard-meaning-guard-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const marker = "// __crmAiHardMeaningGuard_v1";
const helper = `${marker}
function crmHardTextHasFollowupAction(text) {
  return /\b(call|text|email|meet|meeting|follow\s*up|reach\s*out|appointment|schedule|remind|todo|to do)\b/i.test(String(text || ""));
}
function crmHardExtractPersonName(text) {
  const clean = String(text || "").replace(/\s+/g, " ").trim();
  const patterns = [
    /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\s+(?:wants|wanted|asked|asks|needs|need|requested|requests|told|said)\b/,
    /\b(?:call|text|email|meet|follow up with|reach out to)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b/,
    /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b/
  ];
  for (const pattern of patterns) {
    const match = clean.match(pattern);
    if (match && match[1]) return match[1].trim();
  }
  return "";
}
function crmHardExtractTime(text) {
  const match = String(text || "").match(/\b(?:at\s*)?(\d{1,2}(?::\d{2})?\s*(?:am|pm))\b/i);
  return match ? match[1].replace(/\s+/g, "").toUpperCase() : "";
}
function crmHardCleanType(action) {
  const entry = action?.entry || action || {};
  return String(entry.record_type || entry.type || entry.module || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}
function crmHardIsBusinessLikeName(value) {
  return /\b(llc|inc|corp|corporation|company|co\.|group|studio|agency|services|construction|manufacturing|shop|restaurant|clinic|school|labs|roofing|plumbing|electric|hvac)\b/i.test(String(value || ""));
}
function crmHardActionMentionsName(action, name) {
  const entry = action?.entry || {};
  const hay = [entry.name, entry.company, entry.deal_name, entry.next_step, entry.notes, entry.title].join(" ").toLowerCase();
  return hay.includes(String(name || "").toLowerCase());
}
function crmHardActionIsPerson(action, name) {
  const entry = action?.entry || {};
  const type = crmHardCleanType(action);
  if (["contact", "person", "contacts"].includes(type)) return true;
  if ((entry.email || entry.phone || entry.mobile) && crmHardActionMentionsName(action, name)) return true;
  return false;
}
function crmHardActionIsTask(action) {
  const entry = action?.entry || {};
  const type = crmHardCleanType(action);
  const text = [entry.name, entry.title, entry.record_type, entry.module, entry.next_step, entry.notes].join(" ");
  return ["task", "tasks", "activity", "activities", "call_log", "email_activity", "note"].includes(type) || crmHardTextHasFollowupAction(text);
}
function crmHardActionIsBadPersonCompany(action, name) {
  const entry = action?.entry || {};
  const type = crmHardCleanType(action);
  const candidate = String(entry.name || entry.company || "").trim();
  if (!["account", "accounts", "company", "companies", "lead", "leads"].includes(type)) return false;
  if (!crmHardActionMentionsName(action, name)) return false;
  return !crmHardIsBusinessLikeName(candidate) && !crmHardIsBusinessLikeName(entry.company);
}
function crmHardBuildContactAction(text, existingAction) {
  const name = crmHardExtractPersonName(text);
  const time = crmHardExtractTime(text);
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
      company: entry.company && entry.company !== name && crmHardIsBusinessLikeName(entry.company) ? entry.company : "",
      title: entry.title && !crmHardTextHasFollowupAction(entry.title) ? entry.title : "",
      industry: entry.industry || "",
      source: entry.source || "AI CRM Entry",
      status: entry.status || "New",
      priority: entry.priority || "Medium",
      deal_name: "",
      value: 0,
      probability: 0,
      expected_revenue: 0,
      next_step: time ? "Call " + name + " at " + time + "." : "Follow up with " + name + ".",
      notes: "Person extracted from AI Add text: " + String(text || ""),
      tags: ["ai-add", "contact", "semantic-extract"],
      owner: entry.owner || "Constrava Demo Team",
      close_date: ""
    },
    reason: "Hard semantic guard: named human extracted as a contact/person record."
  };
}
function crmHardBuildTaskAction(text, existingAction) {
  const name = crmHardExtractPersonName(text);
  const time = crmHardExtractTime(text);
  const entry = existingAction?.entry || {};
  const label = time ? "Call " + name + " at " + time : "Call " + name;
  return {
    action: existingAction?.action === "update" ? "update" : "create",
    match: existingAction?.match || { name: label },
    entry: {
      ...entry,
      record_type: "task",
      type: "task",
      module: "activities",
      name: entry.name && crmHardTextHasFollowupAction(entry.name) ? entry.name : label,
      email: entry.email || "",
      phone: entry.phone || entry.mobile || "",
      mobile: entry.mobile || entry.phone || "",
      company: entry.company && entry.company !== name && crmHardIsBusinessLikeName(entry.company) ? entry.company : "",
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
      notes: entry.notes || "Task extracted from AI Add text: " + String(text || ""),
      tags: Array.isArray(entry.tags) && entry.tags.length ? entry.tags : ["ai-add", "task", "semantic-extract"],
      owner: entry.owner || "Constrava Demo Team",
      close_date: entry.close_date || ""
    },
    reason: "Hard semantic guard: follow-up action extracted as a separate task record."
  };
}
function crmHardMeaningGuardActions(text, actions) {
  const list = Array.isArray(actions) ? actions : [];
  if (!crmHardTextHasFollowupAction(text)) return list;
  const name = crmHardExtractPersonName(text);
  if (!name || crmHardIsBusinessLikeName(name)) return list;

  const kept = list.filter((action) => !crmHardActionIsBadPersonCompany(action, name));
  const hasPerson = kept.some((action) => crmHardActionIsPerson(action, name));
  const hasTask = kept.some((action) => crmHardActionIsTask(action));
  const seed = list.find((action) => crmHardActionMentionsName(action, name)) || list[0] || null;
  const output = [];
  if (!hasPerson) output.push(crmHardBuildContactAction(text, seed));
  output.push(...kept);
  if (!hasTask) output.push(crmHardBuildTaskAction(text, null));
  return output;
}
`;

if (!source.includes(marker)) {
  const anchor = "async function handleCrmAiEntry(req, res) {";
  const index = source.indexOf(anchor);
  if (index >= 0) {
    source = source.slice(0, index) + helper + "\n" + source.slice(index);
    changed = true;
  } else {
    console.warn("[crm-ai-hard-meaning-guard-patch] Could not find handleCrmAiEntry anchor.");
  }
}

const oldLine = "    const results = [];";
const newLine = "    plan.actions = crmHardMeaningGuardActions(text, plan.actions || []);\n    const results = [];";
if (source.includes(oldLine) && !source.includes("crmHardMeaningGuardActions(text, plan.actions")) {
  source = source.replace(oldLine, newLine);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[crm-ai-hard-meaning-guard-patch] Added hard semantic guard before CRM AI saves records.");
} else {
  console.log("[crm-ai-hard-meaning-guard-patch] Hard semantic guard already present or anchors not found.");
}
