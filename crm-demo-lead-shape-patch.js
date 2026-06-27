import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-demo-lead-shape-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function replaceOnce(find, replacement, label) {
  if (source.includes(replacement)) return;
  if (!source.includes(find)) {
    console.warn(`[crm-demo-lead-shape-patch] Could not find ${label}; leaving that piece unchanged.`);
    return;
  }
  source = source.replace(find, replacement);
  changed = true;
}

replaceOnce(
  'Return only JSON with fields: name,email,phone,company,title,message,service,budget,website,preferred_contact,confidence,mapped_fields. Never invent contact details.',
  'Return only JSON with fields: name,email,phone,company,title,industry,employees,website,location,message,service,budget,preferred_contact,next_step,confidence,mapped_fields. Never invent contact details.',
  "LLM CRM field prompt"
);

replaceOnce(
  '["name", "email", "phone", "company", "title", "message", "service", "website", "preferred_contact"]',
  '["name", "email", "phone", "company", "title", "industry", "employees", "website", "location", "message", "service", "preferred_contact", "next_step"]',
  "LLM merge field list"
);

replaceOnce(
  '  const now = new Date().toISOString();\n  return {',
  '  const now = new Date().toISOString();\n  const leadName = String(fields.name || fields.email || fields.phone || "External Form Lead");\n  const nameParts = splitLeadName(leadName);\n  return {',
  "lead name variables"
);

replaceOnce(
  '    name: String(fields.name || fields.email || fields.phone || "External Form Lead"),\n    email: String(fields.email || ""),\n    phone: String(fields.phone || ""),\n    company: String(company),\n    title: String(fields.title || "External Form Lead"),',
  '    name: leadName,\n    first_name: nameParts.first_name,\n    last_name: nameParts.last_name,\n    email: String(fields.email || ""),\n    phone: String(fields.phone || ""),\n    mobile: String(fields.phone || ""),\n    company: String(company),\n    title: String(fields.title || "External Form Lead"),\n    industry: String(fields.industry || inferIndustryFromText(company + " " + fields.service + " " + fields.message)),\n    employees: String(fields.employees || "Unknown"),\n    website: String(fields.website || ""),\n    location: String(fields.location || ""),',
  "normalized CRM identity fields"
);

replaceOnce(
  '    close_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),\n    created_at: now,',
  '    close_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),\n    next_step: String(fields.next_step || "Review the submitted form and follow up with the lead."),\n    created_at: now,',
  "next step field"
);

const mapStart = source.indexOf("function mapLead(lead, i) {");
const mapEnd = source.indexOf("async function getDashboardPayload(token) {", mapStart);
if (mapStart !== -1 && mapEnd !== -1 && !source.includes("__crmDemoLeadShapePatch_v1")) {
  const mapBlock = `// __crmDemoLeadShapePatch_v1
function splitLeadName(name) {
  const clean = String(name || "").trim();
  if (!clean || clean.includes("@")) return { first_name: "", last_name: "" };
  const parts = clean.split(/\s+/).filter(Boolean);
  return { first_name: parts[0] || "", last_name: parts.slice(1).join(" ") || "" };
}
function normalizeLeadTags(value, fallback = []) {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === "string" && value.trim()) {
    try { const parsed = JSON.parse(value); if (Array.isArray(parsed)) return parsed.map(String).filter(Boolean); } catch {}
    return value.split(",").map((x) => x.trim()).filter(Boolean);
  }
  return fallback;
}
function inferIndustryFromText(text) {
  const s = String(text || "").toLowerCase();
  if (/construct|roof|hvac|plumb|electric|contractor|renovation|build/.test(s)) return "Home Services";
  if (/manufactur|factory|production|maintenance|machine/.test(s)) return "Manufacturing";
  if (/fitness|gym|training|studio|class/.test(s)) return "Fitness";
  if (/restaurant|cafe|food|catering|coffee/.test(s)) return "Restaurant";
  if (/design|creative|studio|brand|media|marketing/.test(s)) return "Creative Services";
  if (/health|medical|clinic|wellness/.test(s)) return "Health Technology";
  return "General Business";
}
function probabilityFromStatus(status, confidence = 0.55) {
  const s = String(status || "").toLowerCase();
  if (s.includes("closed won")) return 100;
  if (s.includes("negotiation")) return 80;
  if (s.includes("proposal")) return 60;
  if (s.includes("qualified")) return 40;
  if (s.includes("needs")) return 20;
  return confidence >= 0.75 ? 25 : 10;
}
function mapLead(lead, i) {
  const rawName = String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name"], "External Form Lead"));
  const parts = splitLeadName(rawName);
  const email = String(valueFrom(lead, ["email", "lead_email", "contact_email"], ""));
  const phone = String(valueFrom(lead, ["phone", "phone_number", "mobile"], ""));
  const company = String(valueFrom(lead, ["company", "organization"], "External Form Lead"));
  const notes = String(valueFrom(lead, ["notes", "message", "body"], ""));
  const normalization = valueFrom(lead, ["normalization"], null);
  const confidence = Number(normalization?.confidence || valueFrom(lead, ["confidence"], 0.55)) || 0.55;
  const status = String(valueFrom(lead, ["status", "stage", "lead_status"], confidence >= 0.75 ? "Qualified" : "New"));
  const value = Number(valueFrom(lead, ["value", "deal_value", "amount", "budget"], 0)) || 0;
  const probability = Number(valueFrom(lead, ["probability"], probabilityFromStatus(status, confidence))) || probabilityFromStatus(status, confidence);
  const expected = Number(valueFrom(lead, ["expected_revenue"], value ? Math.round(value * probability / 100) : 0)) || 0;
  return {
    lead_id: String(valueFrom(lead, ["lead_id", "id"], "CL-FORM-" + String(i + 1).padStart(4, "0"))),
    name: rawName,
    first_name: String(valueFrom(lead, ["first_name", "firstName"], parts.first_name)),
    last_name: String(valueFrom(lead, ["last_name", "lastName"], parts.last_name)),
    email,
    phone,
    mobile: String(valueFrom(lead, ["mobile"], phone)),
    company,
    title: String(valueFrom(lead, ["title", "role", "job_title"], "External Form Lead")),
    industry: String(valueFrom(lead, ["industry"], inferIndustryFromText(company + " " + notes))),
    employees: String(valueFrom(lead, ["employees", "employee_count", "team_size"], "Unknown")),
    website: String(valueFrom(lead, ["website", "url", "domain"], "")),
    location: String(valueFrom(lead, ["location", "city", "region"], "")),
    source: String(valueFrom(lead, ["source", "channel", "campaign"], "Form Submission")),
    owner: String(valueFrom(lead, ["owner"], "Constrava Demo Team")),
    status,
    priority: String(valueFrom(lead, ["priority"], confidence >= 0.75 ? "High" : "Medium")),
    deal_name: String(valueFrom(lead, ["deal_name", "project", "service"], company + " form inquiry")),
    value,
    probability,
    expected_revenue: expected,
    close_date: String(valueFrom(lead, ["close_date"], new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10))),
    next_step: String(valueFrom(lead, ["next_step"], "Review the submitted form and follow up with the lead.")),
    last_contacted: String(valueFrom(lead, ["last_contacted"], new Date().toISOString().slice(0, 10))),
    created_at: String(valueFrom(lead, ["created_at", "timestamp", "received_at"], new Date().toISOString())),
    tags: normalizeLeadTags(valueFrom(lead, ["tags"], []), ["external-form", "ai-normalized"]),
    notes,
    normalization,
    raw_submission: valueFrom(lead, ["raw_submission"], lead.raw_submission || lead.payload || lead.metadata || {})
  };
}
`;
  source = source.slice(0, mapStart) + mapBlock + source.slice(mapEnd);
  changed = true;
} else if (source.includes("__crmDemoLeadShapePatch_v1")) {
  console.log("CRM demo lead shape mapper already applied.");
} else {
  console.warn("[crm-demo-lead-shape-patch] Could not find mapLead block.");
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM form leads now align with the demo CRM list shape.");
} else {
  console.log("CRM demo lead shape patch made no changes.");
}
