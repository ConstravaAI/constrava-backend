import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-form-intake-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
if (source.includes("__crmAiFormIntakePatch_v1")) {
  console.log("AI form intake patch already applied.");
  process.exit(0);
}

const start = source.indexOf("function normalizeFormLead(body, siteSlug, formSlug, req) {");
const end = source.indexOf("async function insertCrmLead(siteId, lead) {", start);
if (start === -1 || end === -1) {
  console.warn("[crm-ai-form-intake-patch] Could not find normalizeFormLead block; leaving server.js unchanged.");
  process.exit(0);
}

const smartBlock = `// __crmAiFormIntakePatch_v1
function normalizeFieldLabel(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}
function compactText(value) {
  if (Array.isArray(value)) return value.filter(Boolean).join(", ").trim();
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value ?? "").trim();
}
function extractEmail(value) {
  const match = compactText(value).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/i);
  return match ? match[0] : "";
}
function extractPhone(value) {
  const text = compactText(value);
  const match = text.match(/(?:\\+?1[\\s.-]?)?(?:\\(?\\d{3}\\)?[\\s.-]?)\\d{3}[\\s.-]?\\d{4}/);
  return match ? match[0].replace(/(?!^)\\D/g, "") : "";
}
function extractUrl(value) {
  const text = compactText(value);
  const match = text.match(/https?:\\/\\/[^\\s]+|(?:www\\.)[^\\s]+|[a-z0-9-]+\\.[a-z]{2,}(?:\\/[^\\s]*)?/i);
  return match ? match[0] : "";
}
function moneyNumber(value) {
  const text = compactText(value).replace(/,/g, "");
  const match = text.match(/\\$?\\b(\\d{2,7})(?:\\.\\d{1,2})?\\b/);
  return match ? Number(match[1]) : 0;
}
function flattenFormPayload(payload) {
  const root = payload && typeof payload === "object" ? payload : {};
  const nested = root.form_response || root.response || root.data || root.submission || root.answers || root.fields || {};
  const rows = [];
  const add = (label, value, path = "") => {
    if (value === undefined || value === null || value === "") return;
    if (["provider", "source", "site_slug", "form_slug", "dashboard_token", "token"].includes(String(label))) return;
    rows.push({ label: String(label), value: compactText(value), path });
  };
  const walk = (obj, prefix = "") => {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
    for (const [key, value] of Object.entries(obj)) {
      const path = prefix ? prefix + "." + key : key;
      if (value && typeof value === "object" && !Array.isArray(value)) {
        if ("question" in value || "label" in value || "title" in value || "answer" in value || "value" in value) {
          add(value.question || value.label || value.title || key, value.answer ?? value.value ?? value.text ?? value.response, path);
        } else walk(value, path);
      } else add(key, value, path);
    }
  };
  walk(root);
  if (nested && nested !== root) walk(nested, "nested");
  const seen = new Set();
  return rows.filter((row) => {
    const key = row.label + "::" + row.value;
    if (seen.has(key)) return false;
    seen.add(key);
    return row.value;
  });
}
function buildRuleBasedLeadFields(payload) {
  const rows = flattenFormPayload(payload);
  const fields = { name: "", email: "", phone: "", company: "", title: "", message: "", service: "", budget: 0, website: "", preferred_contact: "", confidence: 0.55, mapped_fields: [], unmapped_fields: [] };
  const addMap = (label, value, target, reason) => fields.mapped_fields.push({ label, value, target, reason });
  const appendMessage = (text) => { const clean = compactText(text); if (!clean) return; fields.message = fields.message ? fields.message + "\n" + clean : clean; };

  for (const row of rows) {
    const label = normalizeFieldLabel(row.label);
    const value = compactText(row.value);
    if (!value) continue;
    const email = extractEmail(value);
    const phone = extractPhone(value);
    const url = extractUrl(value);
    const budget = moneyNumber(value);

    if (email && !fields.email) { fields.email = email; addMap(row.label, value, "email", "email pattern found in answer"); }
    if (phone && !fields.phone) { fields.phone = phone; addMap(row.label, value, "phone", "phone pattern found in answer"); }
    if (url && !email && !fields.website && /web|site|url|domain|portfolio|company/.test(label)) { fields.website = url; addMap(row.label, value, "website", "website-like value and label"); }

    if (!fields.name && /(^| )(name|full name|your name|contact person|who are you)( |$)/.test(label) && !email && !phone && value.length <= 80) {
      fields.name = value; addMap(row.label, value, "name", "name-like label"); continue;
    }
    if (!fields.company && /(company|business|organization|organisation|brand|agency|studio|school|employer)/.test(label)) {
      fields.company = value; addMap(row.label, value, "company", "company-like label"); continue;
    }
    if (!fields.title && /(role|title|position|job)/.test(label)) {
      fields.title = value; addMap(row.label, value, "title", "role/title label"); continue;
    }
    if (!fields.service && /(service|project|need|looking for|interested|help|request|type)/.test(label)) {
      fields.service = value; addMap(row.label, value, "service", "service/request label"); continue;
    }
    if (!fields.preferred_contact && /(preferred|best way|reach|contact method|how can we reach|contact)/.test(label)) {
      if (!email && !phone) fields.preferred_contact = value;
      addMap(row.label, value, email ? "email" : phone ? "phone" : "preferred_contact", "contact label plus answer pattern");
      continue;
    }
    if (!fields.budget && (budget || /(budget|price|cost|spend|amount|value)/.test(label))) {
      fields.budget = budget || 0; addMap(row.label, value, "budget", "budget-like label/value"); continue;
    }
    if (/(message|notes|comments|describe|description|details|anything else|question)/.test(label)) {
      appendMessage(value); addMap(row.label, value, "message", "message-like label"); continue;
    }
    if (!email && !phone && !url && value.length > 15) appendMessage(row.label + ": " + value);
    else fields.unmapped_fields.push(row);
  }

  if (!fields.name && fields.email) fields.name = fields.email.split("@")[0].replace(/[._-]+/g, " ").replace(/\\b\\w/g, (m) => m.toUpperCase());
  if (!fields.message && fields.service) fields.message = fields.service;
  fields.confidence = Math.min(0.95, 0.45 + (fields.email ? 0.18 : 0) + (fields.phone ? 0.12 : 0) + (fields.name ? 0.12 : 0) + (fields.message ? 0.08 : 0));
  return fields;
}
async function llmNormalizeLeadFields(payload, ruleFields) {
  if (!process.env.OPENAI_API_KEY) return null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 9000);
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.OPENAI_API_KEY },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        temperature: 0,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: "You normalize messy form submissions into CRM lead fields. Use answer content over question wording. If a value is an email, put it in email even if the question says contact. If a value is a phone number, put it in phone. Return only JSON with fields: name,email,phone,company,title,message,service,budget,website,preferred_contact,confidence,mapped_fields. Never invent contact details." },
          { role: "user", content: JSON.stringify({ raw_submission: payload, rule_based_guess: ruleFields }) }
        ]
      })
    });
    clearTimeout(timer);
    const json = await response.json();
    if (!response.ok) return null;
    return JSON.parse(json.choices?.[0]?.message?.content || "null");
  } catch { return null; }
}
function mergeLeadFields(ruleFields, aiFields) {
  const merged = { ...ruleFields };
  if (aiFields && typeof aiFields === "object") {
    for (const key of ["name", "email", "phone", "company", "title", "message", "service", "website", "preferred_contact"]) {
      if (aiFields[key] && String(aiFields[key]).trim()) merged[key] = String(aiFields[key]).trim();
    }
    if (Number(aiFields.budget)) merged.budget = Number(aiFields.budget);
    if (Number(aiFields.confidence)) merged.confidence = Math.max(Number(ruleFields.confidence || 0), Math.min(0.98, Number(aiFields.confidence)));
    if (Array.isArray(aiFields.mapped_fields)) merged.ai_mapped_fields = aiFields.mapped_fields;
  }
  const email = extractEmail(merged.email || "");
  const phone = extractPhone(merged.phone || "");
  if (email) merged.email = email;
  if (phone) merged.phone = phone;
  return merged;
}
async function normalizeFormLeadSmart(body, siteSlug, formSlug, req) {
  const payload = body && typeof body === "object" ? body : {};
  const ruleFields = buildRuleBasedLeadFields(payload);
  const aiFields = await llmNormalizeLeadFields(payload, ruleFields);
  const fields = mergeLeadFields(ruleFields, aiFields);
  const pick = (...names) => {
    for (const name of names) if (payload[name] !== undefined && payload[name] !== null && payload[name] !== "") return payload[name];
    return "";
  };
  const company = fields.company || "External Form Lead";
  const value = Number(fields.budget || 0);
  const now = new Date().toISOString();
  return {
    lead_id: "FORM-" + randomBytes(5).toString("hex").toUpperCase(),
    record_type: "external_form_lead",
    module: "leads",
    site_id: siteSlug,
    site_slug: siteSlug,
    form_slug: formSlug,
    dashboard_token: String(pick("dashboard_token", "token") || siteSlug),
    name: String(fields.name || fields.email || fields.phone || "External Form Lead"),
    email: String(fields.email || ""),
    phone: String(fields.phone || ""),
    company: String(company),
    title: String(fields.title || "External Form Lead"),
    source: String(pick("source", "platform", "provider", "utm_source") || req.get("x-form-provider") || "External Form"),
    owner: String(pick("owner") || "Constrava Demo Team"),
    status: String(pick("status", "stage") || "New"),
    priority: fields.confidence >= 0.75 ? "High" : "Review",
    deal_name: String(fields.service || pick("deal_name", "project", "service") || company + " form inquiry"),
    value: Number.isFinite(value) ? value : 0,
    probability: fields.confidence >= 0.75 ? 45 : 25,
    expected_revenue: Number.isFinite(value) ? Math.round(value * (fields.confidence >= 0.75 ? 0.45 : 0.25)) : 0,
    close_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
    created_at: now,
    last_contacted: now.slice(0, 10),
    tags: ["external-form", "ai-normalized", String(siteSlug), String(formSlug)],
    notes: String(fields.message || "Submitted through external form intake."),
    normalization: { strategy: aiFields ? "rules+llm" : "rules", confidence: fields.confidence, mapped_fields: fields.mapped_fields, ai_mapped_fields: fields.ai_mapped_fields || [], unmapped_fields: fields.unmapped_fields || [] },
    raw_submission: payload
  };
}

`;

source = source.slice(0, start) + smartBlock + source.slice(end);
source = source.replace(
  "const lead = normalizeFormLead(req.body || {}, siteSlug, formSlug, req);",
  "const lead = await normalizeFormLeadSmart(req.body || {}, siteSlug, formSlug, req);"
);

fs.writeFileSync(file, source);
console.log("AI form intake normalization patch applied.");
