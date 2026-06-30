import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-messy-ai-intake-pipeline-patch] server.js not found.");
  process.exit(0);
}

function replaceFunction(source, name, replacement) {
  const start = source.indexOf(name);
  if (start === -1) return { source, changed: false };
  const braceStart = source.indexOf("{", start);
  if (braceStart === -1) return { source, changed: false };
  let depth = 0;
  let end = -1;
  let inString = false;
  let stringChar = "";
  let escaped = false;
  let inTemplate = false;
  for (let i = braceStart; i < source.length; i++) {
    const ch = source[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (inString) { if (ch === stringChar) inString = false; continue; }
    if (inTemplate) { if (ch === "`") inTemplate = false; continue; }
    if (ch === "\"" || ch === "'") { inString = true; stringChar = ch; continue; }
    if (ch === "`") { inTemplate = true; continue; }
    if (ch === "{") depth++;
    if (ch === "}") {
      depth--;
      if (depth === 0) { end = i + 1; break; }
    }
  }
  if (end === -1) return { source, changed: false };
  const current = source.slice(start, end);
  if (current === replacement) return { source, changed: false };
  return { source: source.slice(0, start) + replacement + source.slice(end), changed: true };
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const helpers = `function cxCrmAiClean(value) {
  return String(value == null ? "" : value).trim();
}
function cxCrmAiTitleCase(value) {
  return cxCrmAiClean(value).replace(/\s+/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}
function cxCrmAiCanonType(value) {
  const raw = cxCrmAiClean(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const aliases = { leads:"lead", contacts:"person", contact:"person", people:"person", companies:"company", businesses:"company", organizations:"company", deals:"deal", sales:"deal", opportunities:"deal", opportunity:"deal", tasks:"task", todos:"task", followups:"task", "follow-ups":"task", forms:"intake", submissions:"intake", entries:"entry", crm_entry:"entry", "crm-entry":"entry" };
  return aliases[raw] || raw;
}
function cxCrmAiAddType(list, value) {
  if (Array.isArray(value)) return value.forEach((v) => cxCrmAiAddType(list, v));
  String(value || "").split(/[,|/]/).forEach((part) => {
    const t = cxCrmAiCanonType(part);
    if (t && !list.includes(t)) list.push(t);
  });
}
function cxCrmAiExtractEmail(text) {
  const m = cxCrmAiClean(text).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return m ? m[0].toLowerCase() : "";
}
function cxCrmAiExtractPhone(text) {
  const m = cxCrmAiClean(text).match(/(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/);
  return m ? m[0].trim() : "";
}
function cxCrmAiExtractMoney(text) {
  const s = cxCrmAiClean(text).toLowerCase();
  const range = s.match(/(\d+(?:\.\d+)?)\s*(?:or|to|-)\s*(\d+(?:\.\d+)?)\s*k\b/);
  if (range) return Math.round(((Number(range[1]) + Number(range[2])) / 2) * 1000);
  const money = s.match(/\$\s*(\d[\d,]*(?:\.\d+)?)(\s*k)?\b/);
  if (money) return Math.round(Number(money[1].replace(/,/g, "")) * (money[2] ? 1000 : 1));
  const budget = s.match(/(?:budget|around|about|maybe|roughly)\D{0,14}(\d+(?:\.\d+)?)\s*k\b/);
  if (budget) return Math.round(Number(budget[1]) * 1000);
  const plainK = s.match(/\b(\d+(?:\.\d+)?)\s*k\b/);
  if (plainK && /budget|quote|proposal|value|cost|price|around|about|maybe/.test(s)) return Math.round(Number(plainK[1]) * 1000);
  return 0;
}
function cxCrmAiExtractName(text) {
  const s = cxCrmAiClean(text);
  const patterns = [
    /^(?:just\s+)?(?:talked to|spoke with|met with|called|texted|messaged|emailed)\s+([a-z][a-z]+(?:\s+[a-z][a-z]+)?)/i,
    /(?:someone named|named|person named)\s+([a-z][a-z]+(?:\s+[a-z][a-z]+)?)/i,
    /^([a-z][a-z]+(?:\s+[a-z][a-z]+)?)\s+(?:from|at|with)\s+/i,
    /(?:contact name|contact)\s*:?\s*([a-z][a-z]+(?:\s+[a-z][a-z]+)?)/i
  ];
  for (const pattern of patterns) {
    const m = s.match(pattern);
    if (m && m[1]) return cxCrmAiTitleCase(m[1].replace(/\b(from|at|with|called|texted|emailed|messaged)\b.*$/i, ""));
  }
  return "";
}
function cxCrmAiExtractCompany(text) {
  const s = cxCrmAiClean(text);
  const direct = s.match(/\b([A-Z][A-Za-z0-9&'. -]{2,70}?(?:Roofing|Fitness|Dentistry|Dental|Landscaping|Auto Detail|Construction|Plumbing|Electric|Contracting|Garage|Gym|Salon|Cafe|Restaurant|Realty|Cleaning|HVAC|Clinic|Studio|LLC|Inc|Company|Co\.))\b/);
  if (direct && direct[1]) return cxCrmAiTitleCase(direct[1]);
  const patterns = [
    /(?:from|at|with)\s+([a-z0-9][a-z0-9&'. -]{2,70}?)(?:\s+(?:called|emailed|texted|messaged|wants|needs|asked|is|was|and|but|about)|[.,]|$)/i,
    /(?:runs|owns|owner of|business is|company is)\s+([a-z0-9][a-z0-9&'. -]{2,70}?)(?:[.,]|\s+(?:and|but|that|who|wants|needs)|$)/i,
    /(?:company|business|organization)\s*:?\s*([a-z0-9][a-z0-9&'. -]{2,70}?)(?:[.,]|$)/i
  ];
  for (const pattern of patterns) {
    const m = s.match(pattern);
    if (m && m[1]) {
      let value = m[1].replace(/\b(called|emailed|texted|messaged|wants|needs|asked|is|was|and|but|about)\b.*$/i, "").trim();
      if (value && !/^(me|us|him|her|them|it|a|the)$/i.test(value)) return cxCrmAiTitleCase(value);
    }
  }
  return "";
}
function cxCrmAiInferSource(text, existing) {
  const s = cxCrmAiClean(text).toLowerCase();
  if (existing) return existing;
  if (/instagram|ig\b/.test(s)) return "Instagram";
  if (/form|submitted|submission|site form|website form/.test(s)) return "Website Form";
  if (/called|phone|voicemail/.test(s)) return "Phone Call";
  if (/texted|sms/.test(s)) return "Text Message";
  if (/emailed|email/.test(s)) return "Email";
  return "AI Plain Text Note";
}
function cxCrmAiInferNextStep(text, existing) {
  if (existing) return existing;
  const s = cxCrmAiClean(text);
  if (/call (him|her|them)?\s*back|call back/i.test(s)) return "Call back about this CRM note.";
  if (/follow\s*up/i.test(s)) return "Follow up about this CRM note.";
  if (/email/i.test(s)) return "Send a follow-up email.";
  if (/proposal|quote/i.test(s)) return "Send or review the proposal/quote.";
  if (/tomorrow|friday|monday|tuesday|wednesday|thursday|next week|after \d/i.test(s)) return "Follow up at the requested time.";
  return "Follow up with this potential lead.";
}
function cxCrmAiInferPriority(text, existing) {
  if (existing) return existing;
  const s = cxCrmAiClean(text).toLowerCase();
  if (/high priority|urgent|serious|solid lead|very interested|approved|ready/.test(s)) return "High";
  if (/low priority|not urgent|maybe later/.test(s)) return "Low";
  return "Medium";
}
function cxCrmAiInferStatus(text, existing) {
  if (existing) return existing;
  const s = cxCrmAiClean(text).toLowerCase();
  if (/proposal|quote|approved moving|move.*proposal/.test(s)) return "Proposal";
  if (/qualified|serious|solid lead|interested/.test(s)) return "Qualified";
  if (/closed won|paid|bought|approved/.test(s)) return "Closed Won";
  return "New";
}
function cxCrmAiInferTypes(entry, text) {
  const src = entry && typeof entry === "object" ? entry : {};
  const types = [];
  cxCrmAiAddType(types, src.types);
  cxCrmAiAddType(types, src.type);
  cxCrmAiAddType(types, src.record_type);
  cxCrmAiAddType(types, src.module);
  cxCrmAiAddType(types, src.category);
  const all = [text, src.notes, src.message, src.next_step, src.source, src.provider, src.company, src.name, src.email, src.phone, src.deal_name, src.title].join(" ").toLowerCase();
  const hasContact = !!(src.name || src.email || src.phone || src.mobile || cxCrmAiExtractName(text) || cxCrmAiExtractEmail(text) || cxCrmAiExtractPhone(text));
  const hasCompany = !!(src.company || cxCrmAiExtractCompany(text));
  const hasNeed = /called|emailed|texted|messaged|reached out|asked|wants|needs|looking for|interested|quote|proposal|website|redesign|landing page|booking|intake|chatbot|form|project|service|system/.test(all);
  const hasTask = /task|todo|follow\s*up|call\s*back|email|tomorrow|next\s+(monday|tuesday|wednesday|thursday|friday|week)|meeting|appointment|after \d/.test(all);
  const hasDeal = Number(src.value || src.deal_value || src.budget || 0) > 0 || cxCrmAiExtractMoney(text) > 0 || /budget|deal|proposal|quote|opportunity|purchase|sale|project|website|redesign|landing page|booking|chatbot/.test(all);
  if (hasNeed || hasContact || hasCompany) cxCrmAiAddType(types, "lead");
  if (hasContact) cxCrmAiAddType(types, "person");
  if (hasCompany) cxCrmAiAddType(types, "company");
  if (hasDeal) cxCrmAiAddType(types, "deal");
  if (hasTask) cxCrmAiAddType(types, "task");
  if (/form|submission|intake|website form|site form/.test(all)) cxCrmAiAddType(types, "intake");
  if (/note|remember|don't forget|dont forget|met with|talked to/.test(all)) cxCrmAiAddType(types, "note");
  if (/client|customer/.test(all)) cxCrmAiAddType(types, "client");
  if (/purchase|order|payment|invoice/.test(all)) cxCrmAiAddType(types, "purchase");
  if (!types.length) cxCrmAiAddType(types, "lead");
  return Array.from(new Set(types.map(cxCrmAiCanonType).filter(Boolean)));
}
function cxCrmAiPrimaryType(types) {
  const order = ["lead", "deal", "task", "person", "company", "intake", "note", "client", "purchase", "entry"];
  return order.find((t) => types.includes(t)) || types[0] || "lead";
}
function cxCrmAiNormalizePatch(input, text) {
  const src = input && typeof input === "object" ? { ...input } : {};
  const rawText = cxCrmAiClean(text || src.plain_text || src.notes || src.message);
  const email = cxCrmAiClean(src.email || cxCrmAiExtractEmail(rawText));
  const phone = cxCrmAiClean(src.phone || src.mobile || cxCrmAiExtractPhone(rawText));
  const name = cxCrmAiClean(src.name || src.full_name || src.contact_name || cxCrmAiExtractName(rawText));
  const company = cxCrmAiClean(src.company || src.organization || src.business || cxCrmAiExtractCompany(rawText));
  const value = Number(src.value || src.deal_value || src.budget || cxCrmAiExtractMoney(rawText) || 0) || 0;
  const base = { ...src };
  base.plain_text = rawText;
  base.notes = cxCrmAiClean(src.notes || src.message || rawText);
  base.email = email;
  base.phone = phone;
  base.name = name || email || company || "AI CRM Record";
  base.company = company || src.company || "";
  base.source = cxCrmAiInferSource(rawText, src.source);
  base.provider = src.provider || "AI CRM Entry";
  base.status = cxCrmAiInferStatus(rawText, src.status || src.stage);
  base.priority = cxCrmAiInferPriority(rawText, src.priority);
  base.next_step = cxCrmAiInferNextStep(rawText, src.next_step);
  base.value = value;
  base.probability = Number(src.probability || (value > 0 ? 35 : 10));
  base.expected_revenue = Number(src.expected_revenue || Math.round(value * (base.probability / 100)) || 0);
  if (!base.deal_name) {
    if (company) base.deal_name = company + " project";
    else if (name && /website|redesign|landing page|booking|chatbot|form|project/i.test(rawText)) base.deal_name = name + " project";
    else base.deal_name = "AI CRM opportunity";
  }
  const types = cxCrmAiInferTypes(base, rawText);
  const primary = cxCrmAiCanonType(base.type || cxCrmAiPrimaryType(types));
  if (!types.includes(primary)) types.unshift(primary);
  base.type = primary;
  base.types = Array.from(new Set(types));
  base.record_type = cxCrmAiCanonType(base.record_type || primary);
  base.module = base.module || (base.types.includes("lead") ? "leads" : base.types.includes("task") ? "tasks" : base.types.includes("company") ? "companies" : "entries");
  base.tags = Array.isArray(base.tags) ? Array.from(new Set(["ai", "plain-text", ...base.tags])) : ["ai", "plain-text"];
  base.created_at = base.created_at || new Date().toISOString();
  return base;
}
function cxCrmAiMatchFromEntry(entry) {
  return {
    lead_id: entry.lead_id || entry.id || "",
    email: entry.email || "",
    phone: entry.phone || entry.mobile || "",
    name: entry.name || "",
    company: entry.company || ""
  };
}
function cxCrmAiFallbackPlan(text, currentEntries = []) {
  const entry = cxCrmAiNormalizePatch({}, text);
  const s = cxCrmAiClean(text).toLowerCase();
  const looksLikeUpdate = /\b(update|again|more serious|move|mark|change|add note|don'?t forget|met with|talked again|approved|followed up)\b/.test(s);
  return { actions: [{ action: looksLikeUpdate ? "update" : "create", match: cxCrmAiMatchFromEntry(entry), entry, reason: "Messy plain text CRM note normalized and saved." }] };
}
function cxCrmAiNormalizePlan(plan, text, currentEntries = []) {
  if (!plan || !Array.isArray(plan.actions) || !plan.actions.length) return cxCrmAiFallbackPlan(text, currentEntries);
  const actions = plan.actions.map((action) => {
    const normalizedEntry = cxCrmAiNormalizePatch(action && action.entry ? action.entry : {}, text);
    return {
      action: String(action && action.action || "create").toLowerCase().includes("update") ? "update" : "create",
      match: { ...cxCrmAiMatchFromEntry(normalizedEntry), ...(action && action.match && typeof action.match === "object" ? action.match : {}) },
      entry: normalizedEntry,
      reason: action && action.reason ? String(action.reason) : "AI interpreted messy CRM note."
    };
  });
  return { actions };
}
`;

if (!source.includes("function cxCrmAiNormalizePatch")) {
  const anchor = "async function handleCrmAiEntry";
  if (source.includes(anchor)) {
    source = source.replace(anchor, helpers + "\n" + anchor);
    changed = true;
  } else {
    console.warn("[crm-messy-ai-intake-pipeline-patch] handleCrmAiEntry anchor not found for helpers.");
  }
}

const llmFunction = `async function llmPlanCrmEntry(text, currentEntries = []) {
  if (!process.env.OPENAI_API_KEY) return null;
  const prompt = "You are a CRM intake interpreter. The user will type messy normal notes, not a form. They may omit labels, punctuation, or exact field names. Your job is to always turn the note into CRM actions that can be saved. Output JSON only in this exact shape: {\"actions\":[{\"action\":\"create\" or \"update\",\"match\":{\"lead_id\":\"\",\"email\":\"\",\"phone\":\"\",\"name\":\"\",\"company\":\"\"},\"entry\":{...crm fields...},\"reason\":\"\"}]}. Required entry fields: type, types, name, email, phone, mobile, company, title, industry, source, status, priority, deal_name, value, probability, expected_revenue, next_step, notes, tags, module, record_type. type is the primary category. types is an array of all matching CRM tabs using singular canonical values: lead, person, company, deal, task, intake, note, client, purchase, entry. If someone called, texted, emailed, messaged, submitted a form, asked, wants, needs, is interested, or has contact info, infer a lead. If a person name/email/phone appears, include person. If a business/company appears, include company. If there is a project, budget, quote, proposal, website, landing page, chatbot, booking, form, or service need, include deal. If there is follow-up, call back, email, tomorrow, weekday, appointment, or next step, include task. If it came from a form/submission, include intake. For vague business notes, still create one useful record with notes equal to the original text. Do not require a specific format. Do not invent email or phone if missing. Prefer update only when the text clearly refers to an existing record.";
  const context = (Array.isArray(currentEntries) ? currentEntries : []).slice(0, 40).map((e) => ({ lead_id: e.lead_id || e.id || "", name: e.name || "", email: e.email || "", phone: e.phone || e.mobile || "", company: e.company || "", type: e.type || e.record_type || "", types: e.types || [], notes: e.notes || "" }));
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Authorization": "Bearer " + process.env.OPENAI_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      temperature: 0,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: prompt },
        { role: "user", content: JSON.stringify({ plain_text_note: text, existing_records: context }) }
      ]
    })
  });
  const json = await response.json();
  if (!response.ok) throw new Error(json.error && json.error.message ? json.error.message : "OpenAI CRM interpretation failed.");
  const content = json.choices && json.choices[0] && json.choices[0].message ? json.choices[0].message.content : "";
  return JSON.parse(content || "{}");
}`;

let result = replaceFunction(source, "async function llmPlanCrmEntry", llmFunction);
if (result.changed) { source = result.source; changed = true; }

const fallbackFunction = `function fallbackPlanCrmEntry(text) {
  return cxCrmAiFallbackPlan(text, []);
}`;
result = replaceFunction(source, "function fallbackPlanCrmEntry", fallbackFunction);
if (result.changed) { source = result.source; changed = true; }

const routeFunction = `async function handleCrmAiEntry(req, res) {
  try {
    const text = String(req.body?.text || req.body?.entry || req.body?.note || req.body?.message || "").trim();
    if (!text) return res.status(400).json({ ok: false, error: "Please include plain text for the AI entry." });

    const token = String(req.body?.token || req.query.token || "demo");
    const site = await findSiteByToken(token);
    const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token || "demo"));

    let current = [];
    try {
      current = typeof getUnifiedCrmLeadList === "function" ? await getUnifiedCrmLeadList(siteId, token) : await getCrmLeads(siteId, 300);
    } catch {
      try { current = await getCrmLeads(siteId, 300); } catch { current = []; }
    }

    let rawPlan = null;
    try {
      if (typeof llmPlanCrmEntry === "function") rawPlan = await llmPlanCrmEntry(text, current);
    } catch (err) {
      rawPlan = null;
    }

    const plan = cxCrmAiNormalizePlan(rawPlan, text, current);
    const results = [];

    for (const action of plan.actions || []) {
      const kind = String(action.action || "create").toLowerCase() === "update" ? "update" : "create";
      const patch = cxCrmAiNormalizePatch(action.entry || {}, text);
      let matched = null;
      if (kind === "update") {
        try { matched = typeof findMatchingEntry === "function" ? findMatchingEntry(current, action.match || patch || {}) : null; } catch { matched = null; }
      }

      const merged = matched && typeof mergeEntryUpdate === "function" ? mergeEntryUpdate(matched, patch, text) : { ...(matched || {}), ...patch };
      let finalEntry = typeof completeCrmEntry === "function" ? completeCrmEntry(merged, siteId, text) : merged;
      finalEntry = cxCrmAiNormalizePatch(finalEntry, text);
      finalEntry.dashboard_token = token;
      finalEntry.site_id = siteId;
      finalEntry.site_slug = siteId;
      finalEntry.lead_id = finalEntry.lead_id || finalEntry.record_id || ("AI-" + randomBytes(6).toString("hex").toUpperCase());
      finalEntry.record_id = finalEntry.record_id || finalEntry.lead_id;

      if (typeof saveCrmEntryCompat === "function") await saveCrmEntryCompat(siteId, token, finalEntry);
      else await insertCrmLead(siteId, finalEntry);

      results.push({
        action: kind,
        matched_lead_id: matched?.lead_id || matched?.record_id || null,
        lead_id: finalEntry.lead_id,
        record_id: finalEntry.record_id,
        types: finalEntry.types,
        type: finalEntry.type,
        reason: action.reason || "Messy CRM note saved.",
        entry: finalEntry
      });
    }

    let refreshed = [];
    try {
      refreshed = typeof getUnifiedCrmLeadList === "function" ? await getUnifiedCrmLeadList(siteId, token) : await getCrmLeads(siteId, 300);
    } catch {
      refreshed = [];
    }

    res.json({
      ok: true,
      message: "Messy CRM entry saved and normalized into matching tabs.",
      source: "messy_ai_crm_pipeline",
      actions: results,
      summary: typeof crmListSummary === "function" ? crmListSummary(refreshed) : { total: refreshed.length },
      entries: refreshed.length ? refreshed : results.map((r) => r.entry)
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "AI CRM entry failed." });
  }
}`;

result = replaceFunction(source, "async function handleCrmAiEntry", routeFunction);
if (result.changed) { source = result.source; changed = true; }

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Messy CRM AI intake pipeline now saves normalized multi-tab records.");
} else {
  console.log("Messy CRM AI intake pipeline already applied or anchors not found.");
}
