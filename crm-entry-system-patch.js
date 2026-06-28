import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-entry-system-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function replaceOnce(find, replacement, label) {
  if (source.includes(replacement)) return;
  if (!source.includes(find)) {
    console.warn(`[crm-entry-system-patch] Could not find ${label}; leaving that part unchanged.`);
    return;
  }
  source = source.replace(find, replacement);
  changed = true;
}

if (!source.includes("__crmEntrySystemPatch_v1")) {
  const anchor = 'app.get("/api/crm/leads"';
  const fallbackAnchor = 'app.get("/api/dashboard", async (req, res) => {';
  const insertAt = source.indexOf(anchor) !== -1 ? source.indexOf(anchor) : source.indexOf(fallbackAnchor);
  if (insertAt === -1) {
    console.warn("[crm-entry-system-patch] Could not find CRM route anchor.");
  } else {
    const block = `// __crmEntrySystemPatch_v1
function entryCleanText(value) { return String(value ?? "").trim(); }
function entryDigits(value) { return String(value || "").replace(/\D/g, ""); }
function entrySplitName(name) {
  const clean = entryCleanText(name);
  if (!clean || clean.includes("@")) return { first_name: "", last_name: "" };
  const parts = clean.split(/\s+/).filter(Boolean);
  return { first_name: parts[0] || "", last_name: parts.slice(1).join(" ") || "" };
}
function entryInferIndustry(text) {
  const s = String(text || "").toLowerCase();
  if (/construct|roof|hvac|plumb|electric|contractor|renovation|build|repair|service/.test(s)) return "Home Services";
  if (/manufactur|factory|production|maintenance|machine|shop/.test(s)) return "Manufacturing";
  if (/fitness|gym|training|studio|class|coach/.test(s)) return "Fitness";
  if (/restaurant|cafe|food|catering|coffee|bakery/.test(s)) return "Restaurant";
  if (/design|creative|studio|brand|media|marketing|agency/.test(s)) return "Creative Services";
  if (/health|medical|clinic|wellness|therapy/.test(s)) return "Health Technology";
  return "General Business";
}
function entryProbability(status, confidence = 0.55) {
  const s = String(status || "").toLowerCase();
  if (s.includes("closed won")) return 100;
  if (s.includes("negotiation")) return 80;
  if (s.includes("proposal")) return 60;
  if (s.includes("qualified")) return 40;
  if (s.includes("needs")) return 20;
  return confidence >= 0.75 ? 25 : 10;
}
function entryMatchScore(entry, match) {
  if (!entry || !match) return 0;
  let score = 0;
  if (match.lead_id && String(entry.lead_id || "").toLowerCase() === String(match.lead_id).toLowerCase()) score += 100;
  if (match.email && String(entry.email || "").toLowerCase() === String(match.email).toLowerCase()) score += 80;
  if (match.phone && entryDigits(entry.phone || entry.mobile) && entryDigits(entry.phone || entry.mobile) === entryDigits(match.phone)) score += 70;
  if (match.company && String(entry.company || "").toLowerCase().includes(String(match.company).toLowerCase())) score += 30;
  if (match.name && String(entry.name || "").toLowerCase().includes(String(match.name).toLowerCase())) score += 35;
  return score;
}
function findMatchingEntry(entries, match) {
  let best = null, bestScore = 0;
  for (const entry of entries || []) {
    const score = entryMatchScore(entry, match || {});
    if (score > bestScore) { best = entry; bestScore = score; }
  }
  return bestScore >= 35 ? best : null;
}
function completeCrmEntry(input, siteId, text = "") {
  const src = input && typeof input === "object" ? input : {};
  const leadName = entryCleanText(src.name || src.full_name || src.lead_name || src.contact_name || src.email || src.phone || "CRM Entry");
  const parts = entrySplitName(leadName);
  const status = entryCleanText(src.status || src.stage || "New");
  const confidence = Number(src.confidence || src.normalization?.confidence || 0.65) || 0.65;
  const probability = Number(src.probability || entryProbability(status, confidence));
  const value = Number(src.value || src.deal_value || src.budget || src.amount || 0) || 0;
  const company = entryCleanText(src.company || src.organization || "Individual / Unknown Company");
  const notes = entryCleanText(src.notes || src.message || src.body || text || "Created from CRM entry system.");
  const now = new Date().toISOString();
  return {
    lead_id: entryCleanText(src.lead_id || src.id || "CRM-" + randomBytes(5).toString("hex").toUpperCase()),
    record_type: entryCleanText(src.record_type || src.type || "crm_entry"),
    module: entryCleanText(src.module || "leads"),
    site_id: String(src.site_id || siteId || "demo"),
    site_slug: String(src.site_slug || siteId || "demo"),
    form_slug: String(src.form_slug || "crm-entry"),
    dashboard_token: String(src.dashboard_token || src.token || siteId || "demo"),
    name: leadName,
    first_name: entryCleanText(src.first_name || src.firstName || parts.first_name),
    last_name: entryCleanText(src.last_name || src.lastName || parts.last_name),
    email: entryCleanText(src.email || src.lead_email || src.contact_email),
    phone: entryCleanText(src.phone || src.phone_number || src.mobile),
    mobile: entryCleanText(src.mobile || src.phone || src.phone_number),
    company,
    title: entryCleanText(src.title || src.role || src.job_title || "CRM Contact"),
    industry: entryCleanText(src.industry || entryInferIndustry(company + " " + (src.deal_name || src.service || "") + " " + notes)),
    employees: entryCleanText(src.employees || src.employee_count || src.team_size || "Unknown"),
    website: entryCleanText(src.website || src.url || src.domain),
    location: entryCleanText(src.location || src.city || src.region),
    source: entryCleanText(src.source || "AI CRM Entry"),
    owner: entryCleanText(src.owner || "Constrava Demo Team"),
    status,
    priority: entryCleanText(src.priority || (confidence >= 0.75 ? "High" : "Medium")),
    deal_name: entryCleanText(src.deal_name || src.project || src.service || company + " opportunity"),
    value,
    probability,
    expected_revenue: Number(src.expected_revenue || Math.round(value * probability / 100)) || 0,
    close_date: entryCleanText(src.close_date || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)),
    next_step: entryCleanText(src.next_step || "Review this CRM entry and follow up."),
    last_contacted: entryCleanText(src.last_contacted || now.slice(0, 10)),
    created_at: entryCleanText(src.created_at || now),
    tags: Array.isArray(src.tags) ? src.tags.map(String) : ["crm-entry", "ai-interpreted"],
    notes,
    normalization: src.normalization || { strategy: "crm-entry-system", confidence },
    raw_submission: src.raw_submission || { plain_text: text, interpreted_entry: src }
  };
}
function mergeEntryUpdate(existing, patch, text = "") {
  const merged = { ...(existing || {}), ...(patch || {}) };
  merged.lead_id = existing?.lead_id || patch?.lead_id || patch?.id;
  merged.created_at = existing?.created_at || patch?.created_at;
  merged.last_contacted = new Date().toISOString().slice(0, 10);
  const existingNotes = entryCleanText(existing?.notes);
  const newNotes = entryCleanText(patch?.notes || patch?.message || text);
  if (existingNotes && newNotes && !existingNotes.includes(newNotes)) merged.notes = existingNotes + "\n\nUpdate: " + newNotes;
  else merged.notes = newNotes || existingNotes;
  merged.tags = Array.from(new Set([...(Array.isArray(existing?.tags) ? existing.tags : []), ...(Array.isArray(patch?.tags) ? patch.tags : []), "ai-updated"]));
  return merged;
}
async function llmPlanCrmEntry(text, currentEntries) {
  if (!process.env.OPENAI_API_KEY) return null;
  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.OPENAI_API_KEY },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        temperature: 0,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: "You are the AI operator for a CRM with one unified entries list. Read the user's plain text update. Decide whether to create one or more entries, update one or more existing entries, or both. Output JSON only: {actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company}, entry:{complete CRM fields}, reason:string}]}. Complete CRM fields include name,email,phone,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type. Use the existing entries to update the right record. Do not invent contact details not present or implied." },
          { role: "user", content: JSON.stringify({ plain_text: text, current_entries: (currentEntries || []).slice(0, 40).map((e) => ({ lead_id: e.lead_id, name: e.name, email: e.email, phone: e.phone, company: e.company, status: e.status, deal_name: e.deal_name, value: e.value, next_step: e.next_step, notes: String(e.notes || "").slice(0, 300) })) }) }
        ]
      })
    });
    const json = await response.json();
    if (!response.ok) return null;
    const parsed = JSON.parse(json.choices?.[0]?.message?.content || "null");
    if (!parsed || !Array.isArray(parsed.actions)) return null;
    return parsed;
  } catch { return null; }
}
function fallbackPlanCrmEntry(text) {
  return { actions: [{ action: "create", match: {}, entry: { name: "CRM Entry", source: "AI CRM Entry", notes: text, message: text, record_type: "crm_entry", module: "leads" }, reason: "Fallback plain-text entry created without LLM." }] };
}
function filterCrmEntries(entries, type, qText) {
  let list = entries || [];
  const t = String(type || "all").toLowerCase();
  if (t === "deals") list = list.filter((e) => Number(e.value) > 0 || e.deal_name);
  if (t === "contacts") list = list.filter((e) => e.email || e.phone || e.mobile);
  if (t === "tasks") list = list.filter((e) => e.next_step || /task|follow|call|meeting|todo/i.test(String(e.record_type || e.module || e.notes || "")));
  if (t === "leads") list = list.filter((e) => !/task|note/i.test(String(e.record_type || e.module || "")));
  const q = String(qText || "").trim().toLowerCase();
  if (q) list = list.filter((e) => JSON.stringify(e).toLowerCase().includes(q));
  return list;
}
async function handleCrmAiEntry(req, res) {
  try {
    const text = String(req.body?.text || req.body?.entry || req.body?.note || "").trim();
    if (!text) return res.status(400).json({ ok: false, error: "Please include plain text for the AI entry." });
    const token = String(req.body?.token || req.query.token || "demo");
    const site = await findSiteByToken(token);
    const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token || "demo"));
    const current = await getUnifiedCrmLeadList(siteId, token);
    const plan = await llmPlanCrmEntry(text, current) || fallbackPlanCrmEntry(text);
    const results = [];
    for (const action of plan.actions || []) {
      const kind = String(action.action || "create").toLowerCase();
      const patch = action.entry || {};
      let finalEntry;
      let matched = null;
      if (kind === "update") {
        matched = findMatchingEntry(current, action.match || patch || {});
        finalEntry = completeCrmEntry(mergeEntryUpdate(matched || {}, patch, text), siteId, text);
        finalEntry.record_type = finalEntry.record_type || "crm_entry_update";
        finalEntry.source = patch.source || "AI CRM Update";
      } else {
        const normalized = await normalizeFormLeadSmart({ ...patch, plain_text: text, notes: patch.notes || patch.message || text, provider: "AI CRM Entry", source: patch.source || "AI CRM Entry", dashboard_token: token }, siteId, "ai-entry", req);
        finalEntry = completeCrmEntry({ ...normalized, ...patch, source: patch.source || normalized.source || "AI CRM Entry" }, siteId, text);
      }
      finalEntry.dashboard_token = token;
      finalEntry.site_id = siteId;
      finalEntry.site_slug = siteId;
      await insertCrmLead(siteId, finalEntry);
      results.push({ action: kind, matched_lead_id: matched?.lead_id || null, lead_id: finalEntry.lead_id, reason: action.reason || "AI interpreted CRM entry.", entry: finalEntry });
    }
    const refreshed = await getUnifiedCrmLeadList(siteId, token);
    res.json({ ok: true, message: "AI entry processed into the unified CRM list.", source: "unified_crm_entry_list", actions: results, summary: crmListSummary(refreshed), entries: refreshed });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "AI CRM entry failed." });
  }
}
`;
    source = source.slice(0, insertAt) + block + "\n" + source.slice(insertAt);
    changed = true;
  }
}

if (!source.includes('app.get("/api/crm/entries"')) {
  const routeAnchor = 'app.get("/api/crm/leads"';
  const route = 'app.get("/api/crm/entries", async (req, res) => { try { const token = String(req.query.token || "demo"); const payload = await getDashboardPayload(token); const entries = filterCrmEntries(payload.leads || [], req.query.type || "all", req.query.q || ""); res.json({ ok: true, site: payload.site, source: "unified_crm_entry_list", type: String(req.query.type || "all"), summary: crmListSummary(entries), entries, leads: entries }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "CRM entries failed." }); } });\napp.post("/api/crm/ai-entry", async (req, res) => handleCrmAiEntry(req, res));\napp.post("/api/crm/add-entry", async (req, res) => handleCrmAiEntry(req, res));\n';
  if (source.includes(routeAnchor)) {
    source = source.replace(routeAnchor, route + routeAnchor);
    changed = true;
  } else {
    console.warn("[crm-entry-system-patch] Could not find CRM leads route anchor.");
  }
}

replaceOnce(
  '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script>',
  '<script src="/crm-demo-form.js"></script><script src="/crm-full-workflows.js"></script><script src="/crm-form-integrations.js"></script><script src="/crm-unified-entry-ui.js"></script>',
  "dashboard CRM script injection"
);

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Unified CRM entry system patch applied.");
} else {
  console.log("Unified CRM entry system patch already applied or no changes needed.");
}
