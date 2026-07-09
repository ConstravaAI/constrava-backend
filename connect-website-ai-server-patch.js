import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverPath = path.join(__dirname, "server.js");
let server = fs.readFileSync(serverPath, "utf8");
let serverChanged = false;

if (!server.includes('/api/connect-website-guide/chat')) {
  const marker = 'app.get("/analytics/install", (req, res) => {';
  const insert = `
function connectWebsiteFallback(message = "", step = {}) {
  const lower = String(message || "").toLowerCase();
  if (lower.includes("squarespace")) return "For Squarespace, open Settings, go to Code Injection, paste the install line into Footer, save, then visit the live site once.";
  if (lower.includes("wordpress")) return "For WordPress, use a trusted header/footer tool or your theme footer area. Paste the install line once so it appears on every page.";
  if (lower.includes("shopify")) return "For Shopify, start with your theme or custom-code setup. A deeper app-style pixel can come later.";
  if (lower.includes("where") || lower.includes("paste")) return "Look for a site-wide custom code, footer code, header/footer, code injection, tag manager, or theme code area. The goal is to load the install line on every public page.";
  if (lower.includes("verify") || lower.includes("test")) return "After saving, open the live site in a private window. Then return to Constrava and look for a recent page view for this site.";
  return "I can help with that. You are on: " + String(step.title || "Connect a Website") + ". Tell me your website platform, and I will keep the next step simple.";
}

async function connectWebsiteAiReply({ message, step, token }) {
  if (!process.env.OPENAI_API_KEY) return connectWebsiteFallback(message, step);
  const prompt = [
    "You are Constrava's friendly website connection partner.",
    "Help a non-technical business user install a website analytics snippet without feeling overwhelmed.",
    "Keep replies short, calm, official, and step-by-step.",
    "Current step: " + JSON.stringify(step || {}),
    "Dashboard token label: " + String(token || "demo"),
    "User question: " + String(message || "")
  ].join("\\n");
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { "Authorization": "Bearer " + process.env.OPENAI_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ model: process.env.CONNECT_GUIDE_MODEL || process.env.OPENAI_MODEL || "gpt-4o-mini", input: prompt, max_output_tokens: 220 })
    });
    const data = await response.json();
    if (!response.ok) return connectWebsiteFallback(message, step);
    const text = data.output_text || (Array.isArray(data.output) ? data.output.flatMap((item) => item.content || []).map((part) => part.text || "").join(" ") : "");
    return String(text || connectWebsiteFallback(message, step)).trim().slice(0, 1200);
  } catch {
    return connectWebsiteFallback(message, step);
  }
}

app.post("/api/connect-website-guide/chat", requireAuth, async (req, res) => {
  try {
    const message = String(req.body?.message || "").slice(0, 1200);
    const step = req.body?.step && typeof req.body.step === "object" ? req.body.step : {};
    const token = String(req.body?.token || req.query.token || "demo");
    const reply = await connectWebsiteAiReply({ message, step, token });
    res.json({ ok: true, reply });
  } catch (err) {
    res.status(500).json({ ok: false, reply: connectWebsiteFallback(req.body?.message || "", req.body?.step || {}), error: err.message || "Guide chat failed." });
  }
});

`;
  if (!server.includes(marker)) throw new Error("Could not find analytics install route marker in server.js");
  server = server.replace(marker, insert + marker);
  serverChanged = true;
  console.log("connect website AI guide endpoint patched into server.js");
} else {
  console.log("connect website AI guide endpoint already present");
}

if (!server.includes('/api/ai/record-sort')) {
  const marker = 'app.get("/analytics/install", (req, res) => {';
  const insert = `
function safeJsonTextParse(text, fallback = null) {
  try { return JSON.parse(String(text || "")); } catch {}
  const match = String(text || "").match(/\\{[\\s\\S]*\\}/);
  if (match) { try { return JSON.parse(match[0]); } catch {} }
  return fallback;
}
function titleCaseWords(value = "") {
  return String(value || "").trim().replace(/\\s+/g, " ").replace(/\\b\\w/g, (char) => char.toUpperCase());
}
function inferRecordModule(type = "lead") {
  const clean = String(type || "lead").toLowerCase();
  if (clean.includes("sale") || clean.includes("deal")) return "sales";
  if (clean.includes("person") || clean.includes("contact")) return "people";
  if (clean.includes("company") || clean.includes("account")) return "companies";
  if (clean.includes("task") || clean.includes("todo") || clean.includes("follow")) return "tasks";
  if (clean.includes("note")) return "notes";
  return "leads";
}
function normalizeSortedRecord(raw = {}, sourceType = "ai") {
  const now = new Date().toISOString();
  const type = String(raw.record_type || raw.type || raw.kind || raw.category || "lead").toLowerCase().replace(/[^a-z0-9_]+/g, "_");
  const module = String(raw.module || inferRecordModule(type));
  const value = Number(String(raw.value || raw.deal_value || raw.amount || raw.budget || 0).replace(/[$,]/g, "")) || 0;
  const status = String(raw.status || raw.stage || (module === "sales" ? "Proposal" : module === "tasks" ? "New" : module === "notes" ? "Saved" : module === "people" || module === "companies" ? "Active" : "New"));
  const probability = Number(raw.probability ?? (status === "Closed Won" ? 100 : status === "Negotiation" ? 80 : status === "Proposal" ? 60 : status === "Qualified" ? 40 : status === "Needs Analysis" ? 20 : status === "Closed Lost" ? 0 : 10));
  const name = String(raw.name || raw.full_name || raw.lead_name || raw.contact_name || raw.company || raw.email || "New Record");
  const company = String(raw.company || raw.organization || raw.account_name || (module === "companies" ? name : "—"));
  const recordId = String(raw.record_id || raw.id || raw.lead_id || makeToken("rec"));
  return {
    ...raw,
    id: recordId,
    record_id: recordId,
    lead_id: String(raw.lead_id || recordId),
    record_type: type,
    module,
    record_schema: String(raw.record_schema || titleCaseWords(type.replace(/_/g, " "))),
    name,
    email: String(raw.email || raw.lead_email || raw.contact_email || ""),
    phone: String(raw.phone || raw.phone_number || raw.mobile || ""),
    company,
    status,
    stage: status,
    source: String(raw.source || sourceType || "AI Record Sorter"),
    deal_name: String(raw.deal_name || raw.opportunity || raw.project || raw.subject || ""),
    value,
    probability,
    expected_revenue: Number(raw.expected_revenue || Math.round(value * probability / 100)) || 0,
    priority: String(raw.priority || (value >= 7500 ? "High" : "Normal")),
    notes: String(raw.notes || raw.message || raw.body || raw.description || raw.summary || ""),
    created_at: String(raw.created_at || now),
    updated_at: now,
    ai_sorted: true,
    ai_source_type: sourceType
  };
}
function fallbackAiRecordSort({ input, sourceType = "fallback", preferredType = "lead", context = {} }) {
  const text = typeof input === "string" ? input : JSON.stringify(input || {});
  const email = (text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}/i) || [""])[0];
  const phone = (text.match(/(?:\\+?1[\\s.-]?)?(?:\\(?\\d{3}\\)?[\\s.-]?)\\d{3}[\\s.-]?\\d{4}/) || [""])[0];
  const valueMatch = text.replace(/,/g, "").match(/\\$?\\b(\\d{3,8})\\b/);
  const value = valueMatch ? Number(valueMatch[1]) : 0;
  const nameMatch = text.match(/(?:named|name is|lead is|called|contact is)\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+){0,2})/) || text.match(/^([A-Z][a-z]+(?:\\s+[A-Z][a-z]+){0,2})\\s+from\\s+/);
  const companyMatch = text.match(/from\\s+([A-Z][A-Za-z0-9& .-]{2,60})(?:\\s+(?:wants|needs|asked|is|and|with|for)|[.,]|$)/) || text.match(/company\\s+(?:is|=)\\s+([A-Z][A-Za-z0-9& .-]{2,60})/i);
  const type = String(preferredType || (sourceType.includes("form") ? "lead" : "lead"));
  const status = /closed won|signed|paid/i.test(text) ? "Closed Won" : /lost|not interested/i.test(text) ? "Closed Lost" : /negotiation/i.test(text) ? "Negotiation" : /proposal|quote|estimate/i.test(text) ? "Proposal" : /qualified|serious|ready/i.test(text) ? "Qualified" : /analysis|discovery|meeting/i.test(text) ? "Needs Analysis" : "New";
  const company = companyMatch ? companyMatch[1].trim() : String(context.siteSlug || context.formSlug || "—");
  return [normalizeSortedRecord({
    record_type: type,
    module: inferRecordModule(type),
    name: nameMatch ? nameMatch[1].trim() : (email ? titleCaseWords(email.split("@")[0].replace(/[._-]+/g, " ")) : (company !== "—" ? company + " inquiry" : "New Record")),
    email,
    phone,
    company,
    status,
    source: sourceType || "Fallback Sorter",
    value,
    deal_name: value ? (company !== "—" ? company + " opportunity" : "Potential opportunity") : "",
    notes: text,
    raw_input: input
  }, sourceType)];
}
function buildRecordSortPrompt({ input, sourceType, preferredType, context }) {
  return [
    "You are Constrava's AI CRM record sorting system.",
    "Turn incoming business data into clean CRM records. Incoming data may be plain text, form submissions, email text, calendar notes, invoices, or connected app payloads.",
    "Return ONLY valid JSON. No markdown. No commentary.",
    "JSON shape: {\\"records\\":[{...}]}",
    "Allowed modules: leads, people, companies, tasks, sales, notes.",
    "Use record_type values like lead, person, company, task, sale, note.",
    "Every record should include: record_type, module, name, email, phone, company, status, source, value, probability, priority, deal_name, notes.",
    "If a submission implies multiple records, return multiple records. Example: a lead plus a follow-up task plus a note.",
    "Prefer the user's selected type when it makes sense. Selected type: " + String(preferredType || "auto"),
    "Source type: " + String(sourceType || "unknown"),
    "Context: " + JSON.stringify(context || {}),
    "Input: " + (typeof input === "string" ? input : JSON.stringify(input || {}))
  ].join("\\n");
}
async function sortRecordsWithAi({ input, sourceType = "plain_text", preferredType = "auto", context = {} }) {
  const fallback = fallbackAiRecordSort({ input, sourceType, preferredType, context });
  if (!process.env.OPENAI_API_KEY) return { ok: true, ai: false, fallback: true, records: fallback, error: "OPENAI_API_KEY is not configured." };
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { "Authorization": "Bearer " + process.env.OPENAI_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ model: process.env.RECORD_SORT_MODEL || process.env.OPENAI_MODEL || "gpt-4o-mini", input: buildRecordSortPrompt({ input, sourceType, preferredType, context }), max_output_tokens: 1400 })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || data.error || "OpenAI record sorting failed.");
    const text = data.output_text || (Array.isArray(data.output) ? data.output.flatMap((item) => item.content || []).map((part) => part.text || "").join(" ") : "");
    const parsed = safeJsonTextParse(text, null);
    const rawRecords = Array.isArray(parsed?.records) ? parsed.records : (Array.isArray(parsed) ? parsed : []);
    const records = rawRecords.map((record) => normalizeSortedRecord(record, sourceType)).filter((record) => record.name || record.email || record.company || record.notes);
    if (!records.length) return { ok: true, ai: false, fallback: true, records: fallback, error: "AI returned no usable records." };
    return { ok: true, ai: true, fallback: false, records };
  } catch (err) {
    return { ok: true, ai: false, fallback: true, records: fallback, error: err.message || "AI record sorting failed." };
  }
}
async function sortFormLeadWithAi(body, siteSlug, formSlug, req) {
  const sorted = await sortRecordsWithAi({ input: body || {}, sourceType: "form_submission", preferredType: "lead", context: { siteSlug, formSlug, provider: req.get("x-form-provider") || "External Form" } });
  const lead = normalizeSortedRecord(sorted.records[0] || {}, "form_submission");
  return { ...lead, lead_id: lead.lead_id || lead.record_id, site_id: siteSlug, site_slug: siteSlug, form_slug: formSlug, dashboard_token: String(lead.dashboard_token || body?.dashboard_token || body?.token || siteSlug), raw_submission: body, ai_sort: { ai: sorted.ai, fallback: sorted.fallback, error: sorted.error || null, records_created: sorted.records.length } };
}

app.post("/api/ai/record-sort", requireAuth, async (req, res) => {
  try {
    const input = req.body?.input ?? req.body?.text ?? req.body?.payload ?? "";
    const sourceType = String(req.body?.source_type || req.body?.sourceType || "plain_text").slice(0, 80);
    const preferredType = String(req.body?.record_type || req.body?.preferred_type || req.body?.type || "auto").slice(0, 40);
    const context = req.body?.context && typeof req.body.context === "object" ? req.body.context : {};
    const sorted = await sortRecordsWithAi({ input, sourceType, preferredType, context: { ...context, user: req.user?.email || "" } });
    res.json(sorted);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "Record sorting failed." });
  }
});

`;
  if (!server.includes(marker)) throw new Error("Could not find analytics install route marker in server.js");
  server = server.replace(marker, insert + marker);
  serverChanged = true;
  console.log("AI record sorter endpoint patched into server.js");
} else {
  console.log("AI record sorter endpoint already present");
}

const formRouteSearch = 'const lead = normalizeFormLead(req.body || {}, siteSlug, formSlug, req); const crmStored = await insertCrmLead(siteSlug, lead);';
const formRouteReplacement = 'const lead = await sortFormLeadWithAi(req.body || {}, siteSlug, formSlug, req); const crmStored = await insertCrmLead(siteSlug, lead);';
if (server.includes(formRouteSearch) && !server.includes(formRouteReplacement)) {
  server = server.replace(formRouteSearch, formRouteReplacement);
  serverChanged = true;
  console.log("form intake route now uses AI record sorting");
}

if (serverChanged) fs.writeFileSync(serverPath, server);

const guidePath = path.join(__dirname, "connect-website-guide.js");
if (fs.existsSync(guidePath)) {
  let guide = fs.readFileSync(guidePath, "utf8");
  let changed = false;
  function quietReplace(search, replacement) {
    if (!guide.includes(search)) return;
    guide = guide.replace(search, replacement);
    changed = true;
  }

  quietReplace(
    "'.side-tools{margin-top:auto;padding-top:22px;display:grid;gap:8px}'",
    "'.side-tools{margin-top:auto;padding-top:18px;display:grid;gap:4px;border-top:1px solid rgba(236,253,245,.12)}'"
  );
  quietReplace(
    "'.side-tool{width:100%;border:0;border-radius:15px;padding:13px 14px;text-align:left;font-weight:900;text-decoration:none;color:rgba(236,253,245,.9);background:rgba(255,255,255,.08)}'",
    "'.side-tool{width:100%;border:0;border-radius:10px;padding:8px 10px;text-align:left;font-size:12px;font-weight:800;text-decoration:none;color:rgba(236,253,245,.62);background:transparent;box-shadow:none}'"
  );
  quietReplace(
    "'.side-tool:hover,.side-tool.active{background:linear-gradient(90deg,rgba(16,185,129,.32),rgba(255,255,255,.12));box-shadow:inset 3px 0 0 #12f7a3}'",
    "'.side-tool:hover,.side-tool.active{color:rgba(236,253,245,.92);background:rgba(255,255,255,.06);box-shadow:none}'"
  );
  quietReplace(
    "'.side-tool.signout{color:#fed7aa;background:rgba(251,146,60,.1)}'",
    "'.side-tool.signout{color:rgba(254,215,170,.68);background:transparent}'"
  );

  if (!guide.includes("aiRecordSortingOverride")) {
    const override = `

  ready(function aiRecordSortingOverride() {
    var pendingRecords = [];
    function byId(id) { return document.getElementById(id); }
    function htmlEscape(value) { return escapeHtml(value); }
    function money(value) {
      try { return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(Number(value || 0)); }
      catch { return '$' + String(value || 0); }
    }
    function preview(records) {
      if (!records.length) return '<div class="hint">No records found yet.</div>';
      return '<div class="panel records"><table><thead><tr><th>Record</th><th>Type</th><th>Status</th><th>Value</th><th>Source</th></tr></thead><tbody>' + records.map(function (record) {
        return '<tr><td><b>' + htmlEscape(record.name || 'New Record') + '</b><span class="mini">' + htmlEscape(record.email || record.phone || record.company || '') + '</span></td><td><span class="pill">' + htmlEscape(record.record_schema || record.record_type || 'Record') + '</span></td><td>' + htmlEscape(record.status || 'New') + '</td><td>' + money(record.value) + '</td><td>' + htmlEscape(record.source || 'AI') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
    }
    async function sortFromIntake() {
      var box = byId('bulkAddText');
      var type = byId('recordTypeSelect');
      var previewBox = byId('addPreview');
      var input = box ? box.value.trim() : '';
      if (!input) {
        pendingRecords = [];
        if (previewBox) previewBox.innerHTML = '<div class="hint">Paste record data first.</div>';
        return [];
      }
      if (previewBox) previewBox.innerHTML = '<div class="hint">AI is sorting this into CRM records...</div>';
      try {
        var response = await fetch('/api/ai/record-sort', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ input: input, source_type: 'plain_text_add_record', record_type: type ? type.value : 'auto', context: { page: 'dashboard_add_records' } })
        });
        var data = await response.json();
        if (!response.ok || !data.ok) throw new Error(data.error || 'AI record sorting failed.');
        pendingRecords = Array.isArray(data.records) ? data.records : [];
        if (previewBox) previewBox.innerHTML = preview(pendingRecords);
        if (window.toast) window.toast((data.ai ? 'AI sorted ' : 'Fallback sorted ') + pendingRecords.length + ' record(s)');
        return pendingRecords;
      } catch (err) {
        pendingRecords = [];
        if (previewBox) previewBox.innerHTML = '<div class="hint">AI sorting failed. Try again or save manually. ' + htmlEscape(err.message || '') + '</div>';
        if (window.toast) window.toast('AI sorting failed');
        return [];
      }
    }
    async function saveSorted() {
      if (!pendingRecords.length) await sortFromIntake();
      if (!pendingRecords.length) return;
      var target = pendingRecords[0].module || 'leads';
      if (window.saveSession) pendingRecords.forEach(function (record) { window.saveSession(record); });
      if (window.toast) window.toast(pendingRecords.length + ' AI sorted record(s) saved');
      pendingRecords = [];
      if (window.renderCRM) window.renderCRM(target);
    }
    document.addEventListener('click', function (event) {
      var target = event.target && event.target.closest ? event.target.closest('#analyzeRecordsBtn,#saveSortedRecordsBtn') : null;
      if (!target) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      if (target.id === 'analyzeRecordsBtn') sortFromIntake();
      if (target.id === 'saveSortedRecordsBtn') saveSorted();
    }, true);
  });
`;
    guide = guide.replace(/\n\}\)\(\);\s*$/, override + "\n})();\n");
    changed = true;
    console.log("dashboard Add Records now calls AI record sorter");
  }

  if (changed) {
    fs.writeFileSync(guidePath, guide);
    console.log("connect website guide patched");
  } else {
    console.log("connect website guide already patched");
  }
}
