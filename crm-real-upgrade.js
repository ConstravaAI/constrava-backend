import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceOnce(search, replacement) {
  if (text.includes(replacement)) return false;
  if (!text.includes(search)) return false;
  text = text.replace(search, replacement);
  return true;
}

replaceOnce(
  'import { Pool } from "pg";',
  'import { Pool } from "pg";\nimport multer from "multer";\nimport * as XLSX from "xlsx";'
);

replaceOnce(
  'app.use(express.static(__dirname));',
  'app.use(express.static(__dirname));\n\nconst crmUpload = multer({\n  storage: multer.memoryStorage(),\n  limits: { fileSize: 8 * 1024 * 1024 },\n});'
);

const backendBlock = `
function isDemoCrmContext(token, siteId) {
  const values = [token, siteId].map((value) => String(value || "").trim().toLowerCase());
  return values.some((value) => ["demo", "preview", "sample"].includes(value));
}

async function crmContext(req) {
  const token = String(req.query.token || req.body?.token || "").trim();
  if (!token) return { error: "Missing token.", status: 400 };

  const site = await findSiteByToken(token);
  if (!site) return { error: "Site not found.", status: 404 };

  const siteId = String(valueFrom(site, ["site_id", "id"], token));
  return {
    token,
    site,
    siteId,
    demoBlocked: isDemoCrmContext(token, siteId),
  };
}

function crmBlockedMessage() {
  return "CRM writes are disabled on the public demo. Connect a real client site token to enable live CRM submissions.";
}

function cleanLeadValue(value) {
  return String(value ?? "").trim();
}

function normalizeLeadInput(input = {}) {
  const first = cleanLeadValue(input.first_name || input.firstName);
  const last = cleanLeadValue(input.last_name || input.lastName);
  const combined = [first, last].filter(Boolean).join(" ");
  return {
    name: cleanLeadValue(input.name || input.full_name || input.lead_name || combined || "New Lead"),
    email: cleanLeadValue(input.email || input.email_address || input.contact_email),
    phone: cleanLeadValue(input.phone || input.phone_number || input.mobile),
    company: cleanLeadValue(input.company || input.organization || input.business),
    status: cleanLeadValue(input.status || input.stage || "New"),
    source: cleanLeadValue(input.source || input.channel || "Manual CRM entry"),
    message: cleanLeadValue(input.message || input.notes || input.note || input.description),
    priority: cleanLeadValue(input.priority || "Normal"),
  };
}

function publicLead(row = {}) {
  return {
    name: String(valueFrom(row, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead")),
    email: String(valueFrom(row, ["email", "lead_email", "contact_email"], "")),
    phone: String(valueFrom(row, ["phone", "phone_number", "mobile"], "")),
    company: String(valueFrom(row, ["company", "organization", "business"], "—")),
    status: String(valueFrom(row, ["status", "stage", "lead_status"], "New")),
    source: String(valueFrom(row, ["source", "channel", "campaign"], "Website")),
    notes: String(valueFrom(row, ["notes", "message", "body", "description"], "")),
    created_at: String(valueFrom(row, ["created_at", "timestamp", "received_at"], "")),
  };
}

function crmSearchScore(lead, query) {
  const q = String(query || "").toLowerCase().trim();
  if (!q) return 1;

  const text = [lead.name, lead.email, lead.phone, lead.company, lead.status, lead.source, lead.notes]
    .join(" ")
    .toLowerCase();
  let score = 0;

  if (text.includes(q)) score += 80;
  for (const word of q.split(/\s+/).filter(Boolean)) {
    if (text.includes(word)) score += 8;
  }

  const status = String(lead.status || "").toLowerCase();
  const source = String(lead.source || "").toLowerCase();
  const notes = String(lead.notes || "").toLowerCase();
  const company = String(lead.company || "").toLowerCase();

  if (/ready|buy|buyer|hot|serious|qualified|proposal|close|decision|urgent/.test(q)) {
    if (/qualified|proposal|won|contacted/.test(status)) score += 35;
    if (/pricing|contact|referral|search/.test(source)) score += 18;
    if (/budget|timeline|quote|proposal|urgent|ready/.test(notes)) score += 18;
  }

  if (/new|uncontacted|fresh/.test(q) && /new/.test(status)) score += 30;
  if (/lost|dead|bad fit/.test(q) && /lost/.test(status)) score += 30;
  if (/manufacturing|factory|industrial/.test(q) && /manufacturing|factory|industrial|hvac|forge/.test(company + " " + notes)) score += 30;
  if (/fitness|gym|trainer|sports/.test(q) && /fitness|gym|trainer|sports/.test(company + " " + notes)) score += 30;
  if (/design|studio|creative|agency/.test(q) && /design|studio|creative|agency/.test(company + " " + notes)) score += 30;

  return score;
}

function importedCell(row, names) {
  const entries = Object.entries(row || {});
  for (const wanted of names) {
    const found = entries.find(([key]) => String(key).trim().toLowerCase() === wanted);
    if (found && found[1] !== undefined && found[1] !== null && String(found[1]).trim() !== "") return found[1];
  }
  for (const wanted of names) {
    const found = entries.find(([key]) => String(key).trim().toLowerCase().includes(wanted));
    if (found && found[1] !== undefined && found[1] !== null && String(found[1]).trim() !== "") return found[1];
  }
  return "";
}

function normalizeImportedLead(row) {
  return normalizeLeadInput({
    name: importedCell(row, ["name", "full name", "lead name", "contact", "contact name"]),
    email: importedCell(row, ["email", "email address", "e-mail"]),
    phone: importedCell(row, ["phone", "phone number", "mobile", "cell"]),
    company: importedCell(row, ["company", "business", "organization", "account"]),
    status: importedCell(row, ["status", "stage", "pipeline"]),
    source: importedCell(row, ["source", "channel", "campaign", "referrer"]),
    message: importedCell(row, ["message", "notes", "note", "description", "request"]),
    priority: importedCell(row, ["priority", "score"]),
  });
}

function parseCrmImport(file) {
  const workbook = XLSX.read(file.buffer, { type: "buffer" });
  const sheetName = workbook.SheetNames[0];
  if (!sheetName) return [];
  const sheet = workbook.Sheets[sheetName];
  return XLSX.utils.sheet_to_json(sheet, { defval: "" });
}

app.get("/crm/search", async (req, res) => {
  try {
    const ctx = await crmContext(req);
    if (ctx.error) return res.status(ctx.status).json({ ok: false, error: ctx.error });

    const qText = String(req.query.q || "").trim();
    const rawLeads = await getCrmLeads(ctx.siteId, 250);
    const ranked = rawLeads
      .map((row) => {
        const lead = publicLead(row);
        return { ...lead, score: crmSearchScore(lead, qText) };
      })
      .filter((lead) => !qText || lead.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 75)
      .map(({ score, ...lead }) => lead);

    res.json({ ok: true, query: qText, leads: ranked, count: ranked.length });
  } catch (err) {
    console.error("CRM SEARCH ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/crm/leads", async (req, res) => {
  try {
    const ctx = await crmContext(req);
    if (ctx.error) return res.status(ctx.status).json({ ok: false, error: ctx.error });
    if (ctx.demoBlocked) return res.status(403).json({ ok: false, error: crmBlockedMessage() });

    const lead = normalizeLeadInput(req.body || {});
    if (!lead.email && !lead.phone) {
      return res.status(400).json({ ok: false, error: "Add at least an email or phone number." });
    }

    const stored = await insertLeadRecord(ctx.siteId, {
      ...lead,
      message: [lead.message, lead.phone ? "Phone: " + lead.phone : "", lead.priority ? "Priority: " + lead.priority : ""].filter(Boolean).join("\n"),
    });
    res.json({ ok: true, stored, lead });
  } catch (err) {
    console.error("CRM LEAD CREATE ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/crm/import", crmUpload.single("file"), async (req, res) => {
  try {
    const ctx = await crmContext(req);
    if (ctx.error) return res.status(ctx.status).json({ ok: false, error: ctx.error });
    if (ctx.demoBlocked) return res.status(403).json({ ok: false, error: crmBlockedMessage() });
    if (!req.file) return res.status(400).json({ ok: false, error: "Upload a CSV or spreadsheet file." });

    const rows = parseCrmImport(req.file);
    const leads = rows.map(normalizeImportedLead).filter((lead) => lead.name || lead.email || lead.phone || lead.company);
    let inserted = 0;

    for (const lead of leads.slice(0, 500)) {
      const stored = await insertLeadRecord(ctx.siteId, {
        ...lead,
        source: lead.source || "Spreadsheet import",
        message: [lead.message, lead.phone ? "Phone: " + lead.phone : "", lead.priority ? "Priority: " + lead.priority : ""].filter(Boolean).join("\n"),
      });
      if (stored) inserted++;
    }

    res.json({
      ok: true,
      file: req.file.originalname,
      rowsFound: rows.length,
      normalized: leads.length,
      inserted,
      preview: leads.slice(0, 8),
      message: "Import processed and organized into CRM lead format.",
    });
  } catch (err) {
    console.error("CRM IMPORT ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});
`;

replaceOnce(
  'app.post("/sites", async (req, res) => {',
  backendBlock + '\napp.post("/sites", async (req, res) => {'
);

// Frontend state for CRM search/import tools.
replaceOnce(
  '    let activeSection = "home";\n    let toastTimer = null;',
  '    let activeSection = "home";\n    let crmSearchResults = null;\n    let toastTimer = null;'
);

const frontendBlock = `
    function getCrmDisplayLeads() {
      return crmSearchResults || dashboardData.leads || [];
    }

    function enhanceCrmTools() {
      const table = byId("crmTable");
      if (!table || byId("crmSearchInput")) return;

      const tableCard = table.closest(".card-inner");
      if (tableCard) {
        tableCard.insertAdjacentHTML("afterbegin", '<div class="code-box" style="background:#f8fffc;color:#064e3b;margin-bottom:14px"><input id="crmSearchInput" placeholder="AI search: people ready to buy, manufacturing leads, proposal stage..." style="flex:1;border:0;background:transparent;outline:0;color:#064e3b;min-width:220px"><button class="mini-btn" type="button" id="crmSearchBtn">AI search</button><button class="mini-btn" type="button" id="crmClearSearchBtn">Clear</button></div><div class="empty" id="crmSearchStatus" style="margin-bottom:12px">Search by keyword or ask for a type of person, like “qualified buyers” or “manufacturing leads.”</div>');
      }

      const actions = document.querySelector("#crmArea .bar-list");
      if (actions && !byId("crmAddLeadForm")) {
        actions.insertAdjacentHTML("afterbegin", '<form id="crmAddLeadForm" class="bar-list"><input name="name" placeholder="Name" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px"><input name="email" placeholder="Email" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px"><input name="phone" placeholder="Phone" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px"><input name="company" placeholder="Company" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px"><select name="status" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px"><option>New</option><option>Contacted</option><option>Qualified</option><option>Proposal</option><option>Won</option><option>Lost</option></select><textarea name="message" placeholder="Notes / request" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px;min-height:82px"></textarea><button class="btn" type="submit">Add real CRM lead</button><div class="empty">Disabled on /dashboard?token=demo. Ready for real client site tokens.</div></form><form id="crmImportForm" class="bar-list" style="margin-top:16px"><input id="crmImportFile" name="file" type="file" accept=".csv,.xlsx,.xls" style="padding:12px;border:1px solid #dbe8e4;border-radius:12px;background:white"><button class="btn" type="submit">Import spreadsheet</button><div class="empty" id="crmImportStatus">Upload CSV/XLSX to organize rows into CRM lead fields.</div></form>');
      }
    }

    function wireCrmTools() {
      const searchBtn = byId("crmSearchBtn");
      if (searchBtn && !searchBtn.dataset.wired) {
        searchBtn.dataset.wired = "true";
        searchBtn.addEventListener("click", runCrmSearch);
      }

      const searchInput = byId("crmSearchInput");
      if (searchInput && !searchInput.dataset.wired) {
        searchInput.dataset.wired = "true";
        searchInput.addEventListener("keydown", function(event) {
          if (event.key === "Enter") runCrmSearch();
        });
      }

      const clearBtn = byId("crmClearSearchBtn");
      if (clearBtn && !clearBtn.dataset.wired) {
        clearBtn.dataset.wired = "true";
        clearBtn.addEventListener("click", function() {
          crmSearchResults = null;
          if (byId("crmSearchInput")) byId("crmSearchInput").value = "";
          if (byId("crmSearchStatus")) byId("crmSearchStatus").textContent = "Showing all CRM leads.";
          renderCrm();
        });
      }

      const addForm = byId("crmAddLeadForm");
      if (addForm && !addForm.dataset.wired) {
        addForm.dataset.wired = "true";
        addForm.addEventListener("submit", submitCrmLead);
      }

      const importForm = byId("crmImportForm");
      if (importForm && !importForm.dataset.wired) {
        importForm.dataset.wired = "true";
        importForm.addEventListener("submit", submitCrmImport);
      }
    }

    async function runCrmSearch() {
      const input = byId("crmSearchInput");
      const status = byId("crmSearchStatus");
      const query = input ? input.value.trim() : "";
      if (!query) {
        crmSearchResults = null;
        renderCrm();
        return;
      }
      if (status) status.textContent = "Searching CRM with AI-style matching...";
      try {
        const response = await fetch("/crm/search?token=" + encodeURIComponent(token) + "&q=" + encodeURIComponent(query));
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "CRM search failed.");
        crmSearchResults = data.leads || [];
        renderCrm();
        if (status) status.textContent = "Found " + crmSearchResults.length + " matching leads for: " + query;
      } catch (err) {
        if (status) status.textContent = err.message || "CRM search failed.";
        toast(err.message || "CRM search failed.");
      }
    }

    async function submitCrmLead(event) {
      event.preventDefault();
      const form = event.currentTarget;
      const payload = Object.fromEntries(new FormData(form).entries());
      try {
        const response = await fetch("/crm/leads?token=" + encodeURIComponent(token), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "Could not add lead.");
        form.reset();
        crmSearchResults = null;
        await refreshData(true);
        switchSide("crm");
        toast("CRM lead added.");
      } catch (err) {
        toast(err.message || "Could not add lead.");
      }
    }

    async function submitCrmImport(event) {
      event.preventDefault();
      const form = event.currentTarget;
      const status = byId("crmImportStatus");
      const formData = new FormData(form);
      try {
        if (status) status.textContent = "Uploading and organizing file...";
        const response = await fetch("/crm/import?token=" + encodeURIComponent(token), {
          method: "POST",
          body: formData,
        });
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "Import failed.");
        crmSearchResults = null;
        await refreshData(true);
        switchSide("crm");
        if (status) status.textContent = "Imported " + data.inserted + " leads from " + data.file + ".";
        toast("Spreadsheet import complete.");
      } catch (err) {
        if (status) status.textContent = err.message || "Import failed.";
        toast(err.message || "Import failed.");
      }
    }
`;

replaceOnce(
  '    function renderCrm() {',
  frontendBlock + '\n    function renderCrm() {'
);

replaceOnce(
  '      const leads = dashboardData.leads || [];\n      if (!leads.length) {',
  '      enhanceCrmTools();\n      wireCrmTools();\n      const leads = getCrmDisplayLeads();\n      if (!leads.length) {'
);

fs.writeFileSync(target, text);
console.log("Prepared server.js with real CRM entry, AI-style search, and spreadsheet import tools.");
