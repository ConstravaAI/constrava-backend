import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceOnce(search, replacement) {
  if (text.includes(replacement)) return false;
  if (!text.includes(search)) return false;
  text = text.replace(search, replacement);
  return true;
}

function replaceRegex(pattern, replacement) {
  const before = text;
  text = text.replace(pattern, replacement);
  return text !== before;
}

const css = String.raw`

    /* Modern CRM reset: pipeline-first, read-only search, explicit write actions */
    .crm-modern-shell { display: grid; gap: 18px; }
    .crm-hero {
      border: 1px solid rgba(16,185,129,.20);
      border-radius: 30px;
      padding: 22px;
      background:
        radial-gradient(circle at 100% 0%, rgba(16,185,129,.20), transparent 32%),
        linear-gradient(135deg, rgba(255,255,255,.98), rgba(236,253,245,.80));
      box-shadow: var(--shadow);
    }
    .crm-hero-top { display:flex; justify-content:space-between; gap:18px; align-items:flex-start; margin-bottom:16px; }
    .crm-hero h2 { margin:0; color:#073d32; letter-spacing:-.04em; font-size:30px; }
    .crm-hero p { margin:7px 0 0; color:var(--muted); line-height:1.55; }
    .crm-badge { display:inline-flex; align-items:center; gap:8px; border:1px solid rgba(4,120,87,.18); border-radius:999px; padding:8px 11px; background:#ecfdf5; color:#047857; font-weight:950; font-size:12px; white-space:nowrap; }
    .crm-search-line { display:grid; grid-template-columns:1fr auto auto; gap:10px; align-items:center; }
    .crm-field, .crm-select, .crm-textarea { width:100%; border:1px solid #dbe8e4; border-radius:14px; padding:12px 13px; background:#fff; color:#073d32; outline:0; }
    .crm-field:focus, .crm-select:focus, .crm-textarea:focus { border-color:#10b981; box-shadow:0 0 0 4px rgba(16,185,129,.12); }
    .crm-help { margin-top:12px; color:var(--muted); padding:12px 14px; border:1px dashed #b9ddd0; background:rgba(248,255,252,.80); border-radius:16px; line-height:1.5; }
    .crm-kpis { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }
    .crm-kpi { border:1px solid #dbe8e4; border-radius:22px; padding:16px; background:rgba(255,255,255,.92); box-shadow:0 12px 28px rgba(15,23,42,.06); }
    .crm-kpi span { display:block; color:var(--muted); font-size:12px; font-weight:850; text-transform:uppercase; letter-spacing:.08em; }
    .crm-kpi strong { display:block; margin-top:8px; color:#073d32; font-size:29px; letter-spacing:-.05em; }
    .crm-board { display:grid; grid-template-columns:1.25fr .85fr; gap:18px; align-items:start; }
    .crm-tabs { display:flex; flex-wrap:wrap; gap:8px; margin:14px 0 16px; }
    .crm-tab { border:1px solid #dbe8e4; border-radius:999px; padding:9px 12px; background:white; color:#064e3b; font-weight:950; font-size:13px; }
    .crm-tab.active { background:#064e3b; border-color:#064e3b; color:#d1fae5; }
    .crm-list { display:grid; gap:12px; }
    .crm-card { display:grid; grid-template-columns:1fr auto; gap:14px; border:1px solid #dbe8e4; border-radius:22px; padding:16px; background:linear-gradient(180deg,#fff,#f8fffc); box-shadow:0 12px 26px rgba(15,23,42,.05); }
    .crm-card h3 { margin:0; color:#073d32; letter-spacing:-.03em; }
    .crm-card p { margin:7px 0 0; color:#475569; line-height:1.45; }
    .crm-tags { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
    .crm-tag { display:inline-flex; align-items:center; border-radius:999px; padding:6px 9px; background:#f1f5f9; color:#475569; font-size:12px; font-weight:850; }
    .crm-tag.green { background:#dcfce7; color:#047857; }
    .crm-card-actions { display:grid; gap:8px; align-self:start; min-width:130px; }
    .crm-panel-stack { display:grid; gap:18px; }
    .crm-form-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    .crm-form-grid .full { grid-column:1 / -1; }
    .crm-upload { border:1px dashed #9bd9c3; border-radius:18px; padding:16px; background:#f8fffc; }
    .crm-note { font-size:13px; color:var(--muted); line-height:1.55; }
    @media (max-width: 980px) {
      .crm-board, .crm-kpis, .crm-search-line, .crm-form-grid { grid-template-columns:1fr; }
      .crm-hero-top, .crm-card { display:grid; grid-template-columns:1fr; }
      .crm-card-actions { grid-template-columns:1fr 1fr; }
    }
`;

if (!text.includes("Modern CRM reset")) {
  text = text.replace("    @media (max-width: 1180px) {", css + "\n    @media (max-width: 1180px) {");
}

const crmMarkup = String.raw`        <div id="crmArea" style="display:none">
          <section class="section-page active">
            <div class="crm-modern-shell">
              <div class="crm-hero">
                <div class="crm-hero-top">
                  <div>
                    <h2>Client CRM</h2>
                    <p>Manage leads like a real sales workspace: search by intent, filter pipeline stages, inspect lead context, add records, and import spreadsheets.</p>
                  </div>
                  <div class="crm-badge">Search is read-only • Writes are manual only</div>
                </div>
                <div class="crm-search-line">
                  <input class="crm-field" id="crmSearchInput" autocomplete="off" placeholder="Try: manufacturing leads, ready buyers, proposal stage, tech companies...">
                  <button class="btn" type="button" id="crmSearchBtn"><span data-icon="sparkles"></span> Smart search</button>
                  <button class="mini-btn" type="button" id="crmClearSearchBtn">Clear</button>
                </div>
                <div class="crm-help" id="crmSearchStatus">Smart search checks company, industry words, status, source, and notes. It never creates leads.</div>
              </div>

              <div class="crm-kpis" id="crmSummaryCards"></div>

              <div class="crm-board">
                <article class="card">
                  <div class="card-inner">
                    <div class="card-title">
                      <div><h2>Pipeline</h2><p>Focus the list by stage, then open the leads that need action.</p></div>
                      <button class="mini-btn" type="button" data-explain="crm"><span data-icon="sparkles"></span> AI explain</button>
                    </div>
                    <div class="crm-tabs" id="crmStageFilters"></div>
                    <div class="crm-list" id="crmLeadList"></div>
                  </div>
                </article>

                <div class="crm-panel-stack">
                  <article class="card">
                    <div class="card-inner">
                      <div class="card-title"><div><h2>Add lead</h2><p>Explicit manual entry for real client sites. The public demo remains blocked for CRM writes.</p></div></div>
                      <form id="crmAddLeadForm" class="bar-list">
                        <div class="crm-form-grid">
                          <input class="crm-field" name="name" placeholder="Name">
                          <input class="crm-field" name="email" placeholder="Email">
                          <input class="crm-field" name="phone" placeholder="Phone">
                          <input class="crm-field" name="company" placeholder="Company">
                          <select class="crm-select full" name="status"><option>New</option><option>Contacted</option><option>Qualified</option><option>Proposal</option><option>Won</option><option>Lost</option></select>
                          <textarea class="crm-textarea full" name="message" placeholder="Notes, request, budget, timeline"></textarea>
                        </div>
                        <button class="btn" type="submit">Add lead manually</button>
                        <div class="crm-note">This is the only button that creates a lead. Search and filters are read-only.</div>
                      </form>
                    </div>
                  </article>

                  <article class="card">
                    <div class="card-inner">
                      <div class="card-title"><div><h2>Import spreadsheet</h2><p>Upload CSV/XLSX and map messy columns into lead fields.</p></div></div>
                      <form id="crmImportForm" class="bar-list">
                        <div class="crm-upload"><input id="crmImportFile" name="file" type="file" accept=".csv,.xlsx,.xls"></div>
                        <button class="btn" type="submit">Import and organize</button>
                        <div class="crm-help" id="crmImportStatus">Looks for columns like Full Name, Email Address, Business, Stage, Source, Notes, and Phone.</div>
                      </form>
                    </div>
                  </article>

                  <article class="card">
                    <div class="card-inner">
                      <div class="card-title"><div><h2>Smart actions</h2><p>Quick guidance for follow-up and qualification.</p></div></div>
                      <div class="bar-list">
                        <button class="btn" type="button" data-explain="followup">Draft follow-up strategy</button>
                        <button class="btn" type="button" data-explain="qualify">Explain lead quality</button>
                        <button class="btn" type="button" data-explain="pipeline">Summarize pipeline</button>
                      </div>
                    </div>
                  </article>
                </div>
              </div>
            </div>
          </section>
        </div>`;

replaceRegex(/        <div id="crmArea" style="display:none">[\s\S]*?          <\/section>\n        <\/div>/, crmMarkup);

replaceOnce(
  '    let crmStatusFilter = "all";\n    let toastTimer = null;',
  '    let crmStatusFilter = "all";\n    let crmSelectedLeadIndex = null;\n    let toastTimer = null;'
);
replaceOnce(
  '    let crmSearchResults = null;\n    let toastTimer = null;',
  '    let crmSearchResults = null;\n    let crmStatusFilter = "all";\n    let crmSelectedLeadIndex = null;\n    let toastTimer = null;'
);

const crmClient = String.raw`
    function crmBaseLeads() {
      return (dashboardData.leads || []).map(function(lead) {
        return Object.assign({ name: "New Lead", email: "", phone: "", company: "—", status: "New", source: "Website", notes: "" }, lead || {});
      });
    }

    function crmWorkingLeads() {
      return crmSearchResults || crmBaseLeads();
    }

    function crmStatus(lead) {
      return String((lead && (lead.status || lead.stage)) || "New");
    }

    function crmStageKey(value) {
      return String(value || "new").toLowerCase().replace(/\s+/g, "-");
    }

    function crmStages() {
      return ["all", "new", "contacted", "qualified", "proposal", "won", "lost"];
    }

    function crmCounts() {
      const leads = crmWorkingLeads();
      const counts = { all: leads.length, new: 0, contacted: 0, qualified: 0, proposal: 0, won: 0, lost: 0 };
      leads.forEach(function(lead) {
        const key = crmStageKey(crmStatus(lead));
        counts[key] = (counts[key] || 0) + 1;
      });
      return counts;
    }

    function crmVisibleLeads() {
      const leads = crmWorkingLeads();
      if (crmStatusFilter === "all") return leads;
      return leads.filter(function(lead) { return crmStageKey(crmStatus(lead)) === crmStatusFilter; });
    }

    function crmSearchScore(lead, rawQuery) {
      const q = String(rawQuery || "").toLowerCase().trim();
      if (!q) return 1;
      const text = [lead.name, lead.email, lead.phone, lead.company, lead.status, lead.source, lead.notes, lead.message]
        .join(" ")
        .toLowerCase();
      const generic = new Set(["lead", "leads", "person", "people", "client", "clients", "customer", "customers", "company", "companies", "business", "businesses", "show", "find", "type", "types", "of", "the", "a", "an", "me"]);
      const words = q.split(/\s+/).map(function(word) { return word.replace(/[^a-z0-9]/g, ""); }).filter(function(word) { return word && !generic.has(word); });
      let score = 0;
      if (text.includes(q)) score += 120;
      words.forEach(function(word) { if (text.includes(word)) score += 25; });

      const groups = [
        { query: ["manufacturing", "factory", "industrial", "warehouse", "machine", "production"], match: ["manufacturing", "factory", "industrial", "warehouse", "machine", "machining", "production", "hvac", "forge", "fabrication", "maintenance"] },
        { query: ["fitness", "gym", "trainer", "sports", "athlete"], match: ["fitness", "gym", "trainer", "sports", "athlete", "wellness", "boxing", "martial"] },
        { query: ["design", "studio", "creative", "agency", "brand"], match: ["design", "studio", "creative", "agency", "brand", "marketing", "media"] },
        { query: ["tech", "software", "saas", "ai", "data", "lab"], match: ["tech", "software", "saas", "ai", "data", "lab", "labs", "startup", "app"] },
        { query: ["contractor", "construction", "service", "local", "home"], match: ["contractor", "construction", "service", "local", "home", "plumbing", "roofing", "repair", "hvac"] }
      ];

      groups.forEach(function(group) {
        const askingForGroup = group.query.some(function(term) { return q.includes(term); });
        const matchesGroup = group.match.some(function(term) { return text.includes(term); });
        if (askingForGroup && matchesGroup) score += 100;
      });

      const statusText = String(lead.status || "").toLowerCase();
      const intentText = text + " " + statusText;
      if (/ready|buyer|buyers|buy|hot|serious|qualified|proposal|close|decision|urgent|best|high/.test(q)) {
        if (/qualified|proposal|won|contacted/.test(statusText)) score += 70;
        if (/budget|timeline|quote|proposal|urgent|ready|pricing|purchase/.test(intentText)) score += 35;
      }
      if (/new|fresh|uncontacted/.test(q) && /new/.test(statusText)) score += 70;
      if (/proposal|quote|estimate/.test(q) && /proposal/.test(intentText)) score += 70;
      if (/won|closed/.test(q) && /won/.test(statusText)) score += 70;
      if (/lost|dead|bad/.test(q) && /lost/.test(statusText)) score += 70;
      return score;
    }

    function crmLeadCardHtml(lead, index) {
      const email = String(lead.email || "");
      const phone = String(lead.phone || "");
      const company = String(lead.company || "—");
      const source = String(lead.source || "Website");
      const status = crmStatus(lead);
      const notes = String(lead.notes || lead.message || "No notes yet.");
      return '<div class="crm-card">' +
        '<div><h3>' + escapeHtml(lead.name || "New Lead") + '</h3>' +
        '<p>' + escapeHtml(company) + (email ? ' • ' + escapeHtml(email) : '') + (phone ? ' • ' + escapeHtml(phone) : '') + '</p>' +
        '<div class="crm-tags"><span class="crm-tag green">' + escapeHtml(status) + '</span><span class="crm-tag">' + escapeHtml(source) + '</span><span class="crm-tag">Lead #' + (index + 1) + '</span></div>' +
        '<p style="margin-top:12px">' + escapeHtml(notes).slice(0, 190) + '</p></div>' +
        '<div class="crm-card-actions"><button class="mini-btn" type="button" data-crm-view="' + index + '">View</button><button class="mini-btn" type="button" data-crm-follow="' + index + '">Follow-up</button></div>' +
      '</div>';
    }

    function crmOpenLead(index, mode) {
      const lead = crmVisibleLeads()[Number(index)] || {};
      const body = mode === "follow"
        ? "Suggested next step: respond quickly, reference their company/context, ask one qualifying question, and offer a short call or next action."
        : "Lead details and context from the CRM pipeline.";
      const detail = '<div class="bar-list">' +
        '<div class="activity-row"><div class="activity-icon">@</div><div><strong>' + escapeHtml(lead.email || "No email") + '</strong><span>Email</span></div><em>contact</em></div>' +
        '<div class="activity-row"><div class="activity-icon">☎</div><div><strong>' + escapeHtml(lead.phone || "No phone") + '</strong><span>Phone</span></div><em>contact</em></div>' +
        '<div class="activity-row"><div class="activity-icon">✓</div><div><strong>' + escapeHtml(crmStatus(lead)) + '</strong><span>' + escapeHtml(lead.source || "Website") + '</span></div><em>stage</em></div>' +
        '<pre class="report-box">' + escapeHtml(String(lead.notes || lead.message || "No notes yet.")) + '</pre>' +
      '</div>';
      openModal(escapeHtml(lead.name || "Lead"), body, detail);
    }

    function crmWire() {
      const searchBtn = byId("crmSearchBtn");
      if (searchBtn) searchBtn.onclick = runCrmSearch;

      const input = byId("crmSearchInput");
      if (input) input.onkeydown = function(event) { if (event.key === "Enter") { event.preventDefault(); runCrmSearch(); } };

      const clearBtn = byId("crmClearSearchBtn");
      if (clearBtn) clearBtn.onclick = function() {
        crmSearchResults = null;
        crmStatusFilter = "all";
        const input = byId("crmSearchInput");
        if (input) input.value = "";
        const status = byId("crmSearchStatus");
        if (status) status.textContent = "Showing all leads. Search is read-only.";
        renderCrm();
      };

      document.querySelectorAll("[data-crm-stage]").forEach(function(btn) {
        btn.onclick = function() { crmStatusFilter = btn.getAttribute("data-crm-stage") || "all"; renderCrm(); };
      });

      document.querySelectorAll("[data-crm-view]").forEach(function(btn) {
        btn.onclick = function() { crmOpenLead(btn.getAttribute("data-crm-view"), "view"); };
      });

      document.querySelectorAll("[data-crm-follow]").forEach(function(btn) {
        btn.onclick = function() { crmOpenLead(btn.getAttribute("data-crm-follow"), "follow"); };
      });

      const addForm = byId("crmAddLeadForm");
      if (addForm) addForm.onsubmit = submitCrmLead;

      const importForm = byId("crmImportForm");
      if (importForm) importForm.onsubmit = submitCrmImport;
    }

    async function runCrmSearch() {
      const input = byId("crmSearchInput");
      const status = byId("crmSearchStatus");
      const query = input ? input.value.trim() : "";
      if (!query) {
        crmSearchResults = null;
        crmStatusFilter = "all";
        renderCrm();
        return;
      }

      const ranked = crmBaseLeads()
        .map(function(lead) { return { lead: lead, score: crmSearchScore(lead, query) }; })
        .filter(function(item) { return item.score > 0; })
        .sort(function(a, b) { return b.score - a.score; })
        .map(function(item) { return item.lead; });

      crmSearchResults = ranked;
      crmStatusFilter = "all";
      renderCrm();
      const nextStatus = byId("crmSearchStatus");
      if (nextStatus) nextStatus.textContent = "Found " + ranked.length + " matching leads for: " + query + ". Search is read-only.";
    }

    async function submitCrmLead(event) {
      event.preventDefault();
      const form = event.currentTarget;
      const payload = Object.fromEntries(new FormData(form).entries());
      if (!String(payload.email || "").trim() && !String(payload.phone || "").trim()) {
        toast("Add an email or phone number first.");
        return;
      }
      try {
        const response = await fetch("/crm/leads?token=" + encodeURIComponent(token) + "&intent=manual", {
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
      if (!formData.get("file") || !formData.get("file").name) {
        toast("Choose a CSV or spreadsheet first.");
        return;
      }
      try {
        if (status) status.textContent = "Uploading and organizing spreadsheet...";
        const response = await fetch("/crm/import?token=" + encodeURIComponent(token), { method: "POST", body: formData });
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

    function renderCrm() {
      const counts = crmCounts();
      const visible = crmVisibleLeads();
      const summary = byId("crmSummaryCards");
      const filters = byId("crmStageFilters");
      const list = byId("crmLeadList");
      if (!summary || !filters || !list) return;

      summary.innerHTML = [
        ["Total leads", counts.all || 0],
        ["New", counts.new || 0],
        ["Qualified", counts.qualified || 0],
        ["Proposal/Won", (counts.proposal || 0) + (counts.won || 0)]
      ].map(function(item) {
        return '<div class="crm-kpi"><span>' + escapeHtml(item[0]) + '</span><strong>' + format(item[1]) + '</strong></div>';
      }).join("");

      filters.innerHTML = crmStages().map(function(stage) {
        const label = stage === "all" ? "All" : stage.charAt(0).toUpperCase() + stage.slice(1);
        const count = counts[stage] || 0;
        return '<button class="crm-tab ' + (crmStatusFilter === stage ? 'active' : '') + '" type="button" data-crm-stage="' + stage + '">' + label + ' (' + count + ')</button>';
      }).join("");

      if (!visible.length) {
        list.innerHTML = '<div class="empty">No leads match this view. Try Clear, Seed demo data, or a search like “manufacturing leads”.</div>';
      } else {
        list.innerHTML = visible.map(crmLeadCardHtml).join("");
      }
      crmWire();
    }
`;

// Replace any CRM client block left by older patches. If only original renderCrm exists, replace that too.
if (!replaceRegex(/    function crmBaseLeads\(\) \{[\s\S]*?\n    function renderHealth\(\) \{/, crmClient + "\n    function renderHealth() {")) {
  if (!replaceRegex(/    function crmAllLeads\(\) \{[\s\S]*?\n    function renderHealth\(\) \{/, crmClient + "\n    function renderHealth() {")) {
    replaceRegex(/    function renderCrm\(\) \{[\s\S]*?\n    function renderHealth\(\) \{/, crmClient + "\n    function renderHealth() {");
  }
}

// Extra safety: keep backend creation guarded.
replaceRegex(
  /app\.post\("\/crm\/leads", async \(req, res\) => \{\n  try \{(?!\n    const createIntent)/,
  'app.post("/crm/leads", async (req, res) => {\n  try {\n    const createIntent = String(req.query.intent || req.body?.intent || "");\n    if (createIntent !== "manual") return res.status(400).json({ ok: false, error: "Lead creation requires manual CRM intent." });'
);

fs.writeFileSync(target, text);
console.log("Applied full modern CRM reset: clean UI, local semantic search, explicit manual writes, working detail actions.");
