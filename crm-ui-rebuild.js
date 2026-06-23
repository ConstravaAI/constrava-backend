import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceOnce(search, replacement) {
  if (text.includes(replacement)) return false;
  if (!text.includes(search)) return false;
  text = text.replace(search, replacement);
  return true;
}

const cssBlock = String.raw`

    .crm-command {
      border: 1px solid rgba(16,185,129,.20);
      border-radius: 28px;
      padding: 22px;
      margin-bottom: 18px;
      background:
        radial-gradient(circle at 100% 0%, rgba(16,185,129,.18), transparent 32%),
        linear-gradient(135deg, rgba(255,255,255,.96), rgba(236,253,245,.78));
      box-shadow: var(--shadow);
    }

    .crm-command-top {
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: flex-start;
      margin-bottom: 16px;
    }

    .crm-command h2 { margin: 0; color: #073d32; letter-spacing: -.04em; }
    .crm-command p { margin: 7px 0 0; color: var(--muted); line-height: 1.55; }

    .crm-readonly {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      border: 1px solid rgba(4,120,87,.18);
      border-radius: 999px;
      padding: 8px 11px;
      color: #047857;
      background: #ecfdf5;
      font-weight: 950;
      font-size: 12px;
      white-space: nowrap;
    }

    .crm-searchbar {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 10px;
      align-items: center;
    }

    .crm-input, .crm-select, .crm-textarea {
      width: 100%;
      border: 1px solid #dbe8e4;
      border-radius: 14px;
      padding: 12px 13px;
      background: white;
      color: #073d32;
      outline: 0;
    }

    .crm-input:focus, .crm-select:focus, .crm-textarea:focus {
      border-color: #10b981;
      box-shadow: 0 0 0 4px rgba(16,185,129,.12);
    }

    .crm-overview {
      display: grid;
      grid-template-columns: repeat(4, minmax(0,1fr));
      gap: 12px;
      margin-bottom: 18px;
    }

    .crm-stat {
      border: 1px solid #dbe8e4;
      border-radius: 20px;
      padding: 16px;
      background: rgba(255,255,255,.86);
      box-shadow: 0 12px 32px rgba(15,23,42,.06);
    }

    .crm-stat span { display: block; color: var(--muted); font-size: 12px; font-weight: 850; text-transform: uppercase; letter-spacing: .08em; }
    .crm-stat strong { display: block; margin-top: 8px; color: #073d32; font-size: 28px; letter-spacing: -.05em; }

    .crm-workspace {
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) minmax(320px, .9fr);
      gap: 18px;
      align-items: start;
    }

    .crm-stage-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 14px 0 16px;
    }

    .crm-stage {
      border: 1px solid #dbe8e4;
      border-radius: 999px;
      padding: 9px 12px;
      background: white;
      color: #064e3b;
      font-weight: 950;
      font-size: 13px;
    }

    .crm-stage.active {
      color: #d1fae5;
      border-color: #064e3b;
      background: #064e3b;
    }

    .crm-list {
      display: grid;
      gap: 12px;
    }

    .crm-lead-card {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 12px;
      border: 1px solid #dbe8e4;
      border-radius: 20px;
      padding: 16px;
      background: linear-gradient(180deg, #ffffff, #f8fffc);
      box-shadow: 0 12px 26px rgba(15,23,42,.05);
    }

    .crm-lead-card h3 { margin: 0; color: #073d32; letter-spacing: -.03em; }
    .crm-lead-card p { margin: 7px 0 0; color: #475569; line-height: 1.45; }
    .crm-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .crm-chip { display: inline-flex; align-items: center; border-radius: 999px; padding: 6px 9px; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 850; }
    .crm-chip.green { background: #dcfce7; color: #047857; }
    .crm-card-actions { display: grid; gap: 8px; min-width: 132px; align-self: start; }

    .crm-side-stack { display: grid; gap: 18px; }
    .crm-form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .crm-form-grid .full { grid-column: 1 / -1; }

    .crm-import-box {
      border: 1px dashed #9bd9c3;
      border-radius: 18px;
      padding: 16px;
      background: #f8fffc;
    }

    @media (max-width: 980px) {
      .crm-workspace, .crm-overview, .crm-searchbar, .crm-form-grid { grid-template-columns: 1fr; }
      .crm-command-top, .crm-lead-card { grid-template-columns: 1fr; display: grid; }
      .crm-card-actions { grid-template-columns: 1fr 1fr; }
    }
`;

if (!text.includes(".crm-command")) {
  text = text.replace("    @media (max-width: 1180px) {", cssBlock + "\n    @media (max-width: 1180px) {");
}

const crmMarkup = String.raw`        <div id="crmArea" style="display:none">
          <section class="section-page active">
            <div class="crm-command">
              <div class="crm-command-top">
                <div>
                  <h2>Client CRM</h2>
                  <p>Capture leads, search by buyer type, import spreadsheets, and keep follow-up organized from one place.</p>
                </div>
                <div class="crm-readonly">Public demo is read-only for CRM writes</div>
              </div>
              <div class="crm-searchbar">
                <input class="crm-input" id="crmSearchInput" placeholder="AI search: ready buyers, manufacturing leads, proposal stage...">
                <button class="btn" type="button" id="crmSearchBtn"><span data-icon="sparkles"></span> Search leads</button>
                <button class="mini-btn" type="button" id="crmClearSearchBtn">Clear</button>
              </div>
              <div class="empty" id="crmSearchStatus" style="margin-top:12px">Search by name/company or ask for a type of person, like “qualified buyers” or “manufacturing leads.”</div>
            </div>

            <div class="crm-overview" id="crmSummaryCards"></div>

            <div class="crm-workspace">
              <article class="card">
                <div class="card-inner">
                  <div class="card-title">
                    <div><h2>Lead pipeline</h2><p>Filter by stage and open the highest-priority leads first.</p></div>
                    <button class="mini-btn" type="button" data-explain="crm"><span data-icon="sparkles"></span> AI explain</button>
                  </div>
                  <div class="crm-stage-tabs" id="crmStageFilters"></div>
                  <div class="crm-list" id="crmLeadList"></div>
                </div>
              </article>

              <div class="crm-side-stack">
                <article class="card">
                  <div class="card-inner">
                    <div class="card-title"><div><h2>Add lead</h2><p>For real client dashboards. Disabled on the public demo token.</p></div></div>
                    <form id="crmAddLeadForm" class="bar-list">
                      <div class="crm-form-grid">
                        <input class="crm-input" name="name" placeholder="Name">
                        <input class="crm-input" name="email" placeholder="Email">
                        <input class="crm-input" name="phone" placeholder="Phone">
                        <input class="crm-input" name="company" placeholder="Company">
                        <select class="crm-select full" name="status"><option>New</option><option>Contacted</option><option>Qualified</option><option>Proposal</option><option>Won</option><option>Lost</option></select>
                        <textarea class="crm-textarea full" name="message" placeholder="Notes, request, budget, timeline"></textarea>
                      </div>
                      <button class="btn" type="submit">Add CRM lead</button>
                    </form>
                  </div>
                </article>

                <article class="card">
                  <div class="card-inner">
                    <div class="card-title"><div><h2>Import spreadsheet</h2><p>Upload CSV/XLSX files and organize messy columns into CRM fields.</p></div></div>
                    <form id="crmImportForm" class="bar-list">
                      <div class="crm-import-box">
                        <input id="crmImportFile" name="file" type="file" accept=".csv,.xlsx,.xls">
                      </div>
                      <button class="btn" type="submit">Import and organize</button>
                      <div class="empty" id="crmImportStatus">The importer maps columns like Full Name, Email Address, Business, Stage, Notes, and Source.</div>
                    </form>
                  </div>
                </article>

                <article class="card">
                  <div class="card-inner">
                    <div class="card-title"><div><h2>Smart actions</h2><p>Quick guidance based on the current lead list.</p></div></div>
                    <div class="bar-list">
                      <button class="btn" type="button" data-explain="followup">Draft follow-up strategy</button>
                      <button class="btn" type="button" data-explain="qualify">Explain lead quality</button>
                      <button class="btn" type="button" data-explain="pipeline">Summarize pipeline</button>
                    </div>
                  </div>
                </article>
              </div>
            </div>
          </section>
        </div>`;

const crmAreaRegex = /        <div id="crmArea" style="display:none">[\s\S]*?          <\/section>\n        <\/div>/;
if (!text.includes('id="crmLeadList"')) {
  text = text.replace(crmAreaRegex, crmMarkup);
}

replaceOnce(
  '    let crmSearchResults = null;\n    let toastTimer = null;',
  '    let crmSearchResults = null;\n    let crmStatusFilter = "all";\n    let toastTimer = null;'
);

const rebuiltClient = String.raw`
    function crmAllLeads() {
      return crmSearchResults || dashboardData.leads || [];
    }

    function crmLeadStatus(lead) {
      return String((lead && (lead.status || lead.stage)) || "New");
    }

    function crmStatusKey(status) {
      return String(status || "new").toLowerCase().replace(/\s+/g, "-");
    }

    function crmStageOrder() {
      return ["all", "new", "contacted", "qualified", "proposal", "won", "lost"];
    }

    function crmFilteredLeads() {
      const leads = crmAllLeads();
      if (crmStatusFilter === "all") return leads;
      return leads.filter(function(lead) { return crmStatusKey(crmLeadStatus(lead)) === crmStatusFilter; });
    }

    function crmCounts() {
      const leads = crmAllLeads();
      const counts = { all: leads.length, new: 0, contacted: 0, qualified: 0, proposal: 0, won: 0, lost: 0 };
      leads.forEach(function(lead) {
        const key = crmStatusKey(crmLeadStatus(lead));
        counts[key] = (counts[key] || 0) + 1;
      });
      return counts;
    }

    function crmLeadCardHtml(lead, index) {
      const status = crmLeadStatus(lead);
      const email = String(lead.email || "");
      const phone = String(lead.phone || "");
      const company = String(lead.company || "—");
      const source = String(lead.source || "Website");
      const notes = String(lead.notes || lead.message || "No notes yet.");
      return '<div class="crm-lead-card">' +
        '<div><h3>' + escapeHtml(lead.name || "New Lead") + '</h3>' +
        '<p>' + escapeHtml(company) + (email ? ' • ' + escapeHtml(email) : '') + (phone ? ' • ' + escapeHtml(phone) : '') + '</p>' +
        '<div class="crm-meta"><span class="crm-chip green">' + escapeHtml(status) + '</span><span class="crm-chip">' + escapeHtml(source) + '</span><span class="crm-chip">Lead #' + (index + 1) + '</span></div>' +
        '<p style="margin-top:12px">' + escapeHtml(notes).slice(0, 180) + '</p></div>' +
        '<div class="crm-card-actions"><button class="mini-btn" type="button" data-explain="followup">Follow-up</button><button class="mini-btn" type="button" data-explain="qualify">Quality</button></div>' +
      '</div>';
    }

    function wireCrmRebuilt() {
      const searchBtn = byId("crmSearchBtn");
      if (searchBtn) searchBtn.onclick = runCrmSearch;

      const searchInput = byId("crmSearchInput");
      if (searchInput) {
        searchInput.onkeydown = function(event) {
          if (event.key === "Enter") runCrmSearch();
        };
      }

      const clearBtn = byId("crmClearSearchBtn");
      if (clearBtn) {
        clearBtn.onclick = function() {
          crmSearchResults = null;
          crmStatusFilter = "all";
          const input = byId("crmSearchInput");
          if (input) input.value = "";
          const status = byId("crmSearchStatus");
          if (status) status.textContent = "Showing all CRM leads.";
          renderCrm();
        };
      }

      document.querySelectorAll("[data-crm-stage]").forEach(function(btn) {
        btn.onclick = function() {
          crmStatusFilter = btn.getAttribute("data-crm-stage") || "all";
          renderCrm();
        };
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
        renderCrm();
        return;
      }

      if (status) status.textContent = "Searching leads by keyword and buyer intent...";
      try {
        const response = await fetch("/crm/search?token=" + encodeURIComponent(token) + "&q=" + encodeURIComponent(query));
        const data = await response.json().catch(function(){ return {}; });
        if (!response.ok || !data.ok) throw new Error(data.error || "CRM search failed.");
        crmSearchResults = data.leads || [];
        crmStatusFilter = "all";
        renderCrm();
        const nextStatus = byId("crmSearchStatus");
        if (nextStatus) nextStatus.textContent = "Found " + crmSearchResults.length + " leads matching: " + query;
      } catch (err) {
        if (status) status.textContent = err.message || "CRM search failed.";
        toast(err.message || "CRM search failed.");
      }
    }

    function renderCrm() {
      const counts = crmCounts();
      const leads = crmFilteredLeads();
      const summary = byId("crmSummaryCards");
      const stages = byId("crmStageFilters");
      const list = byId("crmLeadList");

      if (!summary || !stages || !list) return;

      summary.innerHTML = [
        ["Total leads", counts.all || 0],
        ["New", counts.new || 0],
        ["Qualified", counts.qualified || 0],
        ["Proposal/Won", (counts.proposal || 0) + (counts.won || 0)]
      ].map(function(item) {
        return '<div class="crm-stat"><span>' + escapeHtml(item[0]) + '</span><strong>' + format(item[1]) + '</strong></div>';
      }).join("");

      stages.innerHTML = crmStageOrder().map(function(stage) {
        const label = stage === "all" ? "All" : stage.charAt(0).toUpperCase() + stage.slice(1);
        const value = counts[stage] || 0;
        return '<button class="crm-stage ' + (crmStatusFilter === stage ? 'active' : '') + '" type="button" data-crm-stage="' + stage + '">' + label + ' <span>(' + value + ')</span></button>';
      }).join("");

      if (!leads.length) {
        list.innerHTML = '<div class="empty">No leads match this view yet. Try clearing search, seeding demo data, or importing a spreadsheet on a real client token.</div>';
      } else {
        list.innerHTML = leads.map(crmLeadCardHtml).join("");
      }

      wireCrmRebuilt();
    }
`;

const renderHealthAnchor = '    function renderHealth() {';
if (!text.includes("function crmLeadCardHtml(lead, index)")) {
  text = text.replace(renderHealthAnchor, rebuiltClient + "\n" + renderHealthAnchor);
}

fs.writeFileSync(target, text);
console.log("Rebuilt CRM UI with command center, stage filters, lead cards, add form, and import panel.");
