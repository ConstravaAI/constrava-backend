(() => {
  const $ = (id) => document.getElementById(id);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));
  const stages = ["New", "Needs Analysis", "Qualified", "Proposal", "Negotiation", "Closed Won", "Closed Lost"];
  const probability = { "New": 10, "Needs Analysis": 20, "Qualified": 40, "Proposal": 60, "Negotiation": 80, "Closed Won": 100, "Closed Lost": 0 };
  const colors = ["#2f80ed", "#38bdf8", "#f4b740", "#ff6b6b", "#8b5cf6", "#25d07f", "#14b8a6"];
  let crmData = { leads: [], summary: {}, localRecords: [] };
  let activeCrm = "dashboards";
  let activeAccount = null;
  let customComponents = [];

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function money(value) {
    return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(Number(value || 0));
  }

  function num(value) {
    return new Intl.NumberFormat("en-US").format(Math.round(Number(value || 0)));
  }

  function toast(message) {
    const existing = $("toast");
    if (!existing) return;
    existing.textContent = message;
    existing.classList.add("show");
    clearTimeout(window.__legacyCrmToast);
    window.__legacyCrmToast = setTimeout(() => existing.classList.remove("show"), 2200);
  }

  function storageKey() {
    return "constrava.crm.legacy.v2." + String(activeAccount?.email || activeAccount?.dashboard_token || "unknown").toLowerCase();
  }

  function loadCrmLocal() {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey()) || "{}");
      customComponents = Array.isArray(saved.components) ? saved.components : [];
    } catch {
      customComponents = [];
    }
  }

  function saveCrmLocal() {
    try {
      localStorage.setItem(storageKey(), JSON.stringify({ components: customComponents, savedAt: new Date().toISOString() }));
    } catch {}
  }

  function appStorageKey(account) {
    return "constrava.private.v4." + String(account?.email || account?.dashboard_token || "unknown").toLowerCase();
  }

  function readLocalRecords(account) {
    try {
      const saved = JSON.parse(localStorage.getItem(appStorageKey(account)) || "{}");
      return Array.isArray(saved.records) ? saved.records : [];
    } catch {
      return [];
    }
  }

  function normalizeStage(stage) {
    const raw = String(stage || "").trim().toLowerCase();
    if (!raw) return "New";
    if (raw.includes("need")) return "Needs Analysis";
    if (raw.includes("qual")) return "Qualified";
    if (raw.includes("prop")) return "Proposal";
    if (raw.includes("nego")) return "Negotiation";
    if (raw.includes("won") || raw === "closed") return "Closed Won";
    if (raw.includes("lost")) return "Closed Lost";
    if (raw.includes("contact")) return "Needs Analysis";
    if (raw.includes("new")) return "New";
    return stages.includes(stage) ? stage : "New";
  }

  function mapLead(lead, index) {
    const email = lead.email || lead.Email || lead.contact_email || "";
    const name = lead.name || lead.full_name || lead.customer || lead.contact || (email ? email.split("@")[0] : "Lead " + (index + 1));
    const company = lead.company || lead.account || lead.organization || lead.business || lead.site_name || "Constrava Lead";
    const stage = normalizeStage(lead.status || lead.stage || lead.deal_stage || lead.pipeline_stage);
    const value = Number(lead.value || lead.amount || lead.revenue || lead.estimated_value || lead.deal_value || ((index + 2) * 900));
    return {
      id: String(lead.id || lead.email || lead.name || "crm_" + index),
      name,
      email,
      phone: lead.phone || lead.tel || "",
      company,
      account: company,
      stage,
      value,
      probability: probability[stage] ?? 10,
      source: lead.source || lead.referrer || lead.channel || "Website",
      type: lead.type || lead.kind || "Lead",
      owner: lead.owner || lead.assigned_to || "Constrava",
      notes: lead.notes || lead.message || lead.description || "",
      created: lead.created_at || lead.created || lead.time || ""
    };
  }

  function records() {
    const source = [...(crmData.leads || []), ...(crmData.localRecords || [])];
    const seen = new Set();
    const mapped = source.map(mapLead).filter((record) => {
      const key = String(record.email || record.name + record.company || record.id).toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    const query = String($("crmSearch")?.value || "").toLowerCase();
    const stage = $("stageFilter")?.value || "all";
    return mapped.filter((record) => {
      const haystack = [record.name, record.email, record.company, record.stage, record.source, record.type, record.owner, record.notes].join(" ").toLowerCase();
      return (!query || haystack.includes(query)) && (stage === "all" || record.stage === stage);
    });
  }

  function groupedByStage(list = records()) {
    return stages.map((stage) => ({ stage, items: list.filter((record) => record.stage === stage) }));
  }

  function setActiveCrm(view) {
    activeCrm = view;
    $$('[data-crm]').forEach((button) => button.classList.toggle("active", button.dataset.crm === view));
    const titles = {
      feeds: ["Feeds", "Recent CRM signals and lead updates."],
      home: ["Home", "CRM overview using the original dashboard format."],
      leads: ["Leads", "Lead record list and qualification pipeline."],
      vip: ["VIP Leads", "High-value lead records."],
      contacts: ["Contacts", "Contact-style record view."],
      accounts: ["Accounts", "Account and company records."],
      deals: ["Pipeline Board", "Deal stages and expected value."],
      activities: ["Activities", "CRM activity and follow-up feed."],
      dashboards: ["Deal Dashboards", "Pipeline, probability, accounts, activities, and lead records."],
      documents: ["Documents", "Documents connected to CRM records."],
      reports: ["Reports", "CRM report-style records and summaries."]
    };
    const [title, subtitle] = titles[view] || titles.dashboards;
    if ($("crmTitle")) $("crmTitle").textContent = title;
    if ($("crmSubtitle")) $("crmSubtitle").textContent = subtitle;
    renderCrmContent();
  }

  function kpis(list) {
    const pipeline = list.reduce((sum, record) => sum + record.value, 0);
    const weighted = list.reduce((sum, record) => sum + record.value * (record.probability / 100), 0);
    const won = list.filter((record) => record.stage === "Closed Won").length;
    const open = list.filter((record) => !record.stage.includes("Closed")).length;
    return `
      <div class="crm-kpis">
        <div class="crm-kpi"><span>Open Deals</span><strong>${num(open)}</strong></div>
        <div class="crm-kpi"><span>Pipeline Value</span><strong>${money(pipeline)}</strong></div>
        <div class="crm-kpi"><span>Weighted Forecast</span><strong>${money(weighted)}</strong></div>
        <div class="crm-kpi"><span>Won Records</span><strong>${num(won)}</strong></div>
      </div>
    `;
  }

  function funnel(list) {
    const groups = groupedByStage(list);
    const max = Math.max(...groups.map((group) => group.items.length), 1);
    return `<div class="crm-funnel">${groups.map((group, index) => {
      const width = Math.max(34, (group.items.length / max) * 100);
      return `<div class="crm-stage" style="width:${width}%;background:${colors[index % colors.length]}22;border:1px solid ${colors[index % colors.length]}88;color:#dceaff">${esc(group.stage)} · ${group.items.length}</div>`;
    }).join("")}</div>`;
  }

  function bars(list) {
    const groups = groupedByStage(list);
    const max = Math.max(...groups.map((group) => group.items.reduce((sum, record) => sum + record.value, 0)), 1);
    return `<div class="crm-bars">${groups.map((group, index) => {
      const total = group.items.reduce((sum, record) => sum + record.value, 0);
      const height = Math.max(8, (total / max) * 190);
      return `<div class="crm-bar" style="height:${height}px;background:${colors[index % colors.length]}"><span>${money(total)}</span><em>${esc(group.stage.split(" ")[0])}</em></div>`;
    }).join("")}</div>`;
  }

  function sourceDonut(list) {
    const counts = new Map();
    list.forEach((record) => counts.set(record.source || "Website", (counts.get(record.source || "Website") || 0) + 1));
    const entries = Array.from(counts.entries()).slice(0, 6);
    return `<div class="donut-wrap"><div class="donut"></div><div class="legend">${entries.map((entry, index) => `<div><i style="background:${colors[index % colors.length]}"></i>${esc(entry[0])} · ${entry[1]}</div>`).join("") || "No sources yet"}</div></div>`;
  }

  function recordsTable(list, limit = 80) {
    return `<div class="records"><table><thead><tr><th>Name</th><th>Company</th><th>Stage</th><th>Value</th><th>Probability</th><th>Source</th><th>Owner</th></tr></thead><tbody>${list.slice(0, limit).map((record) => `
      <tr><td><strong>${esc(record.name)}</strong><br><span>${esc(record.email)}</span></td><td>${esc(record.company)}</td><td><span class="crm-pill">${esc(record.stage)}</span></td><td>${money(record.value)}</td><td>${record.probability}%</td><td>${esc(record.source)}</td><td>${esc(record.owner)}</td></tr>
    `).join("") || '<tr><td colspan="7">No records found.</td></tr>'}</tbody></table></div>`;
  }

  function board(list) {
    return `<div class="crm-board">${groupedByStage(list).map((group) => `<div class="crm-col"><h4>${esc(group.stage)}</h4>${group.items.map((record) => `<div class="crm-deal"><strong>${esc(record.name)}</strong><span>${esc(record.company)}</span><em>${money(record.value)} · ${record.probability}%</em></div>`).join("") || '<div class="empty">No records</div>'}</div>`).join("")}</div>`;
  }

  function activities(list) {
    const rows = list.slice(0, 18).map((record, index) => {
      const action = record.stage.includes("Closed") ? "Deal updated" : index % 3 === 0 ? "Follow-up needed" : index % 3 === 1 ? "Lead qualified" : "Record reviewed";
      return `<div class="crm-activity"><strong>${esc(action)}</strong><p>${esc(record.name)} · ${esc(record.company)} · ${esc(record.stage)}</p></div>`;
    }).join("") || '<div class="empty">No CRM activities yet.</div>';
    return `<div class="crm-activity-list">${rows}</div>`;
  }

  function typeRows(list) {
    const counts = new Map();
    list.forEach((record) => counts.set(record.type || "Lead", (counts.get(record.type || "Lead") || 0) + 1));
    const max = Math.max(...Array.from(counts.values()), 1);
    return Array.from(counts.entries()).map(([type, count]) => `
      <div class="type-row"><strong>${esc(type)}</strong><div class="track"><div class="fill" style="width:${Math.max(5, (count / max) * 100)}%"></div></div><span>${count}</span></div>
    `).join("") || '<div class="empty">No type data.</div>';
  }

  function componentHtml(component, list) {
    const title = esc(component.title || "AI Component");
    if (component.kind === "pipeline") return `<section class="crm-panel"><div class="crm-panel-head"><h3>${title}</h3><button class="crm-btn" data-remove-component="${esc(component.id)}">Remove</button></div><div class="crm-panel-body">${board(list)}</div></section>`;
    if (component.kind === "sources") return `<section class="crm-panel"><div class="crm-panel-head"><h3>${title}</h3><button class="crm-btn" data-remove-component="${esc(component.id)}">Remove</button></div><div class="crm-panel-body">${sourceDonut(list)}</div></section>`;
    if (component.kind === "activity") return `<section class="crm-panel"><div class="crm-panel-head"><h3>${title}</h3><button class="crm-btn" data-remove-component="${esc(component.id)}">Remove</button></div><div class="crm-panel-body">${activities(list)}</div></section>`;
    if (component.kind === "types") return `<section class="crm-panel"><div class="crm-panel-head"><h3>${title}</h3><button class="crm-btn" data-remove-component="${esc(component.id)}">Remove</button></div><div class="crm-panel-body">${typeRows(list)}</div></section>`;
    if (component.kind === "table") return `<section class="crm-panel"><div class="crm-panel-head"><h3>${title}</h3><button class="crm-btn" data-remove-component="${esc(component.id)}">Remove</button></div><div class="crm-panel-body">${recordsTable(list)}</div></section>`;
    return `<section class="crm-panel"><div class="crm-panel-head"><h3>${title}</h3><button class="crm-btn" data-remove-component="${esc(component.id)}">Remove</button></div><div class="crm-panel-body">${bars(list)}</div></section>`;
  }

  function customComponentGrid(list) {
    if (!customComponents.length) return "";
    return `<div class="crm-grid" style="margin-top:12px">${customComponents.map((component) => componentHtml(component, list)).join("")}</div>`;
  }

  function dashboardView(list) {
    return `
      ${kpis(list)}
      <div class="crm-grid">
        <section class="crm-panel"><div class="crm-panel-head"><h3>Deal Funnel</h3><span>${list.length} records</span></div><div class="crm-panel-body">${funnel(list)}</div></section>
        <section class="crm-panel"><div class="crm-panel-head"><h3>Revenue by Stage</h3><span>Forecast</span></div><div class="crm-panel-body">${bars(list)}</div></section>
        <section class="crm-panel"><div class="crm-panel-head"><h3>Lead Source Mix</h3><span>Channels</span></div><div class="crm-panel-body">${sourceDonut(list)}</div></section>
        <section class="crm-panel"><div class="crm-panel-head"><h3>Recent CRM Activity</h3><span>Follow-ups</span></div><div class="crm-panel-body">${activities(list)}</div></section>
      </div>
      ${customComponentGrid(list)}
      <section class="crm-panel" style="margin-top:12px"><div class="crm-panel-head"><h3>Records</h3><span>Original CRM record table</span></div><div class="crm-panel-body">${recordsTable(list)}</div></section>
    `;
  }

  function renderCrmContent() {
    const list = records();
    if (!$('crmContent')) return;
    if (activeCrm === "deals") {
      $('crmContent').innerHTML = kpis(list) + board(list) + customComponentGrid(list);
      return;
    }
    if (activeCrm === "activities" || activeCrm === "feeds") {
      $('crmContent').innerHTML = kpis(list) + `<section class="crm-panel"><div class="crm-panel-head"><h3>Activities</h3><span>CRM feed</span></div><div class="crm-panel-body">${activities(list)}</div></section>` + customComponentGrid(list);
      return;
    }
    if (["leads", "vip", "contacts", "accounts", "documents", "reports"].includes(activeCrm)) {
      const filtered = activeCrm === "vip" ? list.filter((record) => record.value >= 5000 || record.probability >= 60) : list;
      $('crmContent').innerHTML = kpis(filtered) + `<section class="crm-panel"><div class="crm-panel-head"><h3>${esc($('crmTitle')?.textContent || 'Records')}</h3><span>${filtered.length} records</span></div><div class="crm-panel-body">${recordsTable(filtered)}</div></section>` + customComponentGrid(filtered);
      return;
    }
    $('crmContent').innerHTML = dashboardView(list);
  }

  function classifyComponent(prompt) {
    const text = String(prompt || "").toLowerCase();
    if (text.includes("source") || text.includes("channel") || text.includes("referrer")) return "sources";
    if (text.includes("pipeline") || text.includes("kanban") || text.includes("board") || text.includes("stage")) return "pipeline";
    if (text.includes("activity") || text.includes("follow") || text.includes("timeline")) return "activity";
    if (text.includes("type") || text.includes("category") || text.includes("segment")) return "types";
    if (text.includes("table") || text.includes("record") || text.includes("list")) return "table";
    return "forecast";
  }

  function titleForComponent(kind, prompt) {
    const clean = String(prompt || "").trim();
    if (clean && clean.length <= 42) return clean;
    const defaults = { sources: "AI Lead Source Component", pipeline: "AI Pipeline Component", activity: "AI Activity Component", types: "AI Lead Type Component", table: "AI Record List Component", forecast: "AI Forecast Component" };
    return defaults[kind] || "AI Component";
  }

  function addComponent() {
    const prompt = window.prompt("Describe the CRM dashboard component to add. Example: source chart, pipeline board, activity feed, VIP records, forecast bars.");
    if (!prompt) return;
    const kind = classifyComponent(prompt);
    customComponents.unshift({ id: "component_" + Date.now(), kind, title: titleForComponent(kind, prompt), prompt, createdAt: new Date().toISOString() });
    saveCrmLocal();
    renderCrmContent();
    toast("AI component added: " + titleForComponent(kind, prompt));
  }

  function explainCrm() {
    const list = records();
    const pipeline = list.reduce((sum, record) => sum + record.value, 0);
    const weighted = list.reduce((sum, record) => sum + record.value * (record.probability / 100), 0);
    const urgent = list.filter((record) => ["Proposal", "Negotiation"].includes(record.stage));
    const message = `CRM insight: ${list.length} records, ${money(pipeline)} pipeline value, ${money(weighted)} weighted forecast. ${urgent.length} proposal/negotiation records may need follow-up.`;
    customComponents.unshift({ id: "component_" + Date.now(), kind: "activity", title: "AI CRM Insight", prompt: message, createdAt: new Date().toISOString() });
    saveCrmLocal();
    renderCrmContent();
    toast(message);
  }

  async function loadCrm() {
    try {
      const meRes = await fetch('/auth/me');
      const me = meRes.ok ? await meRes.json() : null;
      activeAccount = me?.account || null;
      loadCrmLocal();
      const dashRes = await fetch('/api/dashboard');
      const dash = dashRes.ok ? await dashRes.json() : { leads: [], summary: {} };
      crmData = { ...dash, localRecords: readLocalRecords(activeAccount || {}) };
      renderCrmContent();
    } catch (error) {
      if ($('crmContent')) $('crmContent').innerHTML = `<div class="empty">CRM failed to load: ${esc(error.message)}</div>`;
    }
  }

  function wireCrm() {
    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-crm]');
      if (button) setActiveCrm(button.dataset.crm);
      if (event.target.closest('#crmAdd')) addComponent();
      if (event.target.closest('[data-explain="crm"]')) explainCrm();
      const remove = event.target.closest('[data-remove-component]');
      if (remove) {
        customComponents = customComponents.filter((component) => component.id !== remove.dataset.removeComponent);
        saveCrmLocal();
        renderCrmContent();
        toast("CRM component removed.");
      }
    });
    $('crmSearch')?.addEventListener('input', renderCrmContent);
    $('stageFilter')?.addEventListener('change', renderCrmContent);
    document.addEventListener('constrava:records-changed', loadCrm);
  }

  wireCrm();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadCrm); else loadCrm();
})();
