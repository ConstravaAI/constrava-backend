import fs from "fs";

const file = "crm-distinct-tabs.js";
const content = `(function(){
  if (window.__constravaSimpleRecordTabsLoaded) return;
  window.__constravaSimpleRecordTabsLoaded = true;

  var params = new URLSearchParams(location.search);
  var token = params.get('token') || 'demo';
  var state = { active: 'all', entries: [], loading: false, query: '' };

  var tabs = [
    { id:'all', icon:'📋', label:'All Records', types:[], action:'Review every CRM data point in one clean list.', placeholder:'Search all records...' },
    { id:'lead', icon:'🎯', label:'Leads', types:['lead'], action:'Track potential customers and follow up with them.', placeholder:'Example: Lidia called and might need a website...' },
    { id:'person', icon:'👤', label:'People', types:['person','contact','client','customer'], action:'Store people, contacts, and customers.', placeholder:'Example: Update Lidia phone number to...' },
    { id:'company', icon:'🏢', label:'Companies', types:['company','organization','business'], action:'Track organizations connected to records.', placeholder:'Example: Add Acme Construction as a company...' },
    { id:'deal', icon:'💼', label:'Deals / Sales', types:['deal','sale','sales','purchase','opportunity'], action:'Track opportunities, purchases, and sales.', placeholder:'Example: Lidia approved the $2,000 website deal...' },
    { id:'task', icon:'✅', label:'Tasks', types:['task','todo','followup','follow-up'], action:'Track next steps and follow-up work.', placeholder:'Example: Remind me to call Lidia tomorrow...' },
    { id:'intake', icon:'📥', label:'Intake', types:['intake','form','submission'], action:'Review new form submissions and messy incoming notes.', placeholder:'Example: New website form: name, email, request...' },
    { id:'note', icon:'📝', label:'Notes', types:['note'], action:'Keep plain notes attached to CRM records.', placeholder:'Example: Note that Lidia prefers text messages...' }
  ];

  var css = document.createElement('style');
  css.textContent = '.crm-modern-shell,.cx-entry-hub,.cx-form-panel{display:none!important}.crm-left.cx-simple-owned{padding:14px!important}.cx-simple-nav-title{margin:6px 8px 10px;color:#64748b;font-size:11px;font-weight:950;letter-spacing:.12em;text-transform:uppercase}.cx-simple-side-btn{display:flex!important;width:100%!important;gap:10px!important;align-items:center!important;border:0!important;background:transparent!important;border-radius:12px!important;padding:10px!important;margin:3px 0!important;text-align:left!important;color:#334155!important;cursor:pointer!important}.cx-simple-side-btn:hover,.cx-simple-side-btn.active{background:#eaf8f1!important;color:#047857!important}.cx-simple-side-btn strong{display:block;font-size:13px}.cx-simple-side-btn small{display:block;color:#64748b;font-size:10px;margin-top:2px}.crm-top.cx-simple-titlebar{height:auto!important;min-height:62px!important;padding:14px 18px!important;display:flex!important;align-items:center!important;justify-content:space-between!important;background:linear-gradient(135deg,#14352b,#052e24)!important;color:#fff!important}.crm-top.cx-simple-titlebar button{display:none!important}.cx-simple-title strong{display:block;color:#fff;font-size:19px}.cx-simple-title span{display:block;color:rgba(226,232,240,.82);font-size:12px;margin-top:4px}.cx-simple{display:grid;gap:14px}.cx-simple-card{border:1px solid #dbe8e4;border-radius:18px;background:#fff;box-shadow:0 10px 24px rgba(15,23,42,.05);padding:16px}.cx-simple-card h2,.cx-simple-card h3{margin:0;color:#022c22}.cx-simple-card p{margin:7px 0 0;color:#64748b;line-height:1.45}.cx-simple-action{display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:14px}.cx-simple-input{width:100%;border:1px solid #d8e0e7;border-radius:12px;background:#f8fafc;color:#0f172a;padding:11px 12px;font:inherit}.cx-simple-btn{border:1px solid #10b981;border-radius:12px;background:#10b981;color:#022c22;font-weight:950;padding:10px 14px;cursor:pointer}.cx-simple-list{display:grid;gap:10px}.cx-simple-row{border:1px solid #e5e7eb;border-radius:15px;background:#fff;padding:13px}.cx-simple-row-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.cx-simple-row h4{margin:0;color:#022c22}.cx-simple-row p{margin:6px 0 0;color:#64748b;font-size:13px;line-height:1.45}.cx-simple-meta{display:flex;gap:7px;flex-wrap:wrap;margin-top:9px}.cx-simple-pill{display:inline-flex;border-radius:999px;padding:5px 8px;background:#ecfdf5;color:#047857;font-size:11px;font-weight:900}.cx-simple-pill.gray{background:#f1f5f9;color:#475569}.cx-simple-empty{border:1px dashed #b9ddd0;border-radius:16px;background:#f8fffc;color:#64748b;text-align:center;padding:28px}.cx-simple-toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;flex-wrap:wrap}.cx-simple-search{max-width:360px}.cx-simple-count{color:#64748b;font-size:13px;font-weight:800}@media(max-width:850px){.cx-simple-action{grid-template-columns:1fr}.cx-simple-row-top{display:block}}';
  document.head.appendChild(css);

  function esc(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]; }); }
  function root(){ return document.querySelector('.crm-main') || document.querySelector('.crm-shell') || document.getElementById('crmArea'); }
  function side(){ return document.querySelector('.crm-left'); }
  function topbar(){ return document.querySelector('.crm-top'); }
  function cleanType(v){
    v = String(v || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    var map = { leads:'lead', people:'person', persons:'person', contacts:'person', contact:'person', customers:'person', customer:'person', clients:'person', client:'person', companies:'company', organizations:'company', organization:'company', businesses:'company', business:'company', deals:'deal', opportunities:'deal', opportunity:'deal', sales:'sale', purchases:'purchase', tasks:'task', todos:'task', followups:'task', 'follow-ups':'task', forms:'intake', submissions:'intake', entries:'entry' };
    return map[v] || v;
  }
  function recordTypes(e){
    var out = [];
    function add(v){ v = cleanType(v); if (v && out.indexOf(v) === -1) out.push(v); }
    if (Array.isArray(e.types)) e.types.forEach(add);
    ['primary_type','type','record_type','module','category'].forEach(function(k){ add(e[k]); });
    if (e.name || e.email || e.phone || e.mobile) add('person');
    if (e.company || e.organization) add('company');
    if (e.deal_name || Number(e.value || 0) > 0) add('deal');
    if (e.next_step || /task|todo|follow/i.test(String(e.notes || '') + ' ' + String(e.status || ''))) add('task');
    if (/form|intake|submission|google|website/i.test(String(e.source || '') + ' ' + String(e.provider || ''))) add('intake');
    if (!out.length) add('entry');
    return out;
  }
  function activeTab(){ return tabs.filter(function(t){ return t.id === state.active; })[0] || tabs[0]; }
  function matchesTab(e, tab){
    if (!tab.types.length) return true;
    var types = recordTypes(e);
    return tab.types.some(function(t){ return types.indexOf(cleanType(t)) !== -1; });
  }
  function displayedEntries(){
    var tab = activeTab();
    var q = state.query.toLowerCase().trim();
    return state.entries.filter(function(e){
      if (!matchesTab(e, tab)) return false;
      if (!q) return true;
      return JSON.stringify(e).toLowerCase().indexOf(q) !== -1;
    });
  }
  function titleFor(e){ return e.name || e.company || e.deal_name || e.title || e.email || 'Unnamed record'; }
  function subline(e){ return [e.company, e.email, e.phone || e.mobile].filter(Boolean).join(' • ') || e.source || 'No details yet'; }
  function description(e){ return e.notes || e.message || e.next_step || e.deal_name || e.status || 'No notes yet.'; }

  async function loadEntries(){
    state.loading = true;
    try {
      var r = await fetch('/api/crm/entries?token=' + encodeURIComponent(token) + '&type=all', { cache:'no-store' });
      var j = await r.json();
      state.entries = j.entries || j.leads || [];
    } catch (err) {
      try { state.entries = (window.dashboardData && window.dashboardData.leads) || (window.data && window.data.leads) || []; } catch(e){ state.entries = []; }
    }
    state.loading = false;
    render();
  }

  async function quickAdd(){
    var input = document.getElementById('cxSimpleQuickInput');
    var status = document.getElementById('cxSimpleStatus');
    var text = input ? input.value.trim() : '';
    if (!text) return;
    var tab = activeTab();
    if (status) status.textContent = 'Saving...';
    try {
      var r = await fetch('/api/crm/ai-entry?token=' + encodeURIComponent(token), {
        method:'POST', headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify({ token: token, text: '[' + tab.label + '] ' + text })
      });
      var j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Could not save.');
      if (input) input.value = '';
      if (status) status.textContent = 'Saved. Reloading list...';
      await loadEntries();
    } catch (err) {
      if (status) status.textContent = err.message || 'Could not save.';
    }
  }

  function rebuildSide(){
    var el = side(); if (!el) return;
    el.classList.add('cx-simple-owned');
    el.innerHTML = '<div class="cx-simple-nav-title">CRM tabs</div>' + tabs.map(function(t){
      return '<button class="cx-simple-side-btn" type="button" data-simple-tab="' + esc(t.id) + '"><span>' + t.icon + '</span><span><strong>' + esc(t.label) + '</strong><small>' + esc(t.action) + '</small></span></button>';
    }).join('');
    Array.prototype.forEach.call(el.querySelectorAll('[data-simple-tab]'), function(btn){
      btn.onclick = function(){ state.active = btn.getAttribute('data-simple-tab'); state.query = ''; render(); };
    });
  }

  function updateTop(){
    var el = topbar(); if (!el) return;
    var tab = activeTab();
    el.classList.add('cx-simple-titlebar');
    el.innerHTML = '<div class="cx-simple-title"><strong>' + esc(tab.label) + '</strong><span>' + esc(tab.action) + '</span></div><div class="cx-simple-pill">Simple tabs</div>';
  }

  function ensurePanel(){
    var r = root(); if (!r) return null;
    var panel = document.getElementById('cxSimpleCrmRoot');
    if (!panel) {
      panel = document.createElement('div');
      panel.id = 'cxSimpleCrmRoot';
      panel.className = 'cx-simple';
      r.insertBefore(panel, r.firstChild || null);
    }
    return panel;
  }

  function renderList(list){
    if (state.loading) return '<div class="cx-simple-empty">Loading records...</div>';
    if (!list.length) return '<div class="cx-simple-empty"><b>No matching records</b>This tab only shows records with matching record types.</div>';
    return '<div class="cx-simple-list">' + list.map(function(e){
      var types = recordTypes(e).map(function(t){ return '<span class="cx-simple-pill gray">' + esc(t) + '</span>'; }).join('');
      return '<div class="cx-simple-row"><div class="cx-simple-row-top"><div><h4>' + esc(titleFor(e)) + '</h4><p>' + esc(subline(e)) + '</p></div><span class="cx-simple-pill">' + esc(e.status || e.data_quality || 'record') + '</span></div><p>' + esc(description(e)) + '</p><div class="cx-simple-meta">' + types + '</div></div>';
    }).join('') + '</div>';
  }

  function render(){
    rebuildSide();
    updateTop();
    var panel = ensurePanel(); if (!panel) return;
    var tab = activeTab();
    var list = displayedEntries();
    Array.prototype.forEach.call(document.querySelectorAll('[data-simple-tab]'), function(btn){ btn.classList.toggle('active', btn.getAttribute('data-simple-tab') === state.active); });
    panel.innerHTML = '<div class="cx-simple-card"><h2>' + esc(tab.label) + '</h2><p><b>Basic function:</b> ' + esc(tab.action) + '</p><div class="cx-simple-action"><input id="cxSimpleQuickInput" class="cx-simple-input" placeholder="' + esc(tab.placeholder) + '"><button id="cxSimpleQuickAdd" class="cx-simple-btn" type="button">Add / Update</button></div><p id="cxSimpleStatus"></p></div><div class="cx-simple-card"><div class="cx-simple-toolbar"><h3>Matching records</h3><div class="cx-simple-count">' + list.length + ' shown / ' + state.entries.length + ' total</div><input id="cxSimpleSearch" class="cx-simple-input cx-simple-search" placeholder="Search this tab" value="' + esc(state.query) + '"></div></div>' + renderList(list);
    var addBtn = document.getElementById('cxSimpleQuickAdd');
    var search = document.getElementById('cxSimpleSearch');
    if (addBtn) addBtn.onclick = quickAdd;
    if (search) search.oninput = function(){ state.query = search.value; render(); };
  }

  window.addEventListener('cx-crm-ai-updated', loadEntries);
  var boot = setInterval(function(){ if (root() && side()) { clearInterval(boot); loadEntries(); } }, 250);
  setTimeout(function(){ clearInterval(boot); loadEntries(); }, 3000);
})();
`;

fs.writeFileSync(file, content);
console.log("CRM tabs simplified to basic actions and matching record lists.");
