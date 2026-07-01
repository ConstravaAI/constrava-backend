(function(){
  if (window.__constravaCanonicalCrmTabsLoaded) return;
  window.__constravaCanonicalCrmTabsLoaded = true;

  var params = new URLSearchParams(location.search);
  var token = params.get('token') || 'demo';
  var STORE_KEY = 'constravaCrmDemoAdds';
  var state = { active: 'all', entries: [], loading: false, query: '' };

  var tabs = [
    { id:'all', icon:'📋', label:'All Records', type:null, action:'Review every CRM data point in one clean list.', search:'Search all records...' },
    { id:'lead', icon:'🎯', label:'Leads', type:'Lead', action:'Track potential customers and follow up with them.', search:'Search leads...' },
    { id:'person', icon:'👤', label:'People', type:'Person', action:'Store people, contacts, and customers.', search:'Search people...' },
    { id:'company', icon:'🏢', label:'Companies', type:'Company', action:'Track organizations connected to records.', search:'Search companies...' },
    { id:'deal', icon:'💼', label:'Deals / Sales', type:'Deal', action:'Track opportunities, purchases, and sales.', search:'Search deals and sales...' },
    { id:'task', icon:'✅', label:'Tasks', type:'Task', action:'Track next steps and follow-up work.', search:'Search tasks...' },
    { id:'intake', icon:'📥', label:'Intake', type:'Intake', action:'Review new form submissions and messy incoming notes.', search:'Search intake records...' },
    { id:'note', icon:'📝', label:'Notes', type:'Note', action:'Keep plain notes attached to CRM records.', search:'Search notes...' },
    { id:'workflow', icon:'⚡', label:'Workflow Center', type:null, action:'Use AI to add, update, and route CRM records from one place.', search:'Search CRM context...' }
  ];

  var css = document.createElement('style');
  css.textContent = '.crm-modern-shell,.cx-entry-hub,.cx-form-panel{display:none!important}.crm-left.cx-simple-owned{padding:14px!important}.cx-simple-nav-title{margin:6px 8px 10px;color:#64748b;font-size:11px;font-weight:950;letter-spacing:.12em;text-transform:uppercase}.cx-simple-side-btn{display:flex!important;width:100%!important;gap:10px!important;align-items:center!important;border:0!important;background:transparent!important;border-radius:12px!important;padding:10px!important;margin:3px 0!important;text-align:left!important;color:#334155!important;cursor:pointer!important}.cx-simple-side-btn:hover,.cx-simple-side-btn.active{background:#eaf8f1!important;color:#047857!important}.cx-simple-side-btn strong{display:block;font-size:13px}.cx-simple-side-btn small{display:block;color:#64748b;font-size:10px;margin-top:2px}.crm-top.cx-simple-titlebar{height:auto!important;min-height:62px!important;padding:14px 18px!important;display:flex!important;align-items:center!important;justify-content:space-between!important;background:linear-gradient(135deg,#14352b,#052e24)!important;color:#fff!important}.crm-top.cx-simple-titlebar>button{display:none!important}.cx-simple-title strong{display:block;color:#fff;font-size:19px}.cx-simple-title span{display:block;color:rgba(226,232,240,.82);font-size:12px;margin-top:4px}.cx-simple-title-pill{border-radius:999px;background:rgba(255,255,255,.12);color:#d1fae5;padding:7px 10px;font-size:11px;font-weight:950}.cx-simple{display:grid;gap:14px}.cx-simple-card{border:1px solid #dbe8e4;border-radius:18px;background:#fff;box-shadow:0 10px 24px rgba(15,23,42,.05);padding:16px}.cx-simple-card h2,.cx-simple-card h3{margin:0;color:#022c22}.cx-simple-card p{margin:7px 0 0;color:#64748b;line-height:1.45}.cx-tab-search{margin-top:14px}.cx-simple-input,.cx-workflow-textarea{width:100%;border:1px solid #d8e0e7;border-radius:12px;background:#f8fafc;color:#0f172a;padding:11px 12px;font:inherit}.cx-workflow-textarea{min-height:120px;resize:vertical}.cx-workflow-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.cx-workflow-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}.cx-workflow-btn{border:1px solid #10b981;border-radius:12px;background:#10b981;color:#022c22;font-weight:950;padding:10px 14px;cursor:pointer}.cx-workflow-btn.secondary{border-color:#d8e0e7;background:#fff;color:#073d32}.cx-workflow-status{color:#64748b;font-size:13px;min-height:18px}.cx-simple-list{display:grid;gap:10px}.cx-simple-row{border:1px solid #e5e7eb;border-radius:15px;background:#fff;padding:13px}.cx-simple-row-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.cx-simple-row h4{margin:0;color:#022c22}.cx-simple-row p{margin:6px 0 0;color:#64748b;font-size:13px;line-height:1.45}.cx-simple-meta{display:flex;gap:7px;flex-wrap:wrap;margin-top:9px}.cx-simple-pill{display:inline-flex;border-radius:999px;padding:5px 8px;background:#ecfdf5;color:#047857;font-size:11px;font-weight:900}.cx-simple-pill.gray{background:#f1f5f9;color:#475569}.cx-simple-empty{border:1px dashed #b9ddd0;border-radius:16px;background:#f8fffc;color:#64748b;text-align:center;padding:28px}.cx-simple-empty b{display:block;color:#022c22;margin-bottom:6px}.cx-simple-toolbar{display:flex;gap:10px;justify-content:space-between;align-items:center;flex-wrap:wrap}.cx-simple-count{color:#64748b;font-size:13px;font-weight:800}@media(max-width:950px){.crm-top.cx-simple-titlebar{display:block!important}.cx-simple-title-pill{display:inline-flex;margin-top:10px}.cx-workflow-grid{grid-template-columns:1fr}.cx-simple-row-top{display:block}}';
  document.head.appendChild(css);

  function esc(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]; }); }
  function root(){ return document.querySelector('.crm-main') || document.querySelector('.crm-shell') || document.getElementById('crmArea'); }
  function side(){ return document.querySelector('.crm-left'); }
  function topbar(){ return document.querySelector('.crm-top'); }
  function saveSession(record){ var list = readSession(); if (Array.isArray(record)) list = record.concat(list); else list.unshift(record); sessionStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0,100))); }
  function readSession(){ try { var x = JSON.parse(sessionStorage.getItem(STORE_KEY) || '[]'); return Array.isArray(x) ? x : []; } catch(e){ return []; } }
  function addAll(target, list){ if(Array.isArray(list)) list.forEach(function(x){ if(x && typeof x === 'object') target.push(x); }); }
  function currentPageData(){ var out = []; try { if(window.dashboardData){ addAll(out, window.dashboardData.entries); addAll(out, window.dashboardData.records); addAll(out, window.dashboardData.leads); } } catch(e){} try { if(window.data){ addAll(out, window.data.entries); addAll(out, window.data.records); addAll(out, window.data.leads); } } catch(e){} addAll(out, readSession()); return out; }
  function dedupe(list){ var seen = {}; return list.filter(function(e, i){ var k = e.record_id || e.lead_id || e.id || (e.email && e.record_type ? (Array.isArray(e.record_type) ? e.record_type.join(',') : e.record_type) + '|' + e.email : '') || (e.name || '') + '|' + (e.company || '') + '|' + (e.deal_name || '') + '|' + (Array.isArray(e.record_type) ? e.record_type.join(',') : e.record_type || '') || ('row-' + i); if(seen[k]) return false; seen[k] = true; return true; }); }
  function valueNum(e){ return Number(String(e.value || e.deal_value || e.amount || e.budget || 0).replace(/[$,]/g,'')) || 0; }

  function splitTypeValues(value){
    if (Array.isArray(value)) return value.flatMap(splitTypeValues);
    if (value && typeof value === 'object') return Object.values(value).flatMap(splitTypeValues);
    return String(value || '').split(/[;,|/+]+/).map(function(v){ return v.trim(); }).filter(Boolean);
  }
  function canonicalTypeValue(value){
    var key = String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
    if (!key) return [];
    if (['lead','leads','ai-text-lead','form-lead'].includes(key)) return ['Lead'];
    if (['person','people','contact','contacts','client','clients','customer','customers'].includes(key)) return ['Person'];
    if (['company','companies','organization','organizations','business','businesses','account','accounts'].includes(key)) return ['Company'];
    if (['deal','deals','sale','sales','purchase','purchases','opportunity','opportunities'].includes(key)) return ['Deal'];
    if (['task','tasks','todo','todos','followup','followups','follow-up','follow-ups','follow-up-task','call-log','email-activity','activity','activities'].includes(key)) return ['Task'];
    if (['intake','form','forms','submission','submissions','google-forms','external-form-lead','website-form-lead'].includes(key)) return ['Lead','Intake'];
    if (['note','notes'].includes(key)) return ['Note'];
    return [];
  }
  function uniqueTypes(list){ var out = []; list.forEach(function(type){ if(type && out.indexOf(type) === -1) out.push(type); }); return out; }
  function canonicalTypesFromValues(values){ return uniqueTypes(values.flatMap(function(v){ return canonicalTypeValue(v); })); }
  function guessTypes(e){
    var module = String(e.module || e.crm_module || e.record_module || '').toLowerCase();
    var sourceText = [e.source,e.provider,e.channel,e.notes,e.message,e.body,e.description,e.deal_name,e.next_step,e.raw_submission && e.raw_submission.text].join(' ').toLowerCase();
    var guessed = [];
    if (/intake|form|submission|google|website form/.test(module + ' ' + sourceText)) guessed.push('Lead','Intake');
    else if (/task|todo|follow|call|meeting|email/.test(module + ' ' + sourceText)) guessed.push('Task');
    else if (/deal|sale|purchase|opportunity|proposal|quote|contract/.test(module + ' ' + sourceText) || valueNum(e) > 0 && e.deal_name) guessed.push('Deal');
    else if (/contact|person|people|client|customer/.test(module)) guessed.push('Person');
    else if (/company|account|organization|business/.test(module)) guessed.push('Company');
    else if (/note/.test(module + ' ' + sourceText)) guessed.push('Note');
    else guessed.push('Lead');
    return uniqueTypes(guessed);
  }
  function recordTypes(e){
    var explicit = [];
    addAll(explicit, e.record_types);
    explicit = explicit.concat(splitTypeValues(e.record_type)).concat(splitTypeValues(e.types)).concat(splitTypeValues(e.primary_type)).concat(splitTypeValues(e.type));
    var types = canonicalTypesFromValues(explicit);
    if (!types.length) types = guessTypes(e);
    e.record_type = types.length === 1 ? types[0] : types.slice();
    return types;
  }
  function normalizeEntry(e, i){ e = e || {}; var types = recordTypes(e); if(!e.lead_id && !e.record_id && !e.id) e.lead_id = 'LOCAL-' + Date.now() + '-' + i; if(!e.status && !e.stage) e.status = 'New'; if(!e.record_type) e.record_type = types[0] || 'Lead'; return e; }
  function activeTab(){ return tabs.filter(function(t){ return t.id === state.active; })[0] || tabs[0]; }
  function matchesTab(e, tab){ if(tab.id === 'workflow') return true; if(!tab.type) return true; return recordTypes(e).indexOf(tab.type) !== -1; }
  function displayedEntries(){ var tab = activeTab(); var q = state.query.toLowerCase().trim(); return state.entries.filter(function(e){ if(!matchesTab(e, tab)) return false; if(!q) return true; return JSON.stringify(e).toLowerCase().indexOf(q) !== -1; }); }
  function titleFor(e){ return e.name || e.company || e.deal_name || e.title || e.email || 'Unnamed record'; }
  function subline(e){ return [e.company, e.email, e.phone || e.mobile].filter(Boolean).join(' • ') || e.source || 'No details yet'; }
  function description(e){ return e.notes || e.message || e.next_step || e.deal_name || e.status || 'No notes yet.'; }

  async function loadEntries(){
    state.loading = true;
    var collected = currentPageData();
    try {
      var r = await fetch('/api/crm/entries?token=' + encodeURIComponent(token) + '&type=all', { cache:'no-store' });
      var j = await r.json();
      addAll(collected, j.entries); addAll(collected, j.records); addAll(collected, j.leads);
    } catch (err) {}
    state.entries = dedupe(collected).map(normalizeEntry);
    state.loading = false;
    render();
  }

  function guessTextTypes(text){
    var t = String(text || '').toLowerCase();
    var types = [];
    var explicit = t.match(/record\s*type\s*:?\s*([a-z, /+-]+)/i) || t.match(/type\s*:?\s*([a-z, /+-]+)/i);
    if (explicit) types = canonicalTypesFromValues(splitTypeValues(explicit[1]));
    if (!types.length) {
      if (/form submission|website form|google form|intake/.test(t)) types.push('Lead','Intake');
      else if (/task|todo|follow-up task|follow up task/.test(t)) types.push('Task');
      else if (/note only|new note|crm note/.test(t)) types.push('Note');
      else if (/company record|account record|organization record|business record/.test(t)) types.push('Company');
      else if (/person record|contact record|customer record|client record/.test(t)) types.push('Person');
      else if (/deal record|sales record|opportunity record|purchase record|proposal record|contract record/.test(t)) types.push('Deal');
      else types.push('Lead');
    }
    return uniqueTypes(types.length ? types : ['Lead']);
  }
  function parsedPersonFromText(text){
    var email = (text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)||[''])[0];
    var phone = (text.match(/(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/)||[''])[0];
    var nameMatch = text.match(/(?:named|name is|lead is|person is|contact is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})/) || text.match(/^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\s+from\s+/);
    var companyMatch = text.match(/from\s+([A-Z][A-Za-z0-9& .-]{2,60})(?:\s+(?:reached|wants|needs|is|and|with)|[.,]|$)/);
    return { name: nameMatch ? nameMatch[1].trim() : (email ? email.split('@')[0].replace(/[._-]+/g,' ') : 'Unknown Person'), email: email, phone: phone, company: companyMatch ? companyMatch[1].trim() : 'AI Added Record' };
  }
  function defaultTypePlan(count, text){
    var base = guessTextTypes(text);
    if (count === 1) return [base.join('+')];
    var plan = [base.join('+'), 'Person'];
    var extras = ['Company','Deal','Task','Intake','Note'];
    while (plan.length < count) plan.push(extras[(plan.length - 2) % extras.length]);
    return plan.slice(0, count);
  }
  function askRecordPlan(text){
    var rawCount = prompt('How many CRM records should I create from this text?\n\nEnter 1 or more. Example: 1, 2, 3', '1');
    if (rawCount === null) return null;
    var count = Math.max(1, Math.min(12, parseInt(rawCount, 10) || 1));
    var suggested = defaultTypePlan(count, text);
    var rawTypes = prompt('What type should each record be?\n\nAllowed types: Lead, Person, Company, Deal, Task, Intake, Note.\nUse commas for separate records. Use + for multiple types on one record.\n\nExample: Lead, Person\nExample: Lead+Intake, Person, Task', suggested.join(', '));
    if (rawTypes === null) return null;
    var parts = String(rawTypes || '').split(',').map(function(x){ return x.trim(); }).filter(Boolean);
    if (!parts.length) parts = suggested;
    while (parts.length < count) parts.push(suggested[parts.length] || 'Lead');
    return { count: count, typeParts: parts.slice(0, count) };
  }
  function typesFromPlanPart(part){
    var types = canonicalTypesFromValues(splitTypeValues(part));
    return types.length ? types : ['Lead'];
  }
  function recordNameForType(type, person, company){
    if (type === 'Person') return person.name || 'Unknown Person';
    if (type === 'Company') return company || person.company || 'Company Record';
    if (type === 'Deal') return 'Deal for ' + (company || person.company || person.name || 'CRM Record');
    if (type === 'Task') return 'Follow up with ' + (person.name || company || 'CRM contact');
    if (type === 'Intake') return 'Intake from ' + (person.name || company || 'CRM source');
    if (type === 'Note') return 'Note about ' + (person.name || company || 'CRM record');
    return (person.name || company || 'AI Text') + ' lead';
  }
  function buildRecordFromType(text, serverRecord, typePart, index, baseId, allIds){
    var person = parsedPersonFromText(text);
    var types = typesFromPlanPart(typePart);
    var primary = types[0] || 'Lead';
    var valueMatch = text.replace(/,/g,'').match(/\$?\b(\d{3,7})\b/);
    var recordId = baseId + '-R' + (index + 1);
    var company = person.company || 'AI Added Record';
    var record = {
      lead_id: recordId,
      record_id: recordId,
      record_type: types.length === 1 ? types[0] : types,
      module: primary === 'Person' ? 'people' : primary === 'Company' ? 'companies' : primary === 'Deal' ? 'deals' : primary === 'Task' ? 'tasks' : primary === 'Intake' ? 'intake' : primary === 'Note' ? 'notes' : 'leads',
      name: recordNameForType(primary, person, company),
      email: primary === 'Company' || primary === 'Deal' || primary === 'Task' || primary === 'Note' ? '' : person.email,
      phone: primary === 'Company' || primary === 'Deal' || primary === 'Task' || primary === 'Note' ? '' : person.phone,
      company: company,
      status: primary === 'Person' || primary === 'Company' ? 'Active' : (/qualified|ready|serious/i.test(text) ? 'Qualified' : 'New'),
      priority: /urgent|soon|ready|high/i.test(text) ? 'High' : 'Normal',
      source: 'AI Text Add',
      value: primary === 'Deal' || primary === 'Lead' ? (valueMatch ? Number(valueMatch[1]) : 0) : 0,
      deal_name: primary === 'Deal' ? recordNameForType(primary, person, company) : '',
      next_step: primary === 'Task' ? 'Follow up based on AI text input.' : '',
      notes: (primary === 'Person' ? 'Person record created from AI text input.' : primary + ' record created from AI text input.') + '\n\nOriginal text: ' + text,
      raw_submission: { text: text, requested_record_number: index + 1, requested_type_text: typePart },
      related_record_ids: allIds.filter(function(id){ return id !== recordId; })
    };
    if (index === 0 && serverRecord) record = Object.assign({}, serverRecord, record);
    return normalizeEntry(record, index);
  }
  function recordsFromTextPlan(text, serverRecord, plan){
    var baseId = 'AI-' + Date.now();
    var ids = [];
    for (var i = 0; i < plan.count; i++) ids.push(baseId + '-R' + (i + 1));
    return plan.typeParts.map(function(part, index){ return buildRecordFromType(text, index === 0 ? serverRecord : null, part, index, baseId, ids); });
  }

  async function aiAddFromWorkflow(){
    var input = document.getElementById('cxWorkflowAiInput');
    var status = document.getElementById('cxWorkflowStatus');
    var text = input ? input.value.trim() : '';
    if(!text) return;
    var plan = askRecordPlan(text);
    if (!plan) { if(status) status.textContent = 'AI add cancelled.'; return; }
    if(status) status.textContent = 'Saving ' + plan.count + ' record' + (plan.count === 1 ? '' : 's') + ' with AI...';
    var records = [];
    try {
      var r = await fetch('/api/crm/ai-entry?token=' + encodeURIComponent(token), { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ token: token, text: text, requested_record_count: plan.count, requested_record_types: plan.typeParts }) });
      var j = await r.json();
      if(!j.ok) throw new Error(j.error || 'Could not save.');
      records = recordsFromTextPlan(text, j.entry || j.record || j.lead || null, plan);
      if(input) input.value = '';
      if(status) status.textContent = 'Saved ' + records.length + ' CRM record' + (records.length === 1 ? '' : 's') + '.';
    } catch (err) {
      records = recordsFromTextPlan(text, null, plan);
      if(status) status.textContent = 'Saved ' + records.length + ' record' + (records.length === 1 ? '' : 's') + ' locally for this session. Backend response was not visible.';
    }
    saveSession(records);
    state.entries = dedupe(records.concat(state.entries, currentPageData())).map(normalizeEntry);
    state.active = 'all';
    render();
    window.dispatchEvent(new CustomEvent('cx-crm-ai-updated', { detail: records }));
  }

  function rebuildSide(){ var el = side(); if(!el) return; el.classList.add('cx-simple-owned'); el.innerHTML = '<div class="cx-simple-nav-title">CRM tabs</div>' + tabs.map(function(t){ return '<button class="cx-simple-side-btn" type="button" data-simple-tab="' + esc(t.id) + '"><span>' + t.icon + '</span><span><strong>' + esc(t.label) + '</strong><small>' + esc(t.action) + '</small></span></button>'; }).join(''); Array.prototype.forEach.call(el.querySelectorAll('[data-simple-tab]'), function(btn){ btn.onclick = function(){ state.active = btn.getAttribute('data-simple-tab'); state.query = ''; render(); }; }); }
  function updateTop(){ var el = topbar(); if(!el) return; var tab = activeTab(); el.classList.add('cx-simple-titlebar'); el.innerHTML = '<div class="cx-simple-title"><strong>' + esc(tab.label) + '</strong><span>' + esc(tab.action) + '</span></div><div class="cx-simple-title-pill">Canonical record types</div>'; }
  function ensurePanel(){ var r = root(); if(!r) return null; var panel = document.getElementById('cxSimpleCrmRoot'); if(!panel){ panel = document.createElement('div'); panel.id = 'cxSimpleCrmRoot'; panel.className = 'cx-simple'; r.insertBefore(panel, r.firstChild || null); } return panel; }
  function renderList(list, limit){ var items = typeof limit === 'number' ? list.slice(0, limit) : list; if(state.loading) return '<div class="cx-simple-empty">Loading records...</div>'; if(!items.length) return '<div class="cx-simple-empty"><b>No matching records</b>Total loaded: ' + state.entries.length + '. This tab only shows records whose record_type includes this tab type. Open All Records, clear search, or change the record_type.</div>'; return '<div class="cx-simple-list">' + items.map(function(e){ var types = recordTypes(e).map(function(t){ return '<span class="cx-simple-pill gray">' + esc(t) + '</span>'; }).join(''); return '<div class="cx-simple-row"><div class="cx-simple-row-top"><div><h4>' + esc(titleFor(e)) + '</h4><p>' + esc(subline(e)) + '</p></div><span class="cx-simple-pill">' + esc(e.status || e.data_quality || 'record') + '</span></div><p>' + esc(description(e)) + '</p><div class="cx-simple-meta">' + types + '</div></div>'; }).join('') + '</div>'; }
  function renderWorkflow(panel){ var list = displayedEntries(); panel.innerHTML = '<div class="cx-workflow-grid"><div class="cx-simple-card"><h2>CRM Workflow Center</h2><p>Use this tab when you want the AI to create, update, classify, or connect CRM records from plain text.</p><textarea id="cxWorkflowAiInput" class="cx-workflow-textarea" placeholder="Example: New lead named Lidia from Price Home Renovations. She wants a website quote and asked me to call back tomorrow."></textarea><div class="cx-workflow-actions"><button id="cxWorkflowAiBtn" class="cx-workflow-btn" type="button">AI Add / Update</button><button id="cxWorkflowReloadBtn" class="cx-workflow-btn secondary" type="button">Reload Records</button></div><p id="cxWorkflowStatus" class="cx-workflow-status"></p></div><div class="cx-simple-card"><h3>Workflow context</h3><p>Total records: <b>' + state.entries.length + '</b></p><p>AI Add first asks how many records to create, then asks for canonical types: Lead, Person, Company, Deal, Task, Intake, Note. Use + for multiple types on one record.</p><div class="cx-tab-search"><input id="cxTabSearch" class="cx-simple-input" placeholder="Search CRM context..." value="' + esc(state.query) + '"></div></div></div><div class="cx-simple-card"><div class="cx-simple-toolbar"><h3>Recent / matching CRM context</h3><div class="cx-simple-count">' + list.length + ' matching</div></div></div>' + renderList(list, 12); var aiBtn = document.getElementById('cxWorkflowAiBtn'); var reloadBtn = document.getElementById('cxWorkflowReloadBtn'); var search = document.getElementById('cxTabSearch'); if(aiBtn) aiBtn.onclick = aiAddFromWorkflow; if(reloadBtn) reloadBtn.onclick = loadEntries; if(search) search.oninput = function(){ state.query = search.value; render(); }; }
  function render(){ rebuildSide(); updateTop(); var panel = ensurePanel(); if(!panel) return; var tab = activeTab(); Array.prototype.forEach.call(document.querySelectorAll('[data-simple-tab]'), function(btn){ btn.classList.toggle('active', btn.getAttribute('data-simple-tab') === state.active); }); if(tab.id === 'workflow') { renderWorkflow(panel); return; } var list = displayedEntries(); panel.innerHTML = '<div class="cx-simple-card"><h2>' + esc(tab.label) + '</h2><p><b>Basic function:</b> ' + esc(tab.action) + '</p><div class="cx-tab-search"><input id="cxTabSearch" class="cx-simple-input" placeholder="' + esc(tab.search) + '" value="' + esc(state.query) + '"></div></div><div class="cx-simple-card"><div class="cx-simple-toolbar"><h3>Matching records</h3><div class="cx-simple-count">' + list.length + ' shown / ' + state.entries.length + ' total</div></div></div>' + renderList(list); var search = document.getElementById('cxTabSearch'); if(search) search.oninput = function(){ state.query = search.value; render(); }; }

  window.addEventListener('cx-crm-ai-updated', loadEntries);
  var boot = setInterval(function(){ if(root() && side()) { clearInterval(boot); loadEntries(); } }, 250);
  setTimeout(function(){ clearInterval(boot); loadEntries(); }, 3000);
})();
