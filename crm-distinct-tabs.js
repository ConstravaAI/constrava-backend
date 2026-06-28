(function(){
  if (window.__constravaDistinctCrmTabsLoaded) return;
  window.__constravaDistinctCrmTabsLoaded = true;

  const params = new URLSearchParams(location.search);
  const token = params.get('token') || 'demo';
  const isPrivate = params.get('mode') === 'private' || params.get('private') === '1' || location.pathname.startsWith('/app');
  const GOOGLE_CONNECTION_KEY = 'constravaGoogleFormsConnectionId';
  const GOOGLE_FORM_KEY = 'constravaSelectedGoogleForm';

  if (isPrivate && params.get('googleFormsConnected') === '1' && params.get('connectionId')) {
    sessionStorage.setItem(GOOGLE_CONNECTION_KEY, params.get('connectionId'));
  }

  const tabs = [
    { id:'overview', icon:'📊', label:'Overview', desc:'CRM command dashboard' },
    { id:'full-list', icon:'📋', label:'Full List', desc:'Every CRM entry' },
    { id:'intake', icon:'📥', label:'Intake Inbox', desc:'New and messy submissions' },
    { id:'leads', icon:'🎯', label:'Leads', desc:'Potential clients' },
    { id:'contacts', icon:'👤', label:'Contacts', desc:'People' },
    { id:'companies', icon:'🏢', label:'Companies', desc:'Organizations' },
    { id:'deals', icon:'💼', label:'Deals', desc:'Money opportunities' },
    { id:'tasks', icon:'✅', label:'Tasks / Follow-Ups', desc:'Next actions' },
    { id:'forms', icon:'🧾', label:'Forms', desc:'Connected intake sources' },
    { id:'ai', icon:'✨', label:'AI Command Center', desc:'Plain-text CRM control' },
    { id:'reports', icon:'📈', label:'Reports', desc:'Pipeline analytics' },
    { id:'settings', icon:'⚙️', label:'Settings', desc:'Stages and AI rules' }
  ];

  const state = { active:'overview', entries:[], loading:false, query:'', forms:[], selectedForm:{} };

  const style = document.createElement('style');
  style.textContent = `
    .crm-modern-shell,.cx-entry-hub,.cx-form-panel{display:none!important}.cx-dcrm{display:grid;gap:16px}.cx-dcrm-hero{border:1px solid #dbe8e4;border-radius:22px;background:linear-gradient(135deg,#fff,#f0fdf4);box-shadow:0 12px 28px rgba(15,23,42,.06);padding:18px}.cx-dcrm-hero h2{margin:0;color:#022c22;letter-spacing:-.04em}.cx-dcrm-hero p{margin:7px 0 0;color:#64748b;line-height:1.5}.cx-dcrm-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.cx-dcrm-card{border:1px solid #dbe8e4;border-radius:18px;background:#fff;box-shadow:0 10px 24px rgba(15,23,42,.05);padding:15px}.cx-dcrm-card h3,.cx-dcrm-card h4{margin:0 0 8px;color:#022c22}.cx-dcrm-card p{margin:0;color:#64748b;font-size:13px;line-height:1.45}.cx-kpi span{display:block;color:#64748b;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.08em}.cx-kpi strong{display:block;margin-top:7px;color:#073d32;font-size:30px;letter-spacing:-.05em}.cx-two{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.cx-three{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.cx-table-wrap{overflow:auto;border:1px solid #e5e7eb;border-radius:14px;background:#fff;max-height:610px}.cx-table{width:100%;min-width:980px;border-collapse:collapse;font-size:12px}.cx-table th{position:sticky;top:0;background:#f8fafc;color:#64748b;text-align:left;text-transform:uppercase;letter-spacing:.08em;font-size:10px;padding:10px;border-bottom:1px solid #e5e7eb}.cx-table td{padding:11px 10px;border-bottom:1px solid #eef2f7;vertical-align:top}.cx-table b{color:#0f172a}.cx-table small{display:block;color:#64748b;margin-top:3px}.cx-pill{display:inline-flex;border-radius:999px;padding:5px 8px;background:#ecfdf5;color:#047857;font-weight:900;font-size:11px}.cx-pill.warn{background:#fffbeb;color:#92400e}.cx-pill.dark{background:#052e24;color:#d1fae5}.cx-list{display:grid;gap:10px}.cx-item{border:1px solid #e5e7eb;border-radius:14px;background:#fff;padding:12px}.cx-item-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.cx-item h4{margin:0;color:#022c22}.cx-item p{margin:6px 0 0;color:#64748b;font-size:13px;line-height:1.45}.cx-actions{display:flex;gap:8px;flex-wrap:wrap}.cx-btn{border:1px solid #d8e0e7;border-radius:11px;background:#fff;color:#073d32;font-weight:900;padding:10px 12px;cursor:pointer}.cx-btn.primary{background:#10b981;border-color:#10b981;color:#022c22}.cx-btn.dark{background:#052e24;border-color:#052e24;color:#d1fae5}.cx-input,.cx-textarea,.cx-select{width:100%;border:1px solid #d8e0e7;border-radius:12px;background:#f8fafc;color:#0f172a;padding:11px 12px;font:inherit}.cx-textarea{min-height:105px;resize:vertical}.cx-toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between}.cx-search{width:min(430px,100%)}.cx-kanban{display:grid;grid-template-columns:repeat(5,minmax(190px,1fr));gap:12px;overflow:auto}.cx-col{background:#f8fafc;border:1px solid #e5e7eb;border-radius:15px;padding:10px;min-height:240px}.cx-col h4{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin:0 0 10px}.cx-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.cx-wide{grid-column:1/-1}.cx-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5;max-height:350px}.cx-status{border:1px solid #dbe8e4;border-radius:13px;background:#f8fafc;color:#334155;padding:11px 12px;font-size:13px;line-height:1.45}.cx-status.ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}.cx-status.warn{background:#fffbeb;color:#92400e;border-color:rgba(245,158,11,.35)}.cx-bars{display:grid;gap:10px}.cx-bar{display:grid;grid-template-columns:130px 1fr auto;gap:10px;align-items:center;font-size:12px}.cx-track{height:11px;border-radius:999px;background:#e8f4ef;overflow:hidden}.cx-fill{height:100%;background:linear-gradient(90deg,#059669,#34d399)}.crm-left.cx-owned{padding:14px!important}.cx-nav-title{margin:6px 8px 10px;color:#64748b;font-size:11px;font-weight:950;letter-spacing:.12em;text-transform:uppercase}.cx-side-btn{display:flex!important;width:100%!important;gap:10px!important;align-items:flex-start!important;border:0!important;background:transparent!important;border-radius:12px!important;padding:10px!important;margin:3px 0!important;text-align:left!important;color:#334155!important}.cx-side-btn:hover,.cx-side-btn.active{background:#eaf6fd!important;color:#0b85be!important}.cx-side-btn strong{display:block;font-size:13px}.cx-side-btn small{display:block;color:#64748b;font-size:10px;margin-top:2px;line-height:1.25}.crm-top.cx-dcrm-titlebar{height:auto!important;min-height:66px!important;padding:14px 18px!important;display:flex!important;align-items:center!important;justify-content:space-between!important;background:linear-gradient(135deg,#26394d,#1d2f41)!important;color:#fff!important}.crm-top.cx-dcrm-titlebar button{display:none!important}.cx-titlebox strong{display:block;font-size:19px;color:#fff}.cx-titlebox span{display:block;color:rgba(226,232,240,.82);font-size:12px;margin-top:4px}.cx-empty{border:1px dashed #b9ddd0;border-radius:16px;background:#f8fffc;color:#64748b;text-align:center;padding:30px}.cx-empty b{display:block;color:#022c22;margin-bottom:6px}.cx-detail{font-size:12px;color:#64748b;line-height:1.45}.cx-settings-row{display:grid;grid-template-columns:220px 1fr;gap:12px;align-items:start;padding:12px 0;border-bottom:1px solid #eef2f7}@media(max-width:1100px){.cx-dcrm-grid,.cx-three,.cx-two,.cx-form-grid{grid-template-columns:1fr}.cx-kanban{grid-template-columns:1fr}.cx-wide{grid-column:auto}.cx-settings-row{grid-template-columns:1fr}}`;
  document.head.appendChild(style);

  function esc(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c])); }
  function money(n){ return Number(n||0) ? new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(Number(n||0)) : '$0'; }
  function date(v){ const d = new Date(v || Date.now()); return isNaN(d) ? '' : d.toISOString().slice(0,10); }
  function getStatus(e){ return String(e.status || e.stage || 'New'); }
  function stageKey(v){ return String(v || 'new').toLowerCase().replace(/[^a-z0-9]+/g,'-'); }
  function contactInfo(e){ return [e.email, e.phone || e.mobile].filter(Boolean).join(' • ') || 'No contact info yet'; }
  function isTask(e){ return /task|follow|todo|call|meeting/i.test([e.record_type,e.module,e.next_step,e.notes].join(' ')); }
  function isDeal(e){ return Number(e.value) > 0 || !!e.deal_name; }
  function isClosed(e){ return /closed|won|lost/i.test(getStatus(e)); }
  function isForm(e){ return /form|google|website|intake/i.test([e.source,e.provider,e.record_type,e.form_slug,e.tags].join(' ')); }
  function isIntake(e){ return isForm(e) || /new|review/i.test([e.status,e.priority].join(' ')) || !e.email || !e.company; }
  function entries(){ return Array.isArray(state.entries) ? state.entries : []; }
  function filtered(list){ const q = state.query.trim().toLowerCase(); if(!q) return list; return list.filter(e => JSON.stringify(e).toLowerCase().includes(q)); }
  function root(){ return document.querySelector('.crm-main') || document.querySelector('.crm-shell') || document.getElementById('crmArea'); }
  function side(){ return document.querySelector('.crm-left'); }
  function topbar(){ return document.querySelector('.crm-top'); }
  function titleFor(id){ return tabs.find(t => t.id === id) || tabs[0]; }

  async function loadEntries(){
    state.loading = true;
    try {
      const r = await fetch('/api/crm/entries?token=' + encodeURIComponent(token) + '&type=all', { cache:'no-store' });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Could not load CRM entries.');
      state.entries = j.entries || j.leads || [];
    } catch (err) {
      try { state.entries = (window.dashboardData && window.dashboardData.leads) || (window.data && window.data.leads) || []; } catch { state.entries = []; }
    }
    state.loading = false;
    render();
  }

  function rebuildSide(){
    const el = side(); if(!el) return;
    if (el.__cxDistinctBuilt) return;
    el.__cxDistinctBuilt = true;
    el.classList.add('cx-owned');
    el.innerHTML = '<div class="cx-nav-title">CRM sections</div>' + tabs.map(t => `<button class="cx-side-btn" type="button" data-cx-tab="${t.id}"><span>${t.icon}</span><span><strong>${esc(t.label)}</strong><small>${esc(t.desc)}</small></span></button>`).join('');
    el.querySelectorAll('[data-cx-tab]').forEach(btn => btn.onclick = () => { state.active = btn.getAttribute('data-cx-tab'); state.query = ''; render(); });
  }

  function updateTitle(){
    const top = topbar(); if(!top) return;
    const t = titleFor(state.active);
    top.classList.add('cx-dcrm-titlebar');
    top.innerHTML = `<div class="cx-titlebox"><strong>${esc(t.label)}</strong><span>${esc(t.desc)} • One unified CRM list</span></div><div class="cx-pill dark">Side tabs only</div>`;
  }

  function ensureRoot(){
    const r = root(); if(!r) return null;
    let panel = document.getElementById('cxDistinctCrmRoot');
    if(!panel){
      panel = document.createElement('div');
      panel.id = 'cxDistinctCrmRoot';
      panel.className = 'cx-dcrm';
      r.insertBefore(panel, r.firstChild || null);
    }
    return panel;
  }

  function kpis(){
    const list = entries();
    const open = list.filter(e => !isClosed(e)).length;
    const deals = list.filter(isDeal);
    const tasks = list.filter(e => e.next_step || isTask(e)).length;
    const value = deals.reduce((s,e)=>s+(Number(e.value)||0),0);
    return `<div class="cx-dcrm-grid"><div class="cx-dcrm-card cx-kpi"><span>Total entries</span><strong>${list.length}</strong></div><div class="cx-dcrm-card cx-kpi"><span>Open records</span><strong>${open}</strong></div><div class="cx-dcrm-card cx-kpi"><span>Pipeline value</span><strong>${money(value)}</strong></div><div class="cx-dcrm-card cx-kpi"><span>Next steps</span><strong>${tasks}</strong></div></div>`;
  }

  function row(e){
    return `<tr><td><b>${esc(e.name || 'Unnamed')}</b><small>${esc(e.lead_id || e.id || '')}</small></td><td>${esc(e.company || '—')}<small>${esc(e.industry || e.title || '')}</small></td><td>${esc(contactInfo(e))}</td><td><b>${esc(e.deal_name || e.record_type || 'CRM entry')}</b><small>${esc(e.source || '')}</small></td><td><span class="cx-pill">${esc(getStatus(e))}</span><small>${esc(e.priority || '')}</small></td><td>${money(e.value)}<small>${Number(e.probability||0) ? esc(e.probability)+'% prob.' : ''}</small></td><td>${esc(e.next_step || 'Review entry')}<small>${esc(date(e.created_at))}</small></td></tr>`;
  }

  function table(list){
    const out = filtered(list);
    if(!out.length) return empty('No matching entries','Try clearing search or adding a new form/AI entry.');
    return `<div class="cx-table-wrap"><table class="cx-table"><thead><tr><th>Name</th><th>Company</th><th>Contact</th><th>Deal / Type</th><th>Status</th><th>Value</th><th>Next Step</th></tr></thead><tbody>${out.map(row).join('')}</tbody></table></div>`;
  }

  function empty(title, msg){ return `<div class="cx-empty"><b>${esc(title)}</b>${esc(msg || '')}</div>`; }
  function toolbar(label){ return `<div class="cx-toolbar"><div><h3 style="margin:0;color:#022c22">${esc(label)}</h3><p class="cx-detail">Filtered from the same unified CRM entry list.</p></div><input class="cx-input cx-search" id="cxCrmSearch" placeholder="Search this section" value="${esc(state.query)}"></div>`; }

  function overview(){
    const recent = entries().slice(0,6);
    const due = entries().filter(e => e.next_step).slice(0,6);
    return hero('Overview','A command dashboard for the unified CRM list.') + kpis() + `<div class="cx-two"><div class="cx-dcrm-card"><h3>Recent activity</h3><div class="cx-list">${recent.length ? recent.map(item).join('') : empty('No recent entries','Connected forms and AI commands will appear here.')}</div></div><div class="cx-dcrm-card"><h3>Upcoming follow-ups</h3><div class="cx-list">${due.length ? due.map(taskItem).join('') : empty('No follow-ups yet','Next steps will appear here.')}</div></div></div>`;
  }

  function item(e){ return `<div class="cx-item"><div class="cx-item-top"><div><h4>${esc(e.name || e.company || 'CRM entry')}</h4><p>${esc(e.company || e.deal_name || e.notes || 'No details yet')}</p></div><span class="cx-pill">${esc(getStatus(e))}</span></div></div>`; }
  function taskItem(e){ return `<div class="cx-item"><h4>${esc(e.next_step || 'Follow up')}</h4><p>${esc(e.name || '')} ${e.company ? '• '+esc(e.company) : ''}</p></div>`; }
  function hero(title, desc){ return `<div class="cx-dcrm-hero"><h2>${esc(title)}</h2><p>${esc(desc)}</p></div>`; }

  function fullList(){ return hero('Full List','The master source of truth. Every CRM function pulls from this same list.') + toolbar('All entries') + table(entries()); }
  function intake(){
    const list = entries().filter(isIntake);
    return hero('Intake Inbox','Review new form submissions, AI-created entries, missing fields, and uncertain records before action.') + toolbar('Needs review') + table(list);
  }
  function leads(){
    const list = entries().filter(e => !isTask(e) && !isClosed(e));
    return hero('Leads','Potential clients that are not closed yet.') + toolbar('Lead pipeline') + `<div class="cx-list">${filtered(list).length ? filtered(list).map(e => `<div class="cx-item"><div class="cx-item-top"><div><h4>${esc(e.name || 'Lead')}</h4><p>${esc(e.company || '')} • ${esc(contactInfo(e))}</p><p>${esc(e.notes || e.next_step || '')}</p></div><span class="cx-pill">${esc(getStatus(e))}</span></div></div>`).join('') : empty('No leads','New lead entries will appear here.')}</div>`;
  }
  function contacts(){
    const list = entries().filter(e => e.name || e.email || e.phone || e.mobile);
    return hero('Contacts','People only: names, emails, phone numbers, roles, and last-contact context.') + toolbar('People') + table(list);
  }
  function companies(){
    const groups = {};
    entries().forEach(e => { const c = e.company || 'Individual / Unknown Company'; groups[c] = groups[c] || { company:c, entries:[], value:0 }; groups[c].entries.push(e); groups[c].value += Number(e.value)||0; });
    const list = filtered(Object.values(groups).map(g => ({ name:g.company, company:g.company, deal_name:g.entries.length+' related entries', value:g.value, status:g.entries.length+' records', next_step:'Open related contacts, deals, and form submissions.', notes:g.entries.map(e=>e.name).join(', ') })));
    return hero('Companies','Organizations grouped from the unified list. Multiple contacts and deals can roll up under one company.') + toolbar('Organizations') + table(list);
  }
  function deals(){
    const dealList = filtered(entries().filter(isDeal));
    const stages = ['New','Qualified','Proposal','Negotiation','Closed Won'];
    return hero('Deals','Opportunities with value, probability, expected revenue, close date, and next step.') + `<div class="cx-kanban">${stages.map(stage => { const col = dealList.filter(e => stageKey(getStatus(e)) === stageKey(stage) || (stage === 'New' && !stages.slice(1).some(s=>stageKey(getStatus(e))===stageKey(s)))); return `<div class="cx-col"><h4>${esc(stage)} • ${col.length}</h4>${col.map(e => `<div class="cx-item"><h4>${esc(e.deal_name || e.company || 'Deal')}</h4><p>${esc(e.name || '')} ${e.company ? '• '+esc(e.company) : ''}</p><p><b>${money(e.value)}</b> ${Number(e.probability||0) ? '• '+esc(e.probability)+'%' : ''}</p></div>`).join('') || '<p class="cx-detail">No deals.</p>'}</div>`; }).join('')}</div>`;
  }
  function tasks(){
    const list = entries().filter(e => e.next_step || isTask(e));
    return hero('Tasks / Follow-Ups','Actions the CRM user needs to take next, pulled from entry next_step fields and AI updates.') + toolbar('Next actions') + `<div class="cx-list">${filtered(list).length ? filtered(list).map(taskItem).join('') : empty('No tasks yet','AI commands and forms can create next steps.')}</div>`;
  }

  function selectedForm(){ try { return JSON.parse(sessionStorage.getItem(GOOGLE_FORM_KEY) || '{}'); } catch { return {}; } }
  function saveForm(f){ sessionStorage.setItem(GOOGLE_FORM_KEY, JSON.stringify(f || {})); }
  function formEndpoint(){ return 'https://constravaai.com/api/forms/intake/constrava-crm/' + encodeURIComponent((selectedForm().name || 'google-form').toLowerCase().replace(/[^a-z0-9]+/g,'-') || 'google-form'); }
  function appScript(){ const f = selectedForm(); return `const CONSTRAVA_ENDPOINT = "${formEndpoint()}";\n\nfunction onFormSubmit(e) {\n  const data = {};\n  if (e && e.namedValues) {\n    Object.keys(e.namedValues).forEach(function(fieldName) {\n      const value = e.namedValues[fieldName];\n      data[fieldName] = Array.isArray(value) ? value.join(", ") : value;\n    });\n  }\n  data.provider = "Google Forms";\n  data.source = "Google Forms";\n  data.google_form_id = "${(f.id || '').replace(/"/g,'')}";\n  data.google_form_name = "${(f.name || '').replace(/"/g,'')}";\n  UrlFetchApp.fetch(CONSTRAVA_ENDPOINT, { method: "post", contentType: "application/json", muteHttpExceptions: true, payload: JSON.stringify(data) });\n}`; }
  function forms(){
    const f = selectedForm();
    return hero('Forms','Connect intake sources. Google Forms responses are forwarded through the AI interpreter into the unified CRM list.') + `<div class="cx-three"><div class="cx-dcrm-card"><h3>Google account</h3><p id="cxGStatus">Not checked yet.</p><div class="cx-actions" style="margin-top:12px"><button class="cx-btn dark" id="cxGConnect">Connect Google</button><button class="cx-btn" id="cxGCheck">Check status</button></div></div><div class="cx-dcrm-card"><h3>Choose form</h3><p>${f.id ? 'Selected: '+esc(f.name || f.id) : 'No form selected yet.'}</p><div class="cx-actions" style="margin-top:12px"><button class="cx-btn primary" id="cxGLoad">Load Google Forms</button></div></div><div class="cx-dcrm-card"><h3>Test intake</h3><p>Send a sample entry through the same AI form route.</p><div class="cx-actions" style="margin-top:12px"><button class="cx-btn primary" id="cxGTest">Send test lead</button></div></div></div><div class="cx-dcrm-card"><h3>Available forms</h3><div id="cxGForms" class="cx-list"><p class="cx-detail">Connect and load forms.</p></div></div><div class="cx-dcrm-card"><h3>Apps Script forwarder</h3><p>Paste this into the response Sheet Apps Script trigger.</p><pre class="cx-code" id="cxGScript">${esc(appScript())}</pre><button class="cx-btn" id="cxGCopy">Copy script</button></div>`;
  }

  async function connectGoogle(){
    const returnTo = location.pathname + location.search;
    const qs = 'private=1&siteSlug=constrava-crm&formSlug=google-form&token=' + encodeURIComponent(token) + '&returnTo=' + encodeURIComponent(returnTo);
    try { const r = await fetch('/debug/google-oauth?' + qs, { cache:'no-store' }); const j = await r.json(); if(j.oauth_url){ location.href = j.oauth_url; return; } } catch {}
    location.href = 'https://constravaai.com/auth/google/forms/start?' + qs;
  }
  async function checkGoogle(){ const el = document.getElementById('cxGStatus'); const id = sessionStorage.getItem(GOOGLE_CONNECTION_KEY) || ''; if(!id){ if(el) el.textContent = 'Not connected yet.'; return; } try{ const r = await fetch('/api/google/forms/status?private=1&connectionId=' + encodeURIComponent(id)); const j = await r.json(); if(!j.ok) throw new Error(j.error); if(el) el.textContent = 'Connected as ' + (j.connection.account || 'Google account') + '.'; }catch(e){ if(el) el.textContent = 'Connection needs refresh.'; } }
  async function loadGoogleForms(){ const box = document.getElementById('cxGForms'); const id = sessionStorage.getItem(GOOGLE_CONNECTION_KEY) || ''; if(!id){ box.innerHTML = '<div class="cx-status warn">Connect Google first.</div>'; return; } box.innerHTML = '<div class="cx-status">Loading forms...</div>'; try{ const r = await fetch('/api/google/forms/list?private=1&connectionId=' + encodeURIComponent(id)); const j = await r.json(); if(!j.ok) throw new Error(j.error || 'Could not load forms.'); box.innerHTML = (j.forms || []).map(f => `<div class="cx-item"><div class="cx-item-top"><div><h4>${esc(f.name || 'Untitled form')}</h4><p>${esc(f.id || '')}</p></div><button class="cx-btn primary" data-use-form="${esc(f.id)}" data-form-name="${esc(f.name || 'Google Form')}">Use</button></div></div>`).join('') || empty('No forms','No Google Forms found.'); box.querySelectorAll('[data-use-form]').forEach(b => b.onclick = () => { saveForm({ id:b.getAttribute('data-use-form'), name:b.getAttribute('data-form-name') }); render(); }); }catch(e){ box.innerHTML = '<div class="cx-status warn">'+esc(e.message)+'</div>'; } }
  async function testForm(){ try{ const r = await fetch(formEndpoint(), { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ name:'Google Forms Test Lead', email:'google.form.lead@example.com', phone:'610-555-0142', company:'Google Forms Client Co', message:'Test lead through Forms tab.', value:7200, provider:'Google Forms', source:'Google Forms Test', dashboard_token:token }) }); const j = await r.json(); if(!j.ok) throw new Error(j.error || 'Test failed.'); await loadEntries(); alert('Test lead sent into the unified CRM list.'); }catch(e){ alert(e.message || 'Test failed.'); } }

  function ai(){ return hero('AI Command Center','Type what happened. The AI can create new entries, update matching entries, or create follow-up tasks in the unified list.') + `<div class="cx-dcrm-card"><textarea id="cxAiText" class="cx-textarea" placeholder="Example: John Henry from Henry Construction called. Move him to Proposal and create a follow-up for Friday."></textarea><div class="cx-actions" style="margin-top:10px"><button class="cx-btn primary" id="cxAiRun">AI Add / Update</button><button class="cx-btn" id="cxAiExample">Load example</button></div><div id="cxAiResult" class="cx-status" style="margin-top:10px">No command run yet.</div></div>`; }
  async function runAi(){ const text = document.getElementById('cxAiText').value.trim(); const out = document.getElementById('cxAiResult'); if(!text){ out.className='cx-status warn'; out.textContent='Type a CRM update first.'; return; } out.className='cx-status'; out.textContent='Interpreting command...'; try{ const r = await fetch('/api/crm/ai-entry?token=' + encodeURIComponent(token), { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ token, text }) }); const j = await r.json(); if(!j.ok) throw new Error(j.error || 'AI command failed.'); state.entries = j.entries || []; out.className='cx-status ok'; out.textContent = 'Processed ' + ((j.actions||[]).length || 1) + ' CRM action(s).'; }catch(e){ out.className='cx-status warn'; out.textContent=e.message || 'AI command failed.'; } }

  function reports(){
    const list = entries(); const byStatus = countBy(list, e => getStatus(e)); const bySource = countBy(list, e => e.source || 'Unknown'); const totalVal = list.reduce((s,e)=>s+(Number(e.value)||0),0);
    return hero('Reports','Simple CRM analytics from the same unified entry list.') + kpis() + `<div class="cx-two"><div class="cx-dcrm-card"><h3>Entries by status</h3>${bars(byStatus)}</div><div class="cx-dcrm-card"><h3>Entries by source</h3>${bars(bySource)}</div></div><div class="cx-dcrm-card"><h3>Pipeline summary</h3><p>Total tracked value: <b>${money(totalVal)}</b></p><p class="cx-detail">Reports become more meaningful as real form submissions and AI commands add entries.</p></div>`;
  }
  function countBy(list, fn){ const o={}; list.forEach(e=>{ const k=fn(e); o[k]=(o[k]||0)+1; }); return o; }
  function bars(obj){ const vals = Object.entries(obj); const max = Math.max(1,...vals.map(x=>x[1])); return `<div class="cx-bars">${vals.length ? vals.map(([k,v])=>`<div class="cx-bar"><span>${esc(k)}</span><div class="cx-track"><div class="cx-fill" style="width:${Math.round(v/max*100)}%"></div></div><b>${v}</b></div>`).join('') : '<p class="cx-detail">No data yet.</p>'}</div>`; }

  function settings(){ return hero('Settings','CRM rules and local preferences. These prepare the system for production settings later.') + `<div class="cx-dcrm-card"><div class="cx-settings-row"><div><b>Unified data source</b><p class="cx-detail">All tabs read from one endpoint.</p></div><code>/api/crm/entries</code></div><div class="cx-settings-row"><div><b>Default deal stages</b><p class="cx-detail">Used by the Deals board.</p></div><input class="cx-input" value="New, Qualified, Proposal, Negotiation, Closed Won, Closed Lost"></div><div class="cx-settings-row"><div><b>AI sorting</b><p class="cx-detail">Forms and commands pass through AI/rules interpretation.</p></div><span class="cx-pill">Enabled</span></div><div class="cx-settings-row"><div><b>Demo data</b><p class="cx-detail">The fake demo list was removed; real entries appear as they are created.</p></div><span class="cx-pill dark">Cleared</span></div></div>`; }

  function render(){
    rebuildSide(); updateTitle();
    const panel = ensureRoot(); if(!panel) return;
    const sideEl = side(); if(sideEl) sideEl.querySelectorAll('[data-cx-tab]').forEach(b=>b.classList.toggle('active', b.getAttribute('data-cx-tab') === state.active));
    const views = { overview, 'full-list':fullList, intake, leads, contacts, companies, deals, tasks, forms, ai, reports, settings };
    panel.innerHTML = (views[state.active] || overview)();
    const search = document.getElementById('cxCrmSearch'); if(search) search.oninput = e => { state.query = e.target.value; render(); };
    bindActiveView();
  }

  function bindActiveView(){
    if(state.active === 'forms'){
      const c=document.getElementById('cxGConnect'); if(c)c.onclick=connectGoogle;
      const chk=document.getElementById('cxGCheck'); if(chk)chk.onclick=checkGoogle;
      const l=document.getElementById('cxGLoad'); if(l)l.onclick=loadGoogleForms;
      const cp=document.getElementById('cxGCopy'); if(cp)cp.onclick=()=>navigator.clipboard && navigator.clipboard.writeText(appScript());
      const t=document.getElementById('cxGTest'); if(t)t.onclick=testForm;
      checkGoogle();
    }
    if(state.active === 'ai'){
      const r=document.getElementById('cxAiRun'); if(r)r.onclick=runAi;
      const ex=document.getElementById('cxAiExample'); if(ex)ex.onclick=()=>{ document.getElementById('cxAiText').value='John Henry from Henry Construction called. Phone 123-754-3808, email HenryJ@email.com. He wants a website quote and is ready for a proposal. Create or update the CRM entry and make the next step send a proposal.'; };
    }
  }

  function boot(){
    if(!document.querySelector('.crm-shell')) return;
    rebuildSide(); updateTitle(); ensureRoot(); render(); loadEntries();
  }
  setInterval(boot, 1200);
  document.addEventListener('click', () => setTimeout(boot, 80), true);
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
