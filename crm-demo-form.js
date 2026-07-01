(function(){
  if (window.__constravaReliableRecordManager) return;
  window.__constravaReliableRecordManager = true;

  const STORE_KEY = 'constravaCrmDemoAdds';
  let installed = false;

  function byId(id){ return document.getElementById(id); }
  function money(v){ return new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(Number(v||0)); }
  function escapeHtml(v){ return String(v == null ? '' : v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }
  function number(v, fallback){ const n = Number(String(v || '').replace(/[$,]/g,'')); return Number.isFinite(n) ? n : Number(fallback || 0); }
  function dashboardData(){
    try { if (typeof data !== 'undefined' && data) return data; } catch(e) {}
    window.data = window.data || { records: [], leads: [] };
    return window.data;
  }
  function readSessionRecords(){ try { const list = JSON.parse(sessionStorage.getItem(STORE_KEY) || '[]'); return Array.isArray(list) ? list : []; } catch(e) { return []; } }
  function saveSessionRecord(record){ const list = readSessionRecords(); list.unshift(record); sessionStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0,100))); }
  function cleanType(v){ const raw = String(v || '').trim().toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,''); return (!raw || raw === 'record' || raw === 'item' || raw === 'crm_record' || raw === 'crm_item') ? '' : raw; }
  function tagList(v){ if (Array.isArray(v)) return Array.from(new Set(v.map(x => String(x||'').trim()).filter(Boolean))); if (typeof v === 'string') return Array.from(new Set(v.split(/[;,]/).map(x => x.trim()).filter(Boolean))); return []; }
  function guessType(raw){
    raw = raw || {};
    const explicit = cleanType(raw.record_type || raw.type || raw.kind || raw.object_type);
    if (explicit) return explicit;
    const module = String(raw.module || raw.crm_module || raw.record_module || '').toLowerCase();
    if (module.includes('vip')) return 'vip_lead';
    if (module.includes('deal')) return 'deal';
    if (module.includes('account')) return 'account';
    if (module.includes('contact')) return 'contact';
    if (module.includes('activit')) return 'activity';
    if (module.includes('task')) return 'task';
    if (module.includes('document')) return 'document';
    if (module.includes('report')) return 'report';
    let payload = '';
    try { payload = JSON.stringify(raw.raw_submission || raw.payload || raw.metadata || raw.data || {}); } catch(e) {}
    const text = [raw.source, raw.provider, raw.channel, raw.deal_name, raw.opportunity, raw.project, raw.service, raw.notes, raw.message, raw.body, tagList(raw.tags).join(' '), payload].join(' ').toLowerCase();
    if (/google\s*forms|typeform|tally|jotform|external form|form submission|form_lead/.test(text)) return 'external_form_lead';
    if (/website form|web lead|contact page|site form/.test(text)) return 'website_form_lead';
    if (/csv|spreadsheet|import/.test(text)) return 'csv_import_lead';
    if (/email|inbox|thread|reply/.test(text)) return 'email_activity';
    if (/call|voicemail|phone conversation/.test(text)) return 'call_log';
    if (/task|todo|to do|follow\s*up|due date/.test(text)) return 'task';
    if (/api|webhook|payload|endpoint/.test(text)) return 'api_payload';
    if (/automation|rule|score|workflow run/.test(text)) return 'automation_run';
    if (/report|summary|analysis/.test(text)) return 'report';
    if (/document|file|proposal pdf|contract/.test(text)) return 'document';
    if (/deal|opportunity|proposal|quote|estimate|budget|project value|pricing|closed won|closed lost|negotiation/.test(text)) return 'deal';
    const hasCompany = !!String(raw.company || raw.organization || raw.account_name || raw.business || '').trim();
    const hasPerson = !!String(raw.name || raw.full_name || raw.first_name || raw.last_name || raw.lead_name || raw.contact_name || '').trim();
    const hasContact = !!String(raw.email || raw.phone || raw.contact_email || raw.phone_number || '').trim();
    const hasValue = number(raw.value || raw.deal_value || raw.amount || raw.budget, 0) > 0;
    if (hasValue && (raw.deal_name || hasCompany)) return 'deal';
    if (hasContact && !hasPerson && !hasCompany) return 'contact';
    if (hasContact || hasPerson) return String(raw.source || '').toLowerCase().includes('ai') ? 'ai_text_lead' : 'lead';
    if (hasCompany) return 'account';
    return 'lead';
  }
  function stageOf(raw){ return String(raw.stage || raw.status || raw.lead_status || raw.deal_stage || 'New'); }
  function probability(stage, raw){ const p = number(raw.probability || raw.prob, NaN); if (Number.isFinite(p) && p >= 0) return p; const s = String(stage||'').toLowerCase(); if (s.includes('closed won') || s === 'won') return 100; if (s.includes('negotiation')) return 80; if (s.includes('proposal')) return 60; if (s.includes('qualified')) return 40; if (s.includes('analysis') || s.includes('contacted')) return 20; if (s.includes('closed lost') || s === 'lost') return 0; return 10; }
  function normalize(raw, index){
    raw = raw || {};
    const type = guessType(raw);
    const stage = stageOf(raw);
    const value = number(raw.value || raw.deal_value || raw.amount || raw.budget || raw.expected_revenue, 2200 + index * 700);
    const company = String(raw.company || raw.organization || raw.account_name || raw.business || '—');
    const name = String(raw.name || raw.full_name || raw.lead_name || raw.contact_name || raw.email || raw.deal_name || ('Record ' + (index + 1)));
    const module = String(raw.module || '').toLowerCase() || (type.includes('deal') ? 'deals' : type.includes('contact') ? 'contacts' : type.includes('account') ? 'accounts' : type.includes('task') || type.includes('activity') || type.includes('call') || type.includes('email') ? 'activities' : type.includes('document') ? 'documents' : type.includes('report') ? 'reports' : 'leads');
    return Object.assign({}, raw, { id:String(raw.id || raw.record_id || raw.lead_id || ('REC-' + (index + 1))), record_id:String(raw.record_id || raw.lead_id || raw.id || ('REC-' + (index + 1))), lead_id:String(raw.lead_id || raw.record_id || raw.id || ('REC-' + (index + 1))), record_type:type, module, name, email:String(raw.email || raw.lead_email || raw.contact_email || ''), phone:String(raw.phone || raw.phone_number || raw.mobile || ''), company, stage, status:stage, source:String(raw.source || raw.provider || raw.channel || 'CRM'), deal_name:String(raw.deal_name || raw.opportunity || raw.project || (company !== '—' ? company + ' opportunity' : name + ' opportunity')), value, probability:probability(stage, raw), priority:String(raw.priority || (value >= 7500 ? 'High' : 'Normal')), tags:Array.from(new Set(tagList(raw.tags).concat([type,module,'typed-record']).filter(Boolean))), notes:String(raw.notes || raw.message || raw.body || raw.description || '') });
  }
  function rawRecords(){ const d = dashboardData(); return [].concat(Array.isArray(d.records)?d.records:[], Array.isArray(d.leads)?d.leads:[], readSessionRecords()); }
  function allRecords(){ const seen = new Set(); return rawRecords().map(normalize).filter((r,i)=>{ const key = r.record_id || r.lead_id || r.id || (r.email ? r.email + '|' + (r.created_at || '') : '') || (r.name + '|' + r.company + '|' + r.deal_name) || ('row-' + i); if (seen.has(key)) return false; seen.add(key); return true; }); }
  function sourceCounts(){ const d = dashboardData(); return { records:Array.isArray(d.records)?d.records.length:0, leads:Array.isArray(d.leads)?d.leads.length:0, session:readSessionRecords().length }; }
  function accountRows(list){ const map = {}; list.forEach(r=>{ const key = r.company && r.company !== '—' ? r.company : (r.email || r.name || 'Unknown Account'); if (!map[key]) map[key] = Object.assign({}, r, { id:'ACC-' + key, record_id:'ACC-' + key, record_type:'account', module:'accounts', name:key, company:key, email:'', source:'Account rollup', value:0, notes:'Account rollup from related CRM records.' }); map[key].value += number(r.value,0); }); return Object.values(map); }
  function moduleRecords(module){ const list = allRecords(); module = module || 'dashboards'; if (['dashboards','home','feeds','documents','reports'].includes(module)) return list; if (module === 'vip') return list.filter(r => /vip|high|critical/i.test([r.record_type,r.priority,r.tags.join(' ')].join(' ')) || number(r.value,0) >= 7500 || number(r.probability,0) >= 60); if (module === 'contacts') return list.filter(r => r.module === 'contacts' || r.record_type.includes('contact') || r.email || r.phone); if (module === 'accounts') return accountRows(list); if (module === 'deals') return list.filter(r => r.module === 'deals' || r.record_type.includes('deal') || r.deal_name || number(r.value,0) > 0).map(r => Object.assign({}, r, { name:r.deal_name || r.name, module:'deals', record_type:r.record_type === 'lead' ? 'deal' : r.record_type })); if (module === 'activities') return list.filter(r => /activity|task|call|email|follow/.test(r.record_type + ' ' + r.module)).concat(list.map(r => Object.assign({}, r, { id:r.id + '-follow', record_id:r.record_id + '-follow', record_type:r.record_type === 'task' ? 'task' : 'follow_up_task', module:'activities', name:'Follow up with ' + (r.name || r.company), notes:r.notes || 'Follow-up generated from this CRM record.' }))); return list.filter(r => r.module === 'leads' || r.record_type.includes('lead') || r.record_type.includes('form') || (!r.record_type.includes('deal') && !r.record_type.includes('account'))); }
  function activeModule(){ const a = document.querySelector('[data-crm].active'); return (a && a.getAttribute('data-crm')) || 'dashboards'; }
  function filtered(module){ const term = String((byId('crmSearch') && byId('crmSearch').value) || '').toLowerCase().trim(); const stage = String((byId('stageFilter') && byId('stageFilter').value) || 'all'); return moduleRecords(module).filter(r => { const text = [r.name,r.email,r.phone,r.company,r.stage,r.status,r.source,r.notes,r.record_type,r.module,r.priority,r.deal_name,r.tags.join(' ')].join(' ').toLowerCase(); return (!term || text.includes(term)) && (stage === 'all' || r.stage === stage); }); }
  function renderTable(list){ if (!list.length) { const c = sourceCounts(); return '<div class="records"><div class="empty"><b>No matching records in this view.</b><br>Checked data.records=' + c.records + ', data.leads=' + c.leads + ', session saves=' + c.session + '. Clear search/stage filters or open Dashboards to see all loaded records.</div></div>'; } return '<div class="records"><table><thead><tr><th>Type</th><th>Name</th><th>Email/Phone</th><th>Company</th><th>Status</th><th>Source</th><th>Value</th></tr></thead><tbody>' + list.map(r => '<tr><td><span class="pill">' + escapeHtml(r.record_type) + '</span></td><td><b>' + escapeHtml(r.name) + '</b><br><small>' + escapeHtml(r.deal_name || '') + '</small></td><td>' + escapeHtml(r.email || r.phone || '—') + '</td><td>' + escapeHtml(r.company || '—') + '</td><td>' + escapeHtml(r.stage || 'New') + '</td><td>' + escapeHtml(r.source || 'CRM') + '</td><td>' + money(r.value) + '</td></tr>').join('') + '</tbody></table></div>'; }
  function renderCrmFinal(module){ module = module || activeModule(); const list = filtered(module); document.querySelectorAll('[data-crm]').forEach(b => b.classList.toggle('active', b.getAttribute('data-crm') === module)); const title = module === 'vip' ? 'VIP Leads' : module.charAt(0).toUpperCase() + module.slice(1); if (byId('crmTitle')) byId('crmTitle').textContent = title; const total = list.reduce((a,r)=>a+number(r.value,0),0); if (byId('crmSubtitle')) byId('crmSubtitle').textContent = list.length + ' matching records • ' + money(total) + ' visible value'; if (byId('crmContent')) byId('crmContent').innerHTML = renderTable(list); const add = byId('crmAdd'); if (add) add.textContent = 'Add Text Record'; return list; }
  function parseTextRecord(text){ text = String(text || '').trim(); const email = (text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)||[''])[0]; const phone = (text.match(/(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/)||[''])[0]; const valueMatch = text.replace(/,/g,'').match(/\$?\b(\d{3,7})\b/); const value = valueMatch ? Number(valueMatch[1]) : 0; const nameMatch = text.match(/(?:named|name is|lead is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})/) || text.match(/^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\s+from\s+/); const companyMatch = text.match(/from\s+([A-Z][A-Za-z0-9& .-]{2,60})(?:\s+(?:reached|wants|needs|is|and|with)|[.,]|$)/); const status = /proposal/i.test(text) ? 'Proposal' : /qualified|serious|ready/i.test(text) ? 'Qualified' : /negotiation/i.test(text) ? 'Negotiation' : 'New'; const priority = /urgent|high priority|important|soon|ready/i.test(text) || value >= 7500 ? 'High' : 'Normal'; return normalize({ lead_id:'TEXT-' + Date.now(), record_type:'ai_text_lead', module:'leads', name:nameMatch ? nameMatch[1].trim() : (email ? email.split('@')[0].replace(/[._-]+/g,' ') : 'Text Lead'), email, phone, company:companyMatch ? companyMatch[1].trim() : 'Text Lead', source:'AI Text Add', status, priority, value, deal_name: value ? 'Text lead opportunity' : 'Text lead inquiry', notes:text, raw_submission:{ text } }, 0); }
  function addTextRecord(){ const text = prompt('Paste a normal-text lead description:'); if (!text) return; const record = parseTextRecord(text); const d = dashboardData(); d.records = Array.isArray(d.records) ? d.records : []; d.leads = Array.isArray(d.leads) ? d.leads : []; d.records.unshift(record); d.leads.unshift(record); saveSessionRecord(record); renderCrmFinal('leads'); const toast = byId('toast'); if (toast) { toast.textContent = 'Text lead saved and shown in CRM.'; toast.classList.add('show'); setTimeout(()=>toast.classList.remove('show'),2400); } }
  function install(){ try { window.renderCRM = renderCrmFinal; try { renderCRM = renderCrmFinal; } catch(e) {} installed = true; renderCrmFinal(activeModule()); } catch(e) {} }
  function bind(){ if (!installed || window.renderCRM !== renderCrmFinal) install(); document.querySelectorAll('[data-crm]').forEach(btn => { if (btn.dataset.reliableRecordBound) return; btn.dataset.reliableRecordBound = 'true'; btn.addEventListener('click', () => setTimeout(() => renderCrmFinal(btn.getAttribute('data-crm') || activeModule()), 0)); }); const search = byId('crmSearch'); if (search && !search.dataset.reliableRecordBound) { search.dataset.reliableRecordBound = 'true'; search.addEventListener('input', () => renderCrmFinal(activeModule())); } const stage = byId('stageFilter'); if (stage && !stage.dataset.reliableRecordBound) { stage.dataset.reliableRecordBound = 'true'; stage.addEventListener('change', () => renderCrmFinal(activeModule())); } const add = byId('crmAdd'); if (add && !add.dataset.reliableTextAddBound) { add.dataset.reliableTextAddBound = 'true'; add.addEventListener('click', function(e){ e.preventDefault(); e.stopImmediatePropagation(); addTextRecord(); }, true); } }
  bind(); setInterval(bind, 700);
})();
