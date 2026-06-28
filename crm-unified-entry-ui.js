(function(){
  if (window.__constravaUnifiedEntryUiLoaded) return;
  window.__constravaUnifiedEntryUiLoaded = true;

  const state = { type: 'all', entries: [], loading: false };
  const tabs = [
    ['all', 'Full List'],
    ['leads', 'Leads'],
    ['deals', 'Deals'],
    ['contacts', 'Contacts'],
    ['tasks', 'Tasks / Next Steps']
  ];

  const css = document.createElement('style');
  css.textContent = `
    .cx-entry-hub{border:1px solid #d8e0e7;border-radius:14px;background:linear-gradient(135deg,#ffffff,#f8fffc);box-shadow:0 12px 26px rgba(15,23,42,.06);margin:0 0 14px;overflow:hidden}.cx-entry-head{display:flex;justify-content:space-between;gap:14px;align-items:start;padding:16px;border-bottom:1px solid #e6edf2}.cx-entry-head h3{margin:0;color:#022c22}.cx-entry-head p{margin:5px 0 0;color:#64748b;font-size:12px;line-height:1.45}.cx-entry-pill{background:#dcfce7;color:#047857;border:1px solid rgba(16,185,129,.3);border-radius:999px;padding:7px 10px;font-size:11px;font-weight:950;white-space:nowrap}.cx-entry-body{padding:15px}.cx-ai-box{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start;margin-bottom:13px}.cx-ai-box textarea{width:100%;min-height:88px;border:1px solid #d8e0e7;border-radius:12px;background:#f8fafc;padding:12px;font:inherit;resize:vertical}.cx-ai-box button,.cx-entry-tabs button,.cx-refresh{border:1px solid #d8e0e7;border-radius:11px;background:white;color:#073d32;font-weight:900;padding:10px 12px;cursor:pointer}.cx-ai-box button{background:#10b981;border-color:#10b981;color:#022c22;min-height:48px}.cx-entry-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.cx-entry-tabs button.active{background:#052e24;color:#d1fae5;border-color:#052e24}.cx-entry-tools{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:12px}.cx-entry-search{width:min(360px,100%);border:1px solid #d8e0e7;border-radius:11px;background:#fff;padding:10px 12px}.cx-entry-table-wrap{overflow:auto;border:1px solid #e5e7eb;border-radius:12px;background:white;max-height:520px}.cx-entry-table{width:100%;border-collapse:collapse;font-size:12px;min-width:960px}.cx-entry-table th{position:sticky;top:0;background:#f8fafc;color:#64748b;text-transform:uppercase;letter-spacing:.08em;font-size:10px;text-align:left;padding:10px;border-bottom:1px solid #e5e7eb}.cx-entry-table td{padding:11px 10px;border-bottom:1px solid #eef2f7;vertical-align:top}.cx-entry-table b{color:#0f172a}.cx-entry-table small{display:block;color:#64748b;margin-top:3px}.cx-entry-status{display:inline-flex;border-radius:999px;padding:5px 8px;background:#ecfdf5;color:#047857;font-weight:900;font-size:11px}.cx-entry-empty{padding:30px;text-align:center;color:#64748b}.cx-entry-empty b{display:block;color:#022c22;font-size:16px;margin-bottom:5px}.cx-json-mini{font-family:ui-monospace,Menlo,Consolas,monospace;color:#64748b;font-size:11px;white-space:pre-wrap}.cx-entry-msg{margin:0 0 12px;border:1px solid #dbe8e4;background:#f0fdf4;color:#064e3b;border-radius:12px;padding:10px 12px;font-weight:850;display:none}.cx-entry-msg.show{display:block}@media(max-width:900px){.cx-ai-box{grid-template-columns:1fr}.cx-entry-head,.cx-entry-tools{display:block}.cx-entry-pill,.cx-refresh{display:inline-flex;margin-top:8px}}
  `;
  document.head.appendChild(css);

  function token(){ return new URLSearchParams(location.search).get('token') || 'demo'; }
  function esc(v){ return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c])); }
  function money(n){ return Number(n || 0) ? new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(Number(n || 0)) : '—'; }
  function toast(msg){ const t=document.getElementById('toast'); if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);} }
  function crmRoot(){ return document.querySelector('.crm-main') || document.querySelector('.crm-shell') || document.querySelector('#crm') || null; }
  function isCrmVisible(){
    const active = document.querySelector('[data-tab].active, .tab.active, [data-crm].active');
    const text = active ? (active.textContent || active.getAttribute('data-tab') || active.getAttribute('data-crm') || '').toLowerCase() : '';
    return document.querySelector('.crm-shell') && (!text || text.includes('crm') || document.querySelector('.cx-entry-hub'));
  }
  function filtered(){
    const q = (document.getElementById('cxEntrySearch')?.value || '').toLowerCase().trim();
    return (state.entries || []).filter(e => !q || JSON.stringify(e).toLowerCase().includes(q));
  }
  function inferType(e){
    if (/task|note/i.test(String(e.record_type || e.module || ''))) return 'Task';
    if (Number(e.value) > 0 || e.deal_name) return 'Deal';
    if (e.email || e.phone) return 'Contact';
    return 'Lead';
  }
  function row(e){
    return `<tr>
      <td><b>${esc(e.name || 'Unnamed Entry')}</b><small>${esc(e.lead_id || '')}</small></td>
      <td>${esc(e.company || '—')}<small>${esc(e.title || e.industry || '')}</small></td>
      <td>${esc(e.email || '—')}<small>${esc(e.phone || e.mobile || '')}</small></td>
      <td><b>${esc(e.deal_name || inferType(e))}</b><small>${esc(e.industry || e.record_type || '')}</small></td>
      <td><span class="cx-entry-status">${esc(e.status || 'New')}</span><small>${esc(e.priority || '')}</small></td>
      <td>${money(e.value)}<small>${Number(e.probability || 0) ? esc(e.probability) + '% probability' : ''}</small></td>
      <td>${esc(e.next_step || 'Review and follow up.')}<small>${esc(e.created_at || '')}</small></td>
    </tr>`;
  }
  function render(){
    const hub = document.getElementById('cxEntryHub');
    if (!hub) return;
    const list = filtered();
    document.getElementById('cxEntryCount').textContent = `${list.length} entr${list.length === 1 ? 'y' : 'ies'}`;
    const tbody = document.getElementById('cxEntryRows');
    if (!tbody) return;
    tbody.innerHTML = list.length ? list.map(row).join('') : `<tr><td colspan="7"><div class="cx-entry-empty"><b>No CRM entries yet</b>Connected forms and AI Add Entry will add records to this one unified list.</div></td></tr>`;
  }
  async function loadEntries(){
    state.loading = true;
    const q = encodeURIComponent(document.getElementById('cxEntrySearch')?.value || '');
    const url = `/api/crm/entries?token=${encodeURIComponent(token())}&type=${encodeURIComponent(state.type)}&q=${q}`;
    try{
      const r = await fetch(url, { cache: 'no-store' });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Could not load CRM entries.');
      state.entries = j.entries || j.leads || [];
      render();
    }catch(err){ showMsg(err.message || 'Could not load CRM entries.', true); }
    finally{ state.loading = false; }
  }
  function showMsg(msg, isBad){
    const el = document.getElementById('cxEntryMsg');
    if (!el) return;
    el.textContent = msg;
    el.style.background = isBad ? '#fff7ed' : '#f0fdf4';
    el.style.color = isBad ? '#9a3412' : '#064e3b';
    el.classList.add('show');
  }
  async function aiSubmit(){
    const box = document.getElementById('cxAiEntryText');
    const text = (box?.value || '').trim();
    if (!text) { showMsg('Type what happened first.', true); return; }
    const btn = document.getElementById('cxAiEntryBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Interpreting…'; }
    try{
      const r = await fetch('/api/crm/ai-entry?token=' + encodeURIComponent(token()), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token(), text })
      });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'AI entry failed.');
      if (box) box.value = '';
      state.entries = j.entries || [];
      showMsg(`AI processed ${j.actions?.length || 1} action${(j.actions?.length || 1) === 1 ? '' : 's'} into the unified CRM list.`, false);
      toast('CRM list updated.');
      render();
    }catch(err){ showMsg(err.message || 'AI entry failed.', true); }
    finally{ if (btn) { btn.disabled = false; btn.textContent = 'AI Add / Update'; } }
  }
  function shell(){
    return `<section class="cx-entry-hub" id="cxEntryHub">
      <div class="cx-entry-head"><div><h3>Unified CRM Entry List</h3><p>Every CRM function should draw from this one list. Connected forms add entries through the AI interpreter. Plain-text updates can create or update one or multiple records.</p></div><div class="cx-entry-pill" id="cxEntryCount">0 entries</div></div>
      <div class="cx-entry-body">
        <div class="cx-entry-msg" id="cxEntryMsg"></div>
        <div class="cx-ai-box"><textarea id="cxAiEntryText" placeholder="Example: John Henry from Henry Construction called. Phone 123-754-3808, email HenryJ@email.com. He wants a website quote and is ready for a proposal."></textarea><button id="cxAiEntryBtn" type="button">AI Add / Update</button></div>
        <div class="cx-entry-tabs">${tabs.map(t=>`<button type="button" data-cx-entry-tab="${t[0]}" class="${t[0] === state.type ? 'active' : ''}">${t[1]}</button>`).join('')}</div>
        <div class="cx-entry-tools"><input id="cxEntrySearch" class="cx-entry-search" placeholder="Search the full CRM list"><button type="button" class="cx-refresh" id="cxEntryRefresh">Refresh List</button></div>
        <div class="cx-entry-table-wrap"><table class="cx-entry-table"><thead><tr><th>Name</th><th>Company</th><th>Contact</th><th>Deal / Type</th><th>Status</th><th>Value</th><th>Next Step</th></tr></thead><tbody id="cxEntryRows"></tbody></table></div>
      </div>
    </section>`;
  }
  function bind(){
    document.querySelectorAll('[data-cx-entry-tab]').forEach(btn => {
      btn.onclick = () => {
        state.type = btn.getAttribute('data-cx-entry-tab') || 'all';
        document.querySelectorAll('[data-cx-entry-tab]').forEach(b=>b.classList.toggle('active', b === btn));
        loadEntries();
      };
    });
    const search = document.getElementById('cxEntrySearch');
    if (search) search.oninput = () => render();
    const refresh = document.getElementById('cxEntryRefresh');
    if (refresh) refresh.onclick = () => loadEntries();
    const ai = document.getElementById('cxAiEntryBtn');
    if (ai) ai.onclick = aiSubmit;
  }
  function ensure(){
    if (!document.querySelector('.crm-shell')) return;
    if (document.getElementById('cxEntryHub')) return;
    const root = crmRoot();
    if (!root) return;
    const div = document.createElement('div');
    div.innerHTML = shell();
    root.insertBefore(div.firstElementChild, root.firstElementChild || null);
    bind();
    loadEntries();
  }

  setInterval(ensure, 1200);
  document.addEventListener('click', () => setTimeout(ensure, 80));
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensure);
  else ensure();
})();
