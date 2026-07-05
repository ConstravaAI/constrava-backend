import fs from "fs";

const file = "dashboard.html";
if (!fs.existsSync(file)) {
  console.warn("[crm-edit-records-ai-builder-patch] dashboard.html not found; skipping.");
  process.exit(0);
}

let html = fs.readFileSync(file, "utf8");
let changed = false;

const marker = "__crmEditRecordsAiBuilder_v1";
if (!html.includes(marker)) {
  const block = String.raw`
<style id="__crmEditRecordsAiBuilder_v1_styles">
  .semantic-ai-builder{background:linear-gradient(135deg,#ecfdf5,#ffffff);border:1px solid #b7ebd2;border-radius:14px;padding:14px;margin:0 0 14px;box-shadow:0 12px 32px rgba(15,23,42,.08)}
  .semantic-ai-builder *{box-sizing:border-box}.semantic-ai-builder h3{margin:0 0 6px;color:#064e3b;font-size:16px}.semantic-ai-builder p{margin:0 0 10px;color:#64748b;font-size:12px;line-height:1.45}.semantic-ai-builder textarea{width:100%;min-height:112px;resize:vertical;border:1px solid #b7d9cf;border-radius:10px;padding:12px;background:white;color:#0f172a;font:inherit;line-height:1.4}.semantic-ai-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:9px}.semantic-ai-builder button{border:1px solid #0ea66b;background:#10b981;color:white;border-radius:9px;padding:9px 12px;font-weight:900}.semantic-ai-builder button.secondary{background:white;color:#047857;border-color:#b7d9cf}.semantic-ai-builder button:disabled{opacity:.55;cursor:wait}.semantic-ai-status{font-size:12px;color:#047857;font-weight:900}.semantic-ai-results{display:grid;gap:8px;margin-top:12px}.semantic-ai-card{border:1px solid #dbe8e4;background:white;border-radius:10px;padding:10px}.semantic-ai-card strong{display:block;color:#022c22;margin-bottom:3px}.semantic-ai-card span{display:inline-flex;border-radius:999px;background:#e8f8ef;color:#047857;padding:3px 7px;font-size:11px;font-weight:900;margin:0 6px 5px 0}.semantic-ai-card em{display:block;color:#64748b;font-size:12px;font-style:normal;margin-top:5px;white-space:pre-wrap}.semantic-ai-mini{font-size:11px;color:#64748b;margin-left:auto}.semantic-ai-error{color:#b91c1c;font-size:12px;font-weight:900;margin-top:8px}.semantic-ai-builder .examples{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.semantic-ai-builder .examples button{background:#f8fafc;color:#065f46;border-color:#cfe8de;font-size:11px;padding:6px 8px}
</style>
<script id="__crmEditRecordsAiBuilder_v1">
(function(){
  const TOKEN = new URLSearchParams(location.search).get('token') || 'demo';
  const EXAMPLES = [
    'Chris Evans wants me to call him at 9pm',
    'Sarah at Acme Roofing wants a $5000 website quote and I need to call her tomorrow',
    'Mike from Green Valley Gym emailed about a new app project worth 12000, follow up Friday'
  ];
  function textOf(el){return String(el && el.textContent || '').replace(/\s+/g,' ').trim().toLowerCase()}
  function isEditRecordsContext(){
    const activeTexts = [...document.querySelectorAll('.active, [aria-selected="true"]')].map(textOf).join(' | ');
    if (/edit.*record|record.*edit|records/.test(activeTexts)) return true;
    const hash = String(location.hash||'').toLowerCase();
    if (/edit.*record|record/.test(hash)) return true;
    return false;
  }
  function findMount(){
    const candidates = [...document.querySelectorAll('.crm-main,.crm-body main,.records,.crm-panel-body,.main,.shell')];
    let best = candidates.find(el => el && el.offsetParent !== null && (el.classList.contains('crm-main') || textOf(el).includes('record')));
    return best || candidates[0] || document.body;
  }
  function recordTitle(entry){
    const type = String(entry.record_type || entry.type || entry.module || 'record').replace(/_/g,' ');
    const name = entry.name || entry.deal_name || entry.company || entry.email || 'CRM record';
    return name + ' · ' + type;
  }
  function renderActions(json){
    const box = document.getElementById('semantic-ai-results');
    if(!box) return;
    const actions = Array.isArray(json.actions) ? json.actions : [];
    if(!actions.length){ box.innerHTML = '<div class="semantic-ai-card"><strong>No actions returned</strong><em>The backend responded but did not return created/edited records.</em></div>'; return; }
    box.innerHTML = actions.map((a,i)=>{
      const e = a.entry || {};
      const chips = [a.action || 'create', e.record_type || e.type || 'record', e.module || '', e.status || '', e.priority || ''].filter(Boolean).map(x=>'<span>'+escapeHtml(x)+'</span>').join('');
      const details = [
        e.company ? 'Company: '+e.company : '',
        e.email ? 'Email: '+e.email : '',
        e.phone ? 'Phone: '+e.phone : '',
        e.value ? 'Value: $'+Number(e.value).toLocaleString() : '',
        e.next_step ? 'Next step: '+e.next_step : '',
        a.reason ? 'Reason: '+a.reason : ''
      ].filter(Boolean).join('\n');
      return '<div class="semantic-ai-card"><strong>'+(i+1)+'. '+escapeHtml(recordTitle(e))+'</strong>'+chips+'<em>'+escapeHtml(details || e.notes || 'Record returned from AI Add.')+'</em></div>';
    }).join('');
  }
  function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
  function rememberReturnedRecords(json){
    try{
      const existing = JSON.parse(sessionStorage.getItem('constravaCrmDemoAdds')||'[]');
      const newRecords = (Array.isArray(json.actions)?json.actions:[]).map(a=>a.entry).filter(Boolean);
      sessionStorage.setItem('constravaCrmDemoAdds', JSON.stringify([...newRecords, ...existing].slice(0,150)));
    }catch(e){}
  }
  async function runBuilder(){
    const txt = document.getElementById('semantic-ai-text');
    const status = document.getElementById('semantic-ai-status');
    const btn = document.getElementById('semantic-ai-run');
    const error = document.getElementById('semantic-ai-error');
    const text = String(txt && txt.value || '').trim();
    if(!text){ if(error) error.textContent='Enter plain text first.'; return; }
    if(error) error.textContent='';
    if(status) status.textContent='Breaking text into CRM records...';
    if(btn) btn.disabled=true;
    try{
      const res = await fetch('/api/crm/ai-entry?token='+encodeURIComponent(TOKEN), {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:TOKEN,text})});
      const json = await res.json().catch(()=>({ok:false,error:'Invalid JSON response'}));
      if(!res.ok || json.ok===false) throw new Error(json.error || 'AI record builder failed.');
      rememberReturnedRecords(json);
      renderActions(json);
      if(status) status.textContent='Saved '+((json.actions||[]).length)+' record action(s). Refreshing list...';
      setTimeout(()=>{ try{ if(typeof load==='function') load(); else if(typeof refresh==='function') refresh(); }catch(e){} }, 350);
    }catch(err){
      if(error) error.textContent = err.message || 'AI record builder failed.';
      if(status) status.textContent='';
    }finally{ if(btn) btn.disabled=false; }
  }
  function mount(){
    if(document.getElementById('semantic-ai-builder')) return;
    const mount = findMount();
    if(!mount) return;
    const panel = document.createElement('section');
    panel.id='semantic-ai-builder';
    panel.className='semantic-ai-builder';
    panel.innerHTML = '<h3>Semantic AI Record Builder</h3><p>Paste a plain-English update. This builder breaks the meaning into separate CRM records: people become contacts, companies become accounts, opportunities become deals, and follow-ups become tasks. It calls the corrected backend route directly.</p><textarea id="semantic-ai-text" placeholder="Example: Chris Evans wants me to call him at 9pm"></textarea><div class="examples">'+EXAMPLES.map(x=>'<button type="button" class="secondary" data-example="'+escapeHtml(x)+'">'+escapeHtml(x)+'</button>').join('')+'</div><div class="semantic-ai-row"><button id="semantic-ai-run" type="button">Create / Edit Records</button><button id="semantic-ai-clear" type="button" class="secondary">Clear</button><span id="semantic-ai-status" class="semantic-ai-status"></span><span class="semantic-ai-mini">Route: /api/crm/ai-entry</span></div><div id="semantic-ai-error" class="semantic-ai-error"></div><div id="semantic-ai-results" class="semantic-ai-results"></div>';
    mount.insertBefore(panel, mount.firstChild);
    panel.addEventListener('click', function(e){
      const ex = e.target.closest('[data-example]');
      if(ex){ document.getElementById('semantic-ai-text').value = ex.getAttribute('data-example') || ''; }
    });
    document.getElementById('semantic-ai-run').addEventListener('click', runBuilder);
    document.getElementById('semantic-ai-clear').addEventListener('click', ()=>{document.getElementById('semantic-ai-text').value='';document.getElementById('semantic-ai-results').innerHTML='';document.getElementById('semantic-ai-error').textContent='';document.getElementById('semantic-ai-status').textContent='';});
  }
  function maybeMount(){
    if(isEditRecordsContext() || document.querySelector('.crm-main,.records')) mount();
  }
  document.addEventListener('DOMContentLoaded', maybeMount);
  document.addEventListener('click', ()=>setTimeout(maybeMount,80), true);
  setTimeout(maybeMount,500);
  setTimeout(maybeMount,1500);
})();
</script>
`;
  if (html.includes("</body>")) html = html.replace("</body>", block + "\n</body>");
  else html += block;
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, html);
  console.log("[crm-edit-records-ai-builder-patch] Added Semantic AI Record Builder inside Edit Records/Records view.");
} else {
  console.log("[crm-edit-records-ai-builder-patch] Semantic AI Record Builder already installed.");
}
