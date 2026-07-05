import fs from "fs";

const file = "dashboard.html";
if (!fs.existsSync(file)) {
  console.warn("[crm-edit-records-ai-builder-patch] dashboard.html not found; skipping.");
  process.exit(0);
}

let html = fs.readFileSync(file, "utf8");
let changed = false;

// Remove earlier floating/launcher versions so there is only one AI Add surface.
html = html.replace(/\n?<style id="__crmEditRecordsAiBuilder_v1_styles">[\s\S]*?<\/script>\s*/g, "\n");
html = html.replace(/\n?<style id="__crmEditRecordsAiBuilder_v2_styles">[\s\S]*?<\/script>\s*/g, "\n");
html = html.replace(/sessionStorage\.setItem\('constravaCrmDemoAdds'[\s\S]*?\}\catch\(e\)\{\}/g, "try{sessionStorage.removeItem('constravaCrmDemoAdds')}catch(e){}");

const marker = "__crmEditRecordsAiBuilder_v3";
if (!html.includes(marker)) {
  const block = String.raw`
<style id="__crmEditRecordsAiBuilder_v3_styles">
  .ai-edit-tab-wrap{display:grid;gap:14px}.ai-edit-builder{background:linear-gradient(135deg,#ecfdf5,#fff);border:1px solid #b7ebd2;border-radius:10px;padding:16px;box-shadow:0 14px 36px rgba(15,23,42,.10)}.ai-edit-builder h3{margin:0 0 6px;color:#064e3b}.ai-edit-builder p{margin:0 0 12px;color:#64748b;font-size:13px;line-height:1.45}.ai-edit-builder textarea{width:100%;min-height:132px;resize:vertical;border:1px solid #b7d9cf;border-radius:8px;padding:12px;background:white;color:#0f172a;font:inherit;line-height:1.45}.ai-edit-examples{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}.ai-edit-example{border:1px solid #b7d9cf;background:white;color:#047857;border-radius:8px;padding:7px 9px;font-size:11px;font-weight:900}.ai-edit-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}.ai-edit-actions button{border:1px solid #0ea66b;background:#10b981;color:white;border-radius:8px;padding:10px 13px;font-weight:950}.ai-edit-actions button.secondary{background:white;color:#047857;border-color:#b7d9cf}.ai-edit-actions button:disabled{opacity:.55;cursor:wait}.ai-edit-status{font-size:12px;color:#047857;font-weight:900}.ai-edit-error{color:#b91c1c;font-size:12px;font-weight:900;margin-top:8px}.ai-edit-results{display:grid;gap:8px;margin-top:12px}.ai-edit-card{border:1px solid #dbe8e4;background:#fff;border-radius:8px;padding:10px}.ai-edit-card strong{display:block;color:#022c22;margin-bottom:4px}.ai-edit-card span{display:inline-flex;border-radius:999px;background:#e8f8ef;color:#047857;padding:3px 7px;font-size:11px;font-weight:900;margin:0 6px 5px 0}.ai-edit-card em{display:block;color:#64748b;font-size:12px;font-style:normal;white-space:pre-wrap}.ai-edit-records-table{background:white;border:1px solid #d8e0e7;border-radius:8px;overflow:auto}.ai-edit-records-table table{width:100%;border-collapse:collapse}.ai-edit-records-table th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;text-align:left;padding:10px}.ai-edit-records-table td{border-top:1px solid #edf2f7;padding:10px;font-size:13px}.ai-edit-pill{display:inline-flex;border-radius:999px;background:#e8f8ef;color:#047857;padding:4px 7px;font-weight:900;font-size:11px}
</style>
<script id="__crmEditRecordsAiBuilder_v3">
(function(){
  const TOKEN = new URLSearchParams(location.search).get('token') || 'demo';
  const EXAMPLES = [
    'Chris Evans wants me to call him at 9pm',
    'Sarah at Acme Roofing wants a $5000 website quote and I need to call her tomorrow',
    'Mike from Green Valley Gym emailed about a new app project worth 12000, follow up Friday'
  ];
  function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[m]})}
  function cleanType(v){return String(v||'record').replace(/_/g,' ')}
  function currentRecords(){
    const d = window.data || {};
    const out = [];
    function add(list){if(Array.isArray(list))list.forEach(function(x){if(x&&typeof x==='object')out.push(x)})}
    add(d.records); add(d.leads);
    const seen = new Set();
    return out.filter(function(r,i){const key=String(r.record_id||r.lead_id||r.id||((r.email||'')+'|'+(r.name||'')+'|'+(r.company||'')+'|'+i));if(seen.has(key))return false;seen.add(key);return true;});
  }
  function ensureEditRecordsTab(){
    const top = document.querySelector('#crm .crm-top');
    if(top && !top.querySelector('[data-crm="editrecords"]')){const b=document.createElement('button');b.type='button';b.setAttribute('data-crm','editrecords');b.textContent='Edit Records';top.appendChild(b);}
    const left = document.querySelector('#crm .crm-left');
    if(left && !left.querySelector('[data-crm="editrecords"]')){const b=document.createElement('button');b.type='button';b.setAttribute('data-crm','editrecords');b.textContent='Edit Records';left.appendChild(b);}
  }
  function setActiveButtons(){
    document.querySelectorAll('#crm [data-crm]').forEach(function(b){b.classList.toggle('active', b.getAttribute('data-crm')==='editrecords')});
  }
  function renderReturnedActions(json){
    const box=document.getElementById('aiEditRecordsResults'); if(!box)return;
    const actions=Array.isArray(json.actions)?json.actions:[];
    if(!actions.length){box.innerHTML='<div class="ai-edit-card"><strong>No record actions returned</strong><em>The server responded but did not return created/edited records.</em></div>';return;}
    box.innerHTML=actions.map(function(a,i){const e=a.entry||{};const type=e.record_type||e.type||'record';const name=e.name||e.deal_name||e.company||e.email||'CRM record';const chips=[a.action||'create',type,e.module||'',e.status||'',e.priority||''].filter(Boolean).map(function(x){return '<span>'+esc(x)+'</span>'}).join('');const details=[e.company?'Company: '+e.company:'',e.email?'Email: '+e.email:'',e.phone?'Phone: '+e.phone:'',Number(e.value)?'Value: $'+Number(e.value).toLocaleString():'',e.next_step?'Next step: '+e.next_step:'',a.reason?'Reason: '+a.reason:''].filter(Boolean).join('\n');return '<div class="ai-edit-card"><strong>'+(i+1)+'. '+esc(name)+' · '+esc(cleanType(type))+'</strong>'+chips+'<em>'+esc(details||e.notes||'Record saved by AI Add.')+'</em></div>'}).join('');
  }
  function renderRecordsTable(){
    const list=currentRecords();
    const rows=list.slice(0,80).map(function(r){const type=r.record_type||r.type||r.module||'record';const name=r.name||r.full_name||r.lead_name||r.contact_name||r.deal_name||'Untitled';const company=r.company||r.organization||r.account_name||'';const next=r.next_step||r.notes||'';return '<tr><td><strong>'+esc(name)+'</strong></td><td><span class="ai-edit-pill">'+esc(cleanType(type))+'</span></td><td>'+esc(company)+'</td><td>'+esc(r.email||'')+'</td><td>'+esc(r.phone||r.mobile||'')+'</td><td>'+esc(next).slice(0,130)+'</td></tr>'}).join('');
    return '<div class="ai-edit-records-table"><table><thead><tr><th>Name</th><th>Type</th><th>Company</th><th>Email</th><th>Phone</th><th>Next step / notes</th></tr></thead><tbody>'+(rows||'<tr><td colspan="6">No server records loaded yet. Refresh the dashboard if needed.</td></tr>')+'</tbody></table></div>';
  }
  function renderEditRecordsTab(){
    const content=document.getElementById('crmContent'); if(!content)return;
    if(typeof window.activeCrm!=='undefined') window.activeCrm='editrecords';
    const title=document.getElementById('crmTitle'); if(title) title.textContent='Edit Records';
    const sub=document.getElementById('crmSubtitle'); if(sub) sub.textContent='Use AI Add to break plain text into contacts, accounts, deals, tasks, notes, and activities.';
    setActiveButtons();
    content.innerHTML='<div class="ai-edit-tab-wrap"><section class="ai-edit-builder"><h3>AI Add: semantic record builder</h3><p>Type a messy CRM update. This runs the corrected backend route and saves separate server records. Example: a person plus a future call becomes a contact plus a task.</p><textarea id="aiEditRecordsText" placeholder="Example: Chris Evans wants me to call him at 9pm"></textarea><div class="ai-edit-examples">'+EXAMPLES.map(function(x){return '<button type="button" class="ai-edit-example" data-example="'+esc(x)+'">'+esc(x)+'</button>'}).join('')+'</div><div class="ai-edit-actions"><button type="button" id="aiEditRecordsRun">AI Add Records</button><button type="button" class="secondary" id="aiEditRecordsRefresh">Refresh Records</button><button type="button" class="secondary" id="aiEditRecordsClear">Clear</button><span id="aiEditRecordsStatus" class="ai-edit-status"></span></div><div id="aiEditRecordsError" class="ai-edit-error"></div><div id="aiEditRecordsResults" class="ai-edit-results"></div></section><section><div class="crm-panel-head"><h3>Current server records</h3><span class="ai-edit-pill">'+currentRecords().length+' loaded</span></div>'+renderRecordsTable()+'</section></div>';
    const root=content.querySelector('.ai-edit-tab-wrap');
    root.addEventListener('click',function(e){const ex=e.target.closest('[data-example]');if(ex){document.getElementById('aiEditRecordsText').value=ex.getAttribute('data-example')||'';}});
    document.getElementById('aiEditRecordsRun').addEventListener('click',runAiAdd);
    document.getElementById('aiEditRecordsRefresh').addEventListener('click',function(){if(typeof load==='function')load(true);setTimeout(renderEditRecordsTab,500)});
    document.getElementById('aiEditRecordsClear').addEventListener('click',function(){document.getElementById('aiEditRecordsText').value='';document.getElementById('aiEditRecordsResults').innerHTML='';document.getElementById('aiEditRecordsError').textContent='';document.getElementById('aiEditRecordsStatus').textContent='';});
  }
  async function runAiAdd(){
    const text=String(document.getElementById('aiEditRecordsText').value||'').trim();const status=document.getElementById('aiEditRecordsStatus');const error=document.getElementById('aiEditRecordsError');const btn=document.getElementById('aiEditRecordsRun');
    if(!text){error.textContent='Enter plain text first.';return;} error.textContent=''; status.textContent='Breaking text into CRM records...'; btn.disabled=true;
    try{const res=await fetch('/api/crm/ai-entry?token='+encodeURIComponent(TOKEN),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:TOKEN,text:text})});const json=await res.json().catch(function(){return {ok:false,error:'Invalid JSON response'}});if(!res.ok||json.ok===false)throw new Error(json.error||'AI Add failed.');renderReturnedActions(json);status.textContent='Saved '+((json.actions||[]).length)+' server record action(s).';if(typeof load==='function')await load(true);setTimeout(renderEditRecordsTab,650);}catch(err){error.textContent=err.message||'AI Add failed.';status.textContent='';}finally{btn.disabled=false;}
  }
  document.addEventListener('click',function(e){const btn=e.target.closest('#crm [data-crm="editrecords"]');if(btn){e.preventDefault();e.stopPropagation();renderEditRecordsTab();}},true);
  function tick(){ensureEditRecordsTab();}
  document.addEventListener('DOMContentLoaded',tick);setTimeout(tick,300);setTimeout(tick,1200);setInterval(tick,1500);
  window.renderAiEditRecordsTab=renderEditRecordsTab;
})();
</script>
`;
  if (html.includes("</body>")) html = html.replace("</body>", block + "\n</body>");
  else html += block;
  changed = true;
}

if (changed || html.includes("__crmEditRecordsAiBuilder_v1") || html.includes("__crmEditRecordsAiBuilder_v2")) {
  fs.writeFileSync(file, html);
  console.log("[crm-edit-records-ai-builder-patch] Added AI Add directly inside the CRM Edit Records tab.");
} else {
  console.log("[crm-edit-records-ai-builder-patch] AI Add is already installed inside Edit Records tab.");
}
