import fs from "fs";

const file = "dashboard.html";
if (!fs.existsSync(file)) {
  console.warn("[crm-edit-records-ai-builder-patch] dashboard.html not found; skipping.");
  process.exit(0);
}

let html = fs.readFileSync(file, "utf8");
let changed = false;

// Remove the earlier v1 injection if it was already added by a prior deploy.
html = html.replace(/\n?<style id="__crmEditRecordsAiBuilder_v1_styles">[\s\S]*?<\/script>\s*/g, "\n");
html = html.replace(/sessionStorage\.setItem\('constravaCrmDemoAdds'[\s\S]*?\}\catch\(e\)\{\}/g, "try{sessionStorage.removeItem('constravaCrmDemoAdds')}catch(e){}");

const marker = "__crmEditRecordsAiBuilder_v2";
if (!html.includes(marker)) {
  const block = String.raw`
<style id="__crmEditRecordsAiBuilder_v2_styles">
  #aiEditRecordsLauncher{position:fixed;right:22px;bottom:22px;z-index:90;border:0;border-radius:999px;padding:14px 18px;background:#10b981;color:white;font-weight:950;box-shadow:0 18px 48px rgba(4,120,87,.32)}
  #aiEditRecordsPanel{position:fixed;right:22px;bottom:82px;width:min(560px,calc(100vw - 28px));max-height:min(760px,calc(100vh - 110px));overflow:auto;z-index:91;background:white;border:1px solid #b7ebd2;border-radius:18px;box-shadow:0 30px 90px rgba(15,23,42,.26);display:none}
  #aiEditRecordsPanel.open{display:block}.ai-edit-head{display:flex;align-items:start;justify-content:space-between;gap:10px;padding:16px 16px 10px;background:linear-gradient(135deg,#ecfdf5,#fff);border-bottom:1px solid #dbe8e4}.ai-edit-head h3{margin:0;color:#064e3b}.ai-edit-head p{margin:4px 0 0;color:#64748b;font-size:12px;line-height:1.35}.ai-edit-close{border:0;background:#e8f8ef;color:#047857;border-radius:9px;width:34px;height:34px;font-weight:950}.ai-edit-body{padding:14px}.ai-edit-body textarea{width:100%;min-height:132px;resize:vertical;border:1px solid #b7d9cf;border-radius:12px;padding:12px;background:#fff;color:#0f172a;font:inherit;line-height:1.45}.ai-edit-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}.ai-edit-actions button,.ai-edit-example{border:1px solid #0ea66b;background:#10b981;color:white;border-radius:9px;padding:9px 12px;font-weight:900}.ai-edit-actions button.secondary,.ai-edit-example{background:white;color:#047857;border-color:#b7d9cf}.ai-edit-actions button:disabled{opacity:.55;cursor:wait}.ai-edit-status{font-size:12px;color:#047857;font-weight:900}.ai-edit-error{color:#b91c1c;font-size:12px;font-weight:900;margin-top:8px}.ai-edit-examples{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.ai-edit-example{font-size:11px;padding:6px 8px}.ai-edit-results{display:grid;gap:8px;margin-top:12px}.ai-edit-card{border:1px solid #dbe8e4;background:#fff;border-radius:12px;padding:10px}.ai-edit-card strong{display:block;color:#022c22;margin-bottom:4px}.ai-edit-card span{display:inline-flex;border-radius:999px;background:#e8f8ef;color:#047857;padding:3px 7px;font-size:11px;font-weight:900;margin:0 6px 5px 0}.ai-edit-card em{display:block;color:#64748b;font-size:12px;font-style:normal;white-space:pre-wrap}.ai-edit-inline{border:1px solid #b7ebd2;background:#ecfdf5;color:#047857;border-radius:9px;padding:9px 12px;font-weight:900}
</style>
<script id="__crmEditRecordsAiBuilder_v2">
(function(){
  const TOKEN = new URLSearchParams(location.search).get('token') || 'demo';
  const EXAMPLES = [
    'Chris Evans wants me to call him at 9pm',
    'Sarah at Acme Roofing wants a $5000 website quote and I need to call her tomorrow',
    'Mike from Green Valley Gym emailed about a new app project worth 12000, follow up Friday'
  ];
  function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
  function cleanupLocalFakeRecords(){try{sessionStorage.removeItem('constravaCrmDemoAdds')}catch(e){}}
  function crmVisible(){const crm=document.getElementById('crm');return !!crm && !crm.classList.contains('hidden');}
  function ensureLauncher(){
    cleanupLocalFakeRecords();
    if(!document.getElementById('aiEditRecordsLauncher')){
      const b=document.createElement('button');b.id='aiEditRecordsLauncher';b.type='button';b.textContent='AI Edit Records';b.addEventListener('click',openPanel);document.body.appendChild(b);
    }
    if(!document.getElementById('aiEditRecordsPanel')){
      const p=document.createElement('section');p.id='aiEditRecordsPanel';p.innerHTML='<div class="ai-edit-head"><div><h3>AI Edit Records</h3><p>Break plain English into real CRM records. People become contacts, follow-ups become tasks, companies become accounts, and revenue opportunities become deals.</p></div><button class="ai-edit-close" type="button">×</button></div><div class="ai-edit-body"><textarea id="aiEditRecordsText" placeholder="Example: Chris Evans wants me to call him at 9pm"></textarea><div class="ai-edit-examples">'+EXAMPLES.map(x=>'<button type="button" class="ai-edit-example" data-example="'+escapeHtml(x)+'">'+escapeHtml(x)+'</button>').join('')+'</div><div class="ai-edit-actions"><button id="aiEditRecordsRun" type="button">Create / Edit Records</button><button id="aiEditRecordsClear" type="button" class="secondary">Clear</button><span id="aiEditRecordsStatus" class="ai-edit-status"></span></div><div id="aiEditRecordsError" class="ai-edit-error"></div><div id="aiEditRecordsResults" class="ai-edit-results"></div></div>';document.body.appendChild(p);
      p.querySelector('.ai-edit-close').addEventListener('click',()=>p.classList.remove('open'));
      p.addEventListener('click',e=>{const ex=e.target.closest('[data-example]');if(ex){document.getElementById('aiEditRecordsText').value=ex.getAttribute('data-example')||'';}});
      p.querySelector('#aiEditRecordsRun').addEventListener('click',runBuilder);
      p.querySelector('#aiEditRecordsClear').addEventListener('click',()=>{document.getElementById('aiEditRecordsText').value='';document.getElementById('aiEditRecordsResults').innerHTML='';document.getElementById('aiEditRecordsError').textContent='';document.getElementById('aiEditRecordsStatus').textContent='';});
    }
    mountInlineButton();
  }
  function mountInlineButton(){
    const actions=document.querySelector('#crm .crm-actions');
    if(actions && !document.getElementById('aiEditRecordsInline')){const b=document.createElement('button');b.id='aiEditRecordsInline';b.type='button';b.className='ai-edit-inline';b.textContent='AI Edit Records';b.addEventListener('click',openPanel);actions.prepend(b);}
  }
  function openPanel(){ensureLauncher();document.getElementById('aiEditRecordsPanel').classList.add('open');}
  function renderActions(json){
    const box=document.getElementById('aiEditRecordsResults');if(!box)return;const actions=Array.isArray(json.actions)?json.actions:[];
    if(!actions.length){box.innerHTML='<div class="ai-edit-card"><strong>No record actions returned</strong><em>The server responded but did not return created/edited records.</em></div>';return;}
    box.innerHTML=actions.map((a,i)=>{const e=a.entry||{};const type=e.record_type||e.type||'record';const name=e.name||e.deal_name||e.company||e.email||'CRM record';const chips=[a.action||'create',type,e.module||'',e.status||'',e.priority||''].filter(Boolean).map(x=>'<span>'+escapeHtml(x)+'</span>').join('');const details=[e.company?'Company: '+e.company:'',e.email?'Email: '+e.email:'',e.phone?'Phone: '+e.phone:'',Number(e.value)?'Value: $'+Number(e.value).toLocaleString():'',e.next_step?'Next step: '+e.next_step:'',a.reason?'Reason: '+a.reason:''].filter(Boolean).join('\n');return '<div class="ai-edit-card"><strong>'+(i+1)+'. '+escapeHtml(name)+' · '+escapeHtml(String(type).replace(/_/g,' '))+'</strong>'+chips+'<em>'+escapeHtml(details||e.notes||'Record saved by AI Edit Records.')+'</em></div>'}).join('');
  }
  async function runBuilder(){
    cleanupLocalFakeRecords();
    const text=String(document.getElementById('aiEditRecordsText').value||'').trim();const status=document.getElementById('aiEditRecordsStatus');const error=document.getElementById('aiEditRecordsError');const btn=document.getElementById('aiEditRecordsRun');
    if(!text){error.textContent='Enter plain text first.';return;} error.textContent=''; status.textContent='Breaking text into CRM records...'; btn.disabled=true;
    try{const res=await fetch('/api/crm/ai-entry?token='+encodeURIComponent(TOKEN),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:TOKEN,text})});const json=await res.json().catch(()=>({ok:false,error:'Invalid JSON response'}));if(!res.ok||json.ok===false)throw new Error(json.error||'AI Edit Records failed.');renderActions(json);status.textContent='Saved '+((json.actions||[]).length)+' server record action(s).';setTimeout(()=>{try{if(typeof load==='function')load(true);else location.reload();}catch(e){}},650);}catch(err){error.textContent=err.message||'AI Edit Records failed.';status.textContent='';}finally{btn.disabled=false;}
  }
  function tick(){ensureLauncher();const launcher=document.getElementById('aiEditRecordsLauncher');if(launcher)launcher.style.display=crmVisible()?'block':'none';mountInlineButton();}
  document.addEventListener('DOMContentLoaded',tick);document.addEventListener('click',()=>setTimeout(tick,80),true);setInterval(tick,1000);setTimeout(tick,300);setTimeout(tick,1200);
})();
</script>
`;
  if (html.includes("</body>")) html = html.replace("</body>", block + "\n</body>");
  else html += block;
  changed = true;
}

if (changed || html.includes("__crmEditRecordsAiBuilder_v1")) {
  fs.writeFileSync(file, html);
  console.log("[crm-edit-records-ai-builder-patch] Installed visible server-only AI Edit Records panel and removed v1 local fake-record behavior.");
} else {
  console.log("[crm-edit-records-ai-builder-patch] Visible server-only AI Edit Records panel already installed.");
}
