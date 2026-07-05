import fs from "fs";

const file = "dashboard.html";
if (!fs.existsSync(file)) {
  console.warn("[crm-edit-records-inline-ai-add-patch] dashboard.html not found; skipping.");
  process.exit(0);
}

let html = fs.readFileSync(file, "utf8");
let changed = false;

const marker = "__crmEditRecordsInlineAiAdd_v1";
if (!html.includes(marker)) {
  const block = String.raw`
<style id="__crmEditRecordsInlineAiAdd_v1_styles">
  .inline-ai-add-card{border:1px solid #b7ebd2;background:linear-gradient(135deg,#ecfdf5,#ffffff);border-radius:14px;padding:15px;margin:0 0 16px;box-shadow:0 14px 34px rgba(15,23,42,.10)}
  .inline-ai-add-card h3{margin:0 0 6px;color:#064e3b;font-size:20px}.inline-ai-add-card p{margin:0 0 10px;color:#556987;line-height:1.45}.inline-ai-add-card textarea{width:100%;min-height:110px;resize:vertical;border:1px solid #b7d9cf;border-radius:12px;padding:12px;background:#020617;color:#fff;font:inherit;line-height:1.45}.inline-ai-add-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}.inline-ai-add-actions button,.inline-ai-example{border:1px solid #10b981;background:#10b981;color:#03251d;border-radius:10px;padding:10px 14px;font-weight:950}.inline-ai-add-actions button.secondary,.inline-ai-example{background:#fff;color:#047857;border-color:#cfe8de}.inline-ai-add-actions button:disabled{opacity:.55;cursor:wait}.inline-ai-status{font-size:12px;color:#047857;font-weight:900}.inline-ai-error{color:#b91c1c;font-size:12px;font-weight:900;margin-top:8px}.inline-ai-examples{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.inline-ai-example{font-size:11px;padding:7px 9px}.inline-ai-results{display:grid;gap:8px;margin-top:12px}.inline-ai-result{border:1px solid #dbe8e4;background:white;border-radius:10px;padding:10px}.inline-ai-result strong{display:block;color:#022c22;margin-bottom:4px}.inline-ai-result span{display:inline-flex;border-radius:999px;background:#e8f8ef;color:#047857;padding:3px 7px;font-size:11px;font-weight:900;margin:0 6px 5px 0}.inline-ai-result em{display:block;color:#64748b;font-size:12px;font-style:normal;white-space:pre-wrap}
</style>
<script id="__crmEditRecordsInlineAiAdd_v1">
(function(){
  const TOKEN = new URLSearchParams(location.search).get('token') || 'demo';
  const EXAMPLES = [
    'Chris Evans wants me to call him at 9pm',
    'Sarah at Acme Roofing wants a $5000 website quote and I need to call her tomorrow',
    'Mike from Green Valley Gym emailed about a new app project worth 12000, follow up Friday'
  ];
  function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[m]})}
  function textOf(el){return String(el && el.textContent || '').replace(/\s+/g,' ').trim().toLowerCase()}
  function findRealEditRecordsCard(){
    const headings=[...document.querySelectorAll('h1,h2,h3,strong,.card-title,.crm-panel-head')];
    const editHeading=headings.find(function(h){return /^edit records$/i.test(String(h.textContent||'').trim())});
    if(!editHeading) return null;
    let node=editHeading;
    for(let i=0;i<8 && node;i++,node=node.parentElement){
      const t=textOf(node);
      if(t.includes('manually add a new record') || (node.querySelector && node.querySelector('select,input,textarea'))) return node;
    }
    return editHeading.parentElement;
  }
  function renderActions(json){
    const box=document.getElementById('inlineAiAddResults'); if(!box)return;
    const actions=Array.isArray(json.actions)?json.actions:[];
    if(!actions.length){box.innerHTML='<div class="inline-ai-result"><strong>No record actions returned</strong><em>The server responded but did not return created/edited records.</em></div>';return;}
    box.innerHTML=actions.map(function(a,i){const e=a.entry||{};const type=e.record_type||e.type||'record';const name=e.name||e.deal_name||e.company||e.email||'CRM record';const chips=[a.action||'create',type,e.module||'',e.status||'',e.priority||''].filter(Boolean).map(function(x){return '<span>'+esc(x)+'</span>'}).join('');const details=[e.company?'Company: '+e.company:'',e.email?'Email: '+e.email:'',e.phone?'Phone: '+e.phone:'',Number(e.value)?'Value: $'+Number(e.value).toLocaleString():'',e.next_step?'Next step: '+e.next_step:'',a.reason?'Reason: '+a.reason:''].filter(Boolean).join('\n');return '<div class="inline-ai-result"><strong>'+(i+1)+'. '+esc(name)+' · '+esc(String(type).replace(/_/g,' '))+'</strong>'+chips+'<em>'+esc(details||e.notes||'Record saved by AI Add.')+'</em></div>'}).join('');
  }
  async function runAiAdd(){
    const text=String(document.getElementById('inlineAiAddText').value||'').trim();const status=document.getElementById('inlineAiAddStatus');const error=document.getElementById('inlineAiAddError');const btn=document.getElementById('inlineAiAddRun');
    if(!text){error.textContent='Enter plain text first.';return;} error.textContent=''; status.textContent='Breaking text into CRM records...'; btn.disabled=true;
    try{const res=await fetch('/api/crm/ai-entry?token='+encodeURIComponent(TOKEN),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:TOKEN,text:text})});const json=await res.json().catch(function(){return {ok:false,error:'Invalid JSON response'}});if(!res.ok||json.ok===false)throw new Error(json.error||'AI Add failed.');renderActions(json);status.textContent='Saved '+((json.actions||[]).length)+' server record action(s).';if(typeof load==='function')setTimeout(function(){load(true)},500);}catch(err){error.textContent=err.message||'AI Add failed.';status.textContent='';}finally{btn.disabled=false;}
  }
  function mountInlineAiAdd(){
    const card=findRealEditRecordsCard();
    if(!card || document.getElementById('inlineAiAddCard')) return;
    const panel=document.createElement('section');
    panel.id='inlineAiAddCard'; panel.className='inline-ai-add-card';
    panel.innerHTML='<h3>AI Add</h3><p>Paste a messy CRM update. AI Add will create the right server records: contacts, tasks, accounts, deals, notes, and activities.</p><textarea id="inlineAiAddText" placeholder="Example: Chris Evans wants me to call him at 9pm"></textarea><div class="inline-ai-examples">'+EXAMPLES.map(function(x){return '<button type="button" class="inline-ai-example" data-example="'+esc(x)+'">'+esc(x)+'</button>'}).join('')+'</div><div class="inline-ai-add-actions"><button type="button" id="inlineAiAddRun">AI Add Records</button><button type="button" class="secondary" id="inlineAiAddClear">Clear</button><span id="inlineAiAddStatus" class="inline-ai-status"></span></div><div id="inlineAiAddError" class="inline-ai-error"></div><div id="inlineAiAddResults" class="inline-ai-results"></div>';
    card.insertBefore(panel, card.firstElementChild && card.firstElementChild.nextSibling ? card.firstElementChild.nextSibling : card.firstChild);
    panel.addEventListener('click',function(e){const ex=e.target.closest('[data-example]');if(ex)document.getElementById('inlineAiAddText').value=ex.getAttribute('data-example')||'';});
    document.getElementById('inlineAiAddRun').addEventListener('click',runAiAdd);
    document.getElementById('inlineAiAddClear').addEventListener('click',function(){document.getElementById('inlineAiAddText').value='';document.getElementById('inlineAiAddError').textContent='';document.getElementById('inlineAiAddStatus').textContent='';document.getElementById('inlineAiAddResults').innerHTML='';});
  }
  document.addEventListener('DOMContentLoaded',mountInlineAiAdd);document.addEventListener('click',function(){setTimeout(mountInlineAiAdd,120)},true);setInterval(mountInlineAiAdd,1000);setTimeout(mountInlineAiAdd,400);setTimeout(mountInlineAiAdd,1500);
})();
</script>
`;
  if (html.includes("</body>")) html = html.replace("</body>", block + "\n</body>");
  else html += block;
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, html);
  console.log("[crm-edit-records-inline-ai-add-patch] AI Add now mounts inside the real Edit Records card.");
} else {
  console.log("[crm-edit-records-inline-ai-add-patch] Inline AI Add already installed.");
}
