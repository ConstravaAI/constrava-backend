(function(){
  if(window.__constravaGoogleFormsConnectorLoaded) return;
  window.__constravaGoogleFormsConnectorLoaded = true;

  const params = new URLSearchParams(window.location.search);
  const isPrivate = params.get('mode') === 'private' || window.location.pathname.startsWith('/app') || window.top !== window.self;
  const baseUrl = window.location.origin || 'https://constrava-backend.onrender.com';
  const token = params.get('token') || 'demo';
  const STORE_KEY = 'constravaCrmDemoAdds';
  const CONNECTION_KEY = 'constravaGoogleFormsConnectionId';
  if(isPrivate && params.get('googleFormsConnected') === '1' && params.get('connectionId')) sessionStorage.setItem(CONNECTION_KEY, params.get('connectionId'));

  const style=document.createElement('style');
  style.textContent=`.gf-modal{position:fixed;inset:0;z-index:1600;display:none;place-items:center;background:rgba(2,18,14,.66);backdrop-filter:blur(10px);padding:20px}.gf-modal.open{display:grid}.gf-box{width:min(1100px,100%);max-height:92vh;overflow:auto;background:#fff;border-radius:24px;border:1px solid rgba(16,185,129,.22);box-shadow:0 34px 110px rgba(0,0,0,.34)}.gf-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:linear-gradient(135deg,#f8fffc,#ecfdf5)}.gf-head h2{margin:0;color:#022c22}.gf-head p{margin:8px 0 0;color:#475569;line-height:1.5}.gf-body{padding:22px 24px;display:grid;gap:14px}.gf-card{border:1px solid #dbe8e4;border-radius:16px;background:#fff;padding:15px;box-shadow:0 8px 22px rgba(15,23,42,.04)}.gf-card h3{margin:0 0 8px;color:#022c22}.gf-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.gf-field label{display:block;margin-bottom:6px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#047857;font-weight:950}.gf-field input,.gf-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;color:#0f172a;padding:12px 13px;font:inherit}.gf-field textarea{min-height:94px;resize:vertical}.gf-wide{grid-column:1/-1}.gf-btn{border:1px solid #dbe8e4;border-radius:13px;background:white;color:#073d32;min-height:45px;padding:0 14px;font-weight:900;cursor:pointer}.gf-primary{background:#10b981;border-color:#10b981;color:#022c22}.gf-dark{background:#052e24;border-color:#052e24;color:#d1fae5}.gf-status{border:1px solid #dbe8e4;border-radius:14px;background:#f8fafc;padding:12px;color:#334155;font-size:13px;line-height:1.45}.gf-ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}.gf-warn{background:#fffbeb;color:#92400e;border-color:rgba(245,158,11,.35)}.gf-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5}.gf-forms{display:grid;gap:8px}.gf-row{border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;padding:10px 11px;display:flex;justify-content:space-between;gap:8px;align-items:center;color:#073d32;font-size:12px;font-weight:850}.gf-row small{display:block;color:#64748b;font-weight:700;margin-top:3px}.gf-foot{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}@media(max-width:800px){.gf-grid{grid-template-columns:1fr}.gf-wide{grid-column:auto}.gf-row{display:block}.gf-row button{margin-top:8px}}`;
  document.head.appendChild(style);

  const modal=document.createElement('div');
  modal.className='gf-modal';
  modal.innerHTML=`<div class="gf-box"><div class="gf-head"><h2>Google Forms Connector</h2><p>Connect Google Forms using the normal Google permission flow, then forward form responses into the CRM.</p></div><div class="gf-body"><div id="gfGate"></div><div class="gf-card"><div class="gf-grid"><div class="gf-field"><label>Site / client name</label><input id="gfSite" value="Constrava Demo Site"></div><div class="gf-field"><label>Form connection name</label><input id="gfForm" value="Google Forms Lead Capture"></div><div class="gf-field"><label>Selected Google Form ID</label><input id="gfFormId" placeholder="Choose after sign-in"></div><div class="gf-field"><label>Lead owner</label><input id="gfOwner" value="Constrava Demo Team"></div></div></div><div class="gf-card"><h3>1. Sign in with Google</h3><button id="gfSignIn" class="gf-btn gf-dark" type="button">Sign in with Google</button><div id="gfStatus" class="gf-status" style="margin-top:10px">Not connected yet.</div></div><div class="gf-card"><h3>2. Choose a Google Form</h3><button id="gfLoad" class="gf-btn gf-primary" type="button">Load my Google Forms</button><div id="gfForms" class="gf-forms" style="margin-top:10px"><p style="color:#64748b">Sign in first, then load forms.</p></div></div><div class="gf-card"><h3>3. Install the response forwarder</h3><p style="color:#64748b;font-size:13px">Google Forms responses go to a response Sheet. Apps Script forwards each new response to Constrava so it becomes a CRM lead.</p><button id="gfScript" class="gf-btn" type="button">Generate Apps Script</button><div id="gfSetup" class="gf-code" style="margin-top:10px">After choosing a form, generate the response forwarder here.</div></div><div class="gf-card"><h3>4. Test the intake endpoint</h3><div class="gf-grid"><div class="gf-field"><label>Name</label><input id="gfTestName" value="Google Forms Test Lead"></div><div class="gf-field"><label>Email</label><input id="gfTestEmail" value="google.form.lead@example.com"></div><div class="gf-field"><label>Company</label><input id="gfTestCompany" value="Google Forms Client Co"></div><div class="gf-field"><label>Estimated value</label><input id="gfTestValue" type="number" value="7200"></div><div class="gf-field gf-wide"><label>Message</label><textarea id="gfTestMessage">This lead was sent through the real Google Forms intake endpoint test.</textarea></div></div></div></div><div class="gf-foot"><button id="gfClose" class="gf-btn" type="button">Close</button><div><button id="gfCopy" class="gf-btn" type="button">Copy script</button> <button id="gfDownload" class="gf-btn" type="button">Download script</button> <button id="gfTest" class="gf-btn gf-primary" type="button">Send test lead</button></div></div></div>`;
  document.body.appendChild(modal);

  const $=id=>document.getElementById(id);
  function slug(v,f){return String(v||f).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||f;}
  function siteSlug(){return slug($('gfSite').value,'google-forms-site');}
  function formSlug(){return slug($('gfForm').value,'google-forms-lead-capture');}
  function endpoint(){return `${baseUrl}/api/forms/intake/${siteSlug()}/${formSlug()}`;}
  function hookKey(){return `cx_${siteSlug().replace(/-/g,'_')}_${formSlug().replace(/-/g,'_')}_google`;}
  function conn(){return sessionStorage.getItem(CONNECTION_KEY)||'';}
  function toast(msg){const t=$('toast');if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);}else alert(msg);}
  function saveLead(lead){try{const d=window.data||{leads:[]};window.data=d;d.leads=Array.isArray(d.leads)?d.leads:[];d.leads.unshift(lead);const list=JSON.parse(sessionStorage.getItem(STORE_KEY)||'[]');list.unshift(lead);sessionStorage.setItem(STORE_KEY,JSON.stringify(list.slice(0,80)));}catch{}}
  function rerender(){if(typeof renderCRM==='function')renderCRM('leads');else if(window.renderCRM)window.renderCRM('leads');}
  function script(){return `const CONSTRAVA_ENDPOINT = "${endpoint()}";
const CONSTRAVA_KEY = "${hookKey()}";

function onFormSubmit(e) {
  const data = {};
  if (e && e.namedValues) {
    Object.keys(e.namedValues).forEach(function(fieldName) {
      const value = e.namedValues[fieldName];
      data[fieldName] = Array.isArray(value) ? value.join(", ") : value;
    });
  }
  data.provider = "Google Forms";
  data.source = "Google Forms";
  data.google_form_id = "${$('gfFormId').value || ''}";
  data.site_slug = "${siteSlug()}";
  data.form_slug = "${formSlug()}";
  UrlFetchApp.fetch(CONSTRAVA_ENDPOINT, {
    method: "post",
    contentType: "application/json",
    muteHttpExceptions: true,
    headers: { "x-constrava-key": CONSTRAVA_KEY, "x-form-provider": "Google Forms" },
    payload: JSON.stringify(data)
  });
}

// Setup: Open the response Sheet -> Extensions -> Apps Script -> paste this file -> Triggers -> Add Trigger -> onFormSubmit -> From spreadsheet -> On form submit.`;}
  function showScript(){ $('gfSetup').className='gf-code'; $('gfSetup').textContent=script(); }
  async function status(){
    if(!isPrivate){$('gfGate').innerHTML='<div class="gf-status gf-warn">Blocked on public demo. Open the private site to connect Google Forms.</div>';$('gfStatus').textContent='Blocked on public demo.';return;}
    $('gfGate').innerHTML='';
    if(!conn()){$('gfStatus').className='gf-status';$('gfStatus').textContent='Not connected yet. Click Sign in with Google to begin.';return;}
    try{const r=await fetch(`/api/google/forms/status?private=1&connectionId=${encodeURIComponent(conn())}`);const j=await r.json();if(!j.ok)throw new Error(j.error);$('gfStatus').className='gf-status gf-ok';$('gfStatus').textContent='Connected as '+j.connection.account;}catch{$('gfStatus').className='gf-status gf-warn';$('gfStatus').textContent='Connection was lost after redeploy. Sign in again.';}
  }
  function signIn(){
    if(!isPrivate){toast('Google sign-in is blocked on the public demo.');return;}
    const returnTo=window.location.pathname+window.location.search;
    const url=`/auth/google/forms/start?private=1&siteSlug=${encodeURIComponent(siteSlug())}&formSlug=${encodeURIComponent(formSlug())}&token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`;
    window.location.href=url;
  }
  async function loadForms(){
    if(!isPrivate){toast('Google Forms loading is blocked on the public demo.');return;}if(!conn()){toast('Sign in with Google first.');return;}
    $('gfForms').innerHTML='<p style="color:#64748b">Loading...</p>';
    try{const r=await fetch(`/api/google/forms/list?private=1&connectionId=${encodeURIComponent(conn())}`);const j=await r.json();if(!j.ok)throw new Error(j.error||'Could not load forms.');if(!j.forms.length){$('gfForms').innerHTML='<p style="color:#64748b">No Google Forms found.</p>';return;}$('gfForms').innerHTML=j.forms.map(f=>`<div class="gf-row"><span>${f.name}<small>${f.id}</small></span><button class="gf-btn gf-primary" data-id="${f.id}" data-name="${String(f.name).replace(/"/g,'&quot;')}">Use form</button></div>`).join('');document.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>{$('gfFormId').value=b.dataset.id;$('gfForm').value=b.dataset.name;showScript();toast('Selected '+b.dataset.name);});}catch(e){$('gfForms').innerHTML='<p style="color:#64748b">'+e.message+'</p>';}
  }
  function copy(){showScript();navigator.clipboard?.writeText($('gfSetup').textContent).then(()=>toast('Script copied.')).catch(()=>toast('Could not copy.'));}
  function download(){showScript();const blob=new Blob([$('gfSetup').textContent],{type:'text/javascript'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`constrava-google-forms-${siteSlug()}-${formSlug()}.gs`;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500);}
  async function test(){
    if(!isPrivate){toast('Testing is blocked on the public demo.');return;}
    const body={name:$('gfTestName').value,email:$('gfTestEmail').value,company:$('gfTestCompany').value,message:$('gfTestMessage').value,value:Number($('gfTestValue').value||0),provider:'Google Forms',source:'Google Forms',google_form_id:$('gfFormId').value,owner:$('gfOwner').value};
    try{const r=await fetch(endpoint(),{method:'POST',headers:{'Content-Type':'application/json','x-constrava-key':hookKey(),'x-form-provider':'Google Forms'},body:JSON.stringify(body)});const j=await r.json();if(!j.ok)throw new Error(j.error||'Test failed.');if(j.lead)saveLead(j.lead);modal.classList.remove('open');rerender();toast('Google Forms test lead added to CRM.');}catch(e){toast(e.message);}
  }
  function open(){modal.classList.add('open');showScript();status();}
  $('gfClose').onclick=()=>modal.classList.remove('open');$('gfSignIn').onclick=signIn;$('gfLoad').onclick=loadForms;$('gfScript').onclick=showScript;$('gfCopy').onclick=copy;$('gfDownload').onclick=download;$('gfTest').onclick=test;modal.onclick=e=>{if(e.target===modal)modal.classList.remove('open');};
  document.addEventListener('click',function(e){const btn=e.target.closest('[data-cx-flow="website"]');if(!btn)return;e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();open();},true);
})();
