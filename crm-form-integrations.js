(function(){
  if(window.__constravaThirdPartyFormsLoaded) return;
  window.__constravaThirdPartyFormsLoaded = true;

  const params = new URLSearchParams(window.location.search);
  const isPrivate = params.get('mode') === 'private' || window.location.pathname.startsWith('/app') || window.top !== window.self;
  const STORE_KEY = 'constravaCrmDemoAdds';
  const GOOGLE_KEY = 'constravaGoogleFormsConnectionId';
  const baseUrl = window.location.origin || 'https://constrava-backend.onrender.com';
  const token = params.get('token') || 'demo';
  const callbackConnection = params.get('connectionId');
  if(isPrivate && params.get('googleFormsConnected') === '1' && callbackConnection) sessionStorage.setItem(GOOGLE_KEY, callbackConnection);

  const css = document.createElement('style');
  css.textContent = `
    .gf-modal{position:fixed;inset:0;z-index:1500;display:none;place-items:center;background:rgba(2,18,14,.66);backdrop-filter:blur(10px);padding:20px}.gf-modal.open{display:grid}.gf-box{width:min(1120px,100%);max-height:92vh;overflow:auto;background:#fff;border:1px solid rgba(16,185,129,.2);border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.34)}.gf-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:radial-gradient(circle at 15% 0,rgba(16,185,129,.2),transparent 36%),linear-gradient(135deg,#f8fffc,#ecfdf5)}.gf-head h2{margin:0;color:#022c22}.gf-head p{margin:8px 0 0;color:#475569;line-height:1.5}.gf-body{padding:22px 24px;display:grid;gap:14px}.gf-card{border:1px solid #dbe8e4;border-radius:16px;background:#fff;padding:15px;box-shadow:0 8px 22px rgba(15,23,42,.04)}.gf-card h3{margin:0 0 8px;color:#022c22}.gf-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.gf-field label{display:block;margin-bottom:6px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#047857;font-weight:950}.gf-field input,.gf-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;color:#0f172a;padding:12px 13px;font:inherit}.gf-field textarea{min-height:100px;resize:vertical}.gf-wide{grid-column:1/-1}.gf-methods{display:grid;grid-template-columns:1fr 1fr;gap:12px}.gf-method{border:1px solid #dbe8e4;border-radius:16px;background:#f8fffc;padding:15px;display:grid;gap:10px}.gf-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5}.gf-locked{border:1px solid rgba(245,158,11,.35);background:#fffbeb;color:#92400e;border-radius:14px;padding:13px 14px;font-weight:850;line-height:1.45}.gf-foot{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}.gf-btn{border:1px solid #dbe8e4;border-radius:13px;background:#fff;color:#073d32;min-height:45px;padding:0 14px;font-weight:900;cursor:pointer}.gf-primary{background:#10b981;border-color:#10b981;color:#022c22}.gf-dark{background:#052e24;border-color:#052e24;color:#d1fae5}.gf-muted{color:#64748b;font-size:12px;line-height:1.45}.gf-status{border:1px solid #dbe8e4;border-radius:14px;background:#f8fafc;padding:12px;color:#334155;font-size:13px;line-height:1.45}.gf-status.ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}.gf-form-list{display:grid;gap:8px;margin-top:10px}.gf-form-row{border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;padding:10px 11px;display:flex;justify-content:space-between;gap:8px;align-items:center;color:#073d32;font-size:12px;font-weight:850}.gf-form-row small{display:block;color:#64748b;font-weight:700;margin-top:3px}.gf-pill{display:inline-flex;border:1px solid rgba(16,185,129,.25);background:#ecfdf5;color:#047857;border-radius:999px;padding:6px 9px;font-size:11px;font-weight:950;margin:4px 6px 0 0}@media(max-width:850px){.gf-grid,.gf-methods{grid-template-columns:1fr}.gf-wide{grid-column:auto}.gf-form-row{display:block}.gf-form-row button{margin-top:8px}}
  `;
  document.head.appendChild(css);

  const modal = document.createElement('div');
  modal.className = 'gf-modal';
  modal.innerHTML = `<div class="gf-box"><div class="gf-head"><h2>Google Forms Connector</h2><p>Start with Google Forms first: sign in with Google, list available forms, choose a form, then install the generated Apps Script so future responses become CRM leads.</p></div><div class="gf-body"><div id="gfLock"></div><div class="gf-card"><div class="gf-grid"><div class="gf-field"><label>Site / client name</label><input id="gfSiteName" value="Constrava Demo Site"></div><div class="gf-field"><label>CRM form connection name</label><input id="gfFormName" value="Google Forms Lead Capture"></div><div class="gf-field"><label>Selected Google Form ID</label><input id="gfFormId" placeholder="Choose after Google sign-in or paste a form ID"></div><div class="gf-field"><label>Lead owner</label><input id="gfOwner" value="Constrava Demo Team"></div></div></div><div class="gf-card"><h3>Connection pathway</h3><div class="gf-methods"><div class="gf-method"><strong>1. Sign in with Google</strong><p class="gf-muted">Redirects to Google's authorization screen. After approval, Constrava can list Google Forms from Drive metadata.</p><button id="gfSignin" class="gf-btn gf-dark" type="button">Sign in with Google</button><div id="gfStatus" class="gf-status">Not connected yet.</div></div><div class="gf-method"><strong>2. Install response forwarder</strong><p class="gf-muted">Google Forms responses are forwarded to the CRM through Apps Script on the response Sheet. This is the part that sends new submissions into Constrava.</p><button id="gfScript" class="gf-btn" type="button">Generate Apps Script</button><div class="gf-status">Uses the real Constrava intake endpoint.</div></div></div></div><div class="gf-card"><h3>Your Google Forms</h3><button id="gfLoadForms" class="gf-btn gf-primary" type="button">Load my Google Forms</button><div id="gfForms" class="gf-form-list"><p class="gf-muted">Sign in first, then load forms.</p></div></div><div class="gf-card"><h3>Generated setup code</h3><div id="gfSetup" class="gf-code">Sign in and choose a form to generate the Apps Script forwarder.</div></div><div class="gf-card"><h3>Test submission</h3><div class="gf-grid"><div class="gf-field"><label>Name</label><input id="gfTestName" value="Google Forms Test Lead"></div><div class="gf-field"><label>Email</label><input id="gfTestEmail" value="google.form.lead@example.com"></div><div class="gf-field"><label>Company</label><input id="gfTestCompany" value="Google Forms Client Co"></div><div class="gf-field"><label>Estimated value</label><input id="gfTestValue" type="number" value="7200"></div><div class="gf-field gf-wide"><label>Message</label><textarea id="gfTestMessage">This lead was sent through the real Google Forms intake endpoint test.</textarea></div></div></div></div><div class="gf-foot"><button id="gfClose" class="gf-btn" type="button">Close</button><div><button id="gfCopyScript" class="gf-btn" type="button">Copy script</button> <button id="gfDownloadScript" class="gf-btn" type="button">Download script</button> <button id="gfTest" class="gf-btn gf-primary" type="button">Send test to real endpoint</button></div></div></div>`;
  document.body.appendChild(modal);

  function clean(value, fallback){ return String(value||fallback||'item').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || fallback || 'item'; }
  function siteSlug(){ return clean(document.getElementById('gfSiteName')?.value,'google-forms-site'); }
  function formSlug(){ return clean(document.getElementById('gfFormName')?.value,'google-forms-lead-capture'); }
  function connectionId(){ return sessionStorage.getItem(GOOGLE_KEY) || ''; }
  function endpoint(){ return `${baseUrl}/api/forms/intake/${siteSlug()}/${formSlug()}`; }
  function secret(){ return `cx_${siteSlug().replace(/-/g,'_')}_${formSlug().replace(/-/g,'_')}_google`; }
  function toast(msg){ const t=document.getElementById('toast'); if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);} else alert(msg); }
  function dash(){ try{ if(typeof data !== 'undefined' && data) return data; }catch(e){} window.data=window.data||{leads:[]}; return window.data; }
  function saved(){ try{return JSON.parse(sessionStorage.getItem(STORE_KEY)||'[]');}catch(e){return[];} }
  function save(record){ const d=dash(); d.leads=Array.isArray(d.leads)?d.leads:[]; d.leads.unshift(record); const list=saved(); list.unshift(record); sessionStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0,80))); }
  function rerender(){ if(typeof renderCRM==='function') renderCRM('leads'); else if(window.renderCRM) window.renderCRM('leads'); }

  function scriptText(){ return `const CONSTRAVA_ENDPOINT = "${endpoint()}";
const CONSTRAVA_KEY = "${secret()}";

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
  data.google_form_id = "${document.getElementById('gfFormId')?.value || ''}";
  data.site_slug = "${siteSlug()}";
  data.form_slug = "${formSlug()}";

  UrlFetchApp.fetch(CONSTRAVA_ENDPOINT, {
    method: "post",
    contentType: "application/json",
    muteHttpExceptions: true,
    headers: {
      "x-constrava-key": CONSTRAVA_KEY,
      "x-form-provider": "Google Forms"
    },
    payload: JSON.stringify(data)
  });
}

// Setup:
// 1. Open your Google Form responses spreadsheet.
// 2. Extensions -> Apps Script.
// 3. Paste this file.
// 4. Triggers -> Add Trigger -> choose onFormSubmit.
// 5. Event source: From spreadsheet. Event type: On form submit.`; }
  function renderLock(){ document.getElementById('gfLock').innerHTML = isPrivate ? '' : `<div class="gf-locked"><b>Blocked on public demo.</b><br>Google sign-in, form listing, Apps Script generation, and test submissions only work on the private site.</div>`; }
  async function renderStatus(){
    const status=document.getElementById('gfStatus');
    if(!isPrivate){ status.textContent='Blocked on public demo.'; return; }
    const id=connectionId();
    if(!id){ status.className='gf-status'; status.textContent='Not connected yet.'; return; }
    try{
      const res=await fetch(`/api/google/forms/status?private=1&connectionId=${encodeURIComponent(id)}`);
      const json=await res.json();
      if(!json.ok) throw new Error(json.error||'Connection not found');
      status.className='gf-status ok';
      status.textContent='Connected as '+json.connection.account;
    }catch(err){ status.className='gf-status'; status.textContent='Connection saved locally, but server session was not found. Sign in again after a redeploy.'; }
  }
  function renderSetup(){ document.getElementById('gfSetup').textContent=scriptText(); }
  function open(){ modal.classList.add('open'); renderLock(); renderStatus(); renderSetup(); }
  function close(){ modal.classList.remove('open'); }
  function signIn(){
    if(!isPrivate){ toast('Google Forms sign-in is blocked on the public demo.'); return; }
    const returnTo = window.location.pathname + window.location.search;
    const url = `/auth/google/forms/start?private=1&siteSlug=${encodeURIComponent(siteSlug())}&formSlug=${encodeURIComponent(formSlug())}&token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`;
    window.location.href = url;
  }
  async function loadForms(){
    if(!isPrivate){ toast('Google Forms loading is blocked on the public demo.'); return; }
    const id=connectionId();
    if(!id){ toast('Sign in with Google first.'); return; }
    const wrap=document.getElementById('gfForms');
    wrap.innerHTML='<p class="gf-muted">Loading Google Forms...</p>';
    try{
      const res=await fetch(`/api/google/forms/list?private=1&connectionId=${encodeURIComponent(id)}`);
      const json=await res.json();
      if(!json.ok) throw new Error(json.error||'Could not load forms.');
      if(!json.forms.length){ wrap.innerHTML='<p class="gf-muted">No Google Forms found in this Google Drive account.</p>'; return; }
      wrap.innerHTML=json.forms.map(f=>`<div class="gf-form-row"><span>${f.name}<small>${f.id}</small></span><button class="gf-btn gf-primary" data-form-id="${f.id}" data-form-name="${String(f.name).replace(/"/g,'&quot;')}" type="button">Use form</button></div>`).join('');
      wrap.querySelectorAll('[data-form-id]').forEach(btn=>btn.onclick=()=>{ document.getElementById('gfFormId').value=btn.dataset.formId; document.getElementById('gfFormName').value=btn.dataset.formName; renderSetup(); toast('Selected '+btn.dataset.formName); });
    }catch(err){ wrap.innerHTML='<p class="gf-muted">'+err.message+'</p>'; }
  }
  async function generateScript(){
    if(!isPrivate){ toast('Apps Script generation is blocked on the public demo.'); return; }
    renderSetup();
    try{
      const res=await fetch(`/api/google/forms/apps-script?private=1&siteSlug=${encodeURIComponent(siteSlug())}&formSlug=${encodeURIComponent(formSlug())}&key=${encodeURIComponent(secret())}`);
      if(res.ok) document.getElementById('gfSetup').textContent=await res.text();
    }catch{}
    toast('Apps Script generated.');
  }
  function copyScript(){ if(!isPrivate){ toast('Copy is blocked on the public demo.'); return; } renderSetup(); navigator.clipboard?.writeText(document.getElementById('gfSetup').textContent).then(()=>toast('Apps Script copied.')).catch(()=>toast('Could not copy script.')); }
  function downloadScript(){
    if(!isPrivate){ toast('Download is blocked on the public demo.'); return; }
    renderSetup();
    const blob=new Blob([document.getElementById('gfSetup').textContent],{type:'text/javascript'});
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`constrava-google-forms-${siteSlug()}-${formSlug()}.gs`; document.body.appendChild(a); a.click(); setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500); toast('Google Apps Script downloaded.');
  }
  async function sendTest(){
    if(!isPrivate){ toast('Testing is blocked on the public demo.'); return; }
    const payload={ name:document.getElementById('gfTestName').value, email:document.getElementById('gfTestEmail').value, company:document.getElementById('gfTestCompany').value, message:document.getElementById('gfTestMessage').value, value:Number(document.getElementById('gfTestValue').value||0), provider:'Google Forms', source:'Google Forms', google_form_id:document.getElementById('gfFormId').value, owner:document.getElementById('gfOwner').value };
    try{
      const res=await fetch(endpoint(),{method:'POST',headers:{'Content-Type':'application/json','x-constrava-key':secret(),'x-form-provider':'Google Forms'},body:JSON.stringify(payload)});
      const json=await res.json();
      if(!json.ok) throw new Error(json.error||'Test failed.');
      if(json.lead) save(json.lead);
      close(); rerender(); toast('Google Forms test lead added to CRM.');
    }catch(err){ toast(err.message); }
  }

  ['gfSiteName','gfFormName','gfFormId'].forEach(id=>document.addEventListener('input',e=>{ if(e.target && e.target.id===id) renderSetup(); }));
  document.getElementById('gfClose').onclick=close;
  document.getElementById('gfSignin').onclick=signIn;
  document.getElementById('gfLoadForms').onclick=loadForms;
  document.getElementById('gfScript').onclick=generateScript;
  document.getElementById('gfCopyScript').onclick=copyScript;
  document.getElementById('gfDownloadScript').onclick=downloadScript;
  document.getElementById('gfTest').onclick=sendTest;
  modal.onclick=e=>{ if(e.target===modal) close(); };
  document.addEventListener('click',function(e){ const btn=e.target.closest('[data-cx-flow="website"]'); if(!btn)return; e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); open(); },true);
})();
