(function(){
  if(window.__constravaThirdPartyFormsLoaded) return;
  window.__constravaThirdPartyFormsLoaded = true;

  const params = new URLSearchParams(window.location.search);
  const isPrivate = params.get('mode') === 'private' || window.location.pathname.startsWith('/app') || window.top !== window.self;
  const STORE_KEY = 'constravaCrmDemoAdds';
  const CONNECTION_KEY = 'constravaFormProviderConnections';
  const baseUrl = window.location.origin || 'https://constrava-backend.onrender.com';
  const token = params.get('token') || 'demo';
  const platforms = {
    google:{name:'Google Forms',icon:'G',signin:'Sign in with Google',forms:['Website Contact Responses','Quote Request Form','Service Intake Form'],method:'Connect through Google Forms response Sheets, Apps Script, Zapier, or Make.'},
    typeform:{name:'Typeform',icon:'T',signin:'Sign in with Typeform',forms:['Lead Qualification Typeform','Project Intake Typeform','Customer Survey'],method:'Use Typeform OAuth/API or Typeform webhooks.'},
    jotform:{name:'Jotform',icon:'J',signin:'Sign in with Jotform',forms:['Contact Us','Appointment Request','Estimate Request'],method:'Use Jotform API or webhook forwarding.'},
    tally:{name:'Tally',icon:'Ta',signin:'Sign in with Tally',forms:['Tally Lead Form','Client Intake','Newsletter Signup'],method:'Use Tally webhooks for each submission.'},
    webflow:{name:'Webflow',icon:'W',signin:'Sign in with Webflow',forms:['Homepage Contact','Landing Page Lead','Demo Request'],method:'Use Webflow sites/forms and webhook forwarding.'},
    framer:{name:'Framer',icon:'F',signin:'Sign in with Framer',forms:['Framer Contact Form','Waitlist Form','Project Inquiry'],method:'Use custom actions, webhooks, or automation forwarding.'},
    wix:{name:'Wix',icon:'Wi',signin:'Sign in with Wix',forms:['Wix Contact Form','Booking Inquiry','Quote Form'],method:'Use Wix automations, Velo, or webhook forwarding.'},
    squarespace:{name:'Squarespace',icon:'Sq',signin:'Sign in with Squarespace',forms:['Squarespace Contact','Consultation Request','Event Inquiry'],method:'Use Zapier/Make or form storage forwarding.'},
    wordpress:{name:'WordPress / Elementor',icon:'WP',signin:'Sign in with WordPress',forms:['Contact Form 7 Lead','Elementor Intake','Gravity Form Lead'],method:'Use a form plugin webhook action or automation bridge.'},
    hubspot:{name:'HubSpot Forms',icon:'H',signin:'Sign in with HubSpot',forms:['HubSpot Contact Form','Lead Capture Form','Demo Request'],method:'Use HubSpot APIs, workflows, or webhook-style exports.'},
    mailchimp:{name:'Mailchimp Forms',icon:'Mc',signin:'Sign in with Mailchimp',forms:['Audience Signup','Interest Form','Campaign Lead Form'],method:'Use Mailchimp API or automation forwarding.'},
    airtable:{name:'Airtable Forms',icon:'A',signin:'Sign in with Airtable',forms:['Airtable Intake','Operations Request','Customer Lead Form'],method:'Use Airtable automations or API to forward submissions.'},
    zapier:{name:'Zapier',icon:'Z',signin:'Sign in with Zapier',forms:['Any Zapier Form Trigger','Google Form Zap','Typeform Zap'],method:'Use any form trigger, then POST to the CRM endpoint.'},
    make:{name:'Make',icon:'M',signin:'Sign in with Make',forms:['Any Make Form Scenario','Google Sheets Scenario','Webhook Scenario'],method:'Use a form module, then HTTP POST to the CRM endpoint.'},
    custom:{name:'Custom HTML Form',icon:'</>',signin:'Use Custom Website Form',forms:['Main Website Form','Quote Page Form','Support Contact Form'],method:'Use HTML form action or JavaScript fetch.'}
  };
  let selected = 'google';
  let connected = loadConnections();

  const css = document.createElement('style');
  css.textContent = `
    .cf-modal,.cf-provider-modal{position:fixed;inset:0;z-index:1500;display:none;place-items:center;background:rgba(2,18,14,.66);backdrop-filter:blur(10px);padding:20px}.cf-provider-modal{z-index:1600}.cf-modal.open,.cf-provider-modal.open{display:grid}.cf-box,.cf-provider-box{width:min(1160px,100%);max-height:92vh;overflow:auto;background:white;border:1px solid rgba(16,185,129,.2);border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.34)}.cf-provider-box{width:min(980px,100%)}.cf-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:radial-gradient(circle at 15% 0,rgba(16,185,129,.2),transparent 36%),linear-gradient(135deg,#f8fffc,#ecfdf5)}.cf-head h2{margin:0;color:#022c22}.cf-head p{margin:8px 0 0;color:#475569;line-height:1.5}.cf-body{display:grid;grid-template-columns:292px 1fr;gap:18px;padding:22px 24px}.cf-platforms{border:1px solid #dbe8e4;border-radius:16px;background:#f8fafc;padding:10px;display:grid;gap:7px;align-content:start}.cf-platforms button{border:1px solid transparent;background:transparent;border-radius:12px;padding:10px 11px;text-align:left;color:#073d32;font-weight:900;cursor:pointer;display:flex;gap:9px;align-items:center}.cf-platforms button.active,.cf-platforms button:hover{background:white;border-color:#10b981;box-shadow:0 8px 20px rgba(15,23,42,.05)}.cf-logo{width:28px;height:28px;border-radius:9px;background:#ecfdf5;color:#047857;display:grid;place-items:center;font-size:11px;font-weight:1000}.cf-main{display:grid;gap:14px}.cf-card{border:1px solid #dbe8e4;border-radius:16px;background:white;padding:15px;box-shadow:0 8px 22px rgba(15,23,42,.04)}.cf-card h3{margin:0 0 8px;color:#022c22}.cf-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.cf-field label{display:block;margin-bottom:6px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#047857;font-weight:950}.cf-field input,.cf-field select,.cf-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;color:#0f172a;padding:12px 13px;font:inherit}.cf-field textarea{min-height:95px;resize:vertical}.cf-wide{grid-column:1/-1}.cf-methods{display:grid;grid-template-columns:1fr 1fr;gap:12px}.cf-method{border:1px solid #dbe8e4;border-radius:16px;background:#f8fffc;padding:15px;display:grid;gap:10px}.cf-method strong{color:#022c22}.cf-method p{margin:0;color:#64748b;font-size:13px;line-height:1.45}.cf-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5}.cf-locked{border:1px solid rgba(245,158,11,.35);background:#fffbeb;color:#92400e;border-radius:14px;padding:13px 14px;font-weight:850;line-height:1.45}.cf-foot{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}.cf-btn{border:1px solid #dbe8e4;border-radius:13px;background:white;color:#073d32;min-height:45px;padding:0 14px;font-weight:900;cursor:pointer}.cf-primary{background:#10b981;border-color:#10b981;color:#022c22}.cf-dark{background:#052e24;border-color:#052e24;color:#d1fae5}.cf-muted{color:#64748b;font-size:12px;line-height:1.45}.cf-pill{display:inline-flex;border:1px solid rgba(16,185,129,.25);background:#ecfdf5;color:#047857;border-radius:999px;padding:6px 9px;font-size:11px;font-weight:950;margin:4px 6px 0 0}.cf-status{border:1px solid #dbe8e4;border-radius:14px;background:#f8fafc;padding:12px;color:#334155;font-size:13px;line-height:1.45}.cf-status.ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}.cf-provider-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:11px;padding:22px 24px}.cf-provider-card{border:1px solid #dbe8e4;border-radius:16px;background:#fff;padding:14px;display:grid;gap:10px;text-align:left;cursor:pointer;min-height:170px}.cf-provider-card:hover{border-color:#10b981;background:#f8fffc;transform:translateY(-1px)}.cf-provider-card.connected{border-color:rgba(16,185,129,.5);background:#ecfdf5}.cf-provider-card h3{margin:0;color:#022c22;font-size:15px}.cf-provider-card p{margin:0;color:#64748b;font-size:12px;line-height:1.4}.cf-provider-card .cf-btn{width:100%;justify-content:center}.cf-provider-top{display:flex;align-items:center;gap:10px}.cf-form-list{display:grid;gap:8px;margin-top:10px}.cf-form-row{border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;padding:9px 10px;display:flex;justify-content:space-between;gap:8px;align-items:center;color:#073d32;font-size:12px;font-weight:850}.cf-form-row button{min-height:32px;padding:0 9px;border-radius:9px}.cf-private-banner{margin:14px 24px 0}.cf-connection-table{width:100%;border-collapse:collapse;font-size:12px}.cf-connection-table th,.cf-connection-table td{border-bottom:1px solid #e5e7eb;text-align:left;padding:9px}.cf-connection-table th{color:#047857;text-transform:uppercase;letter-spacing:.08em;font-size:10px}@media(max-width:980px){.cf-provider-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:900px){.cf-body,.cf-grid,.cf-methods{grid-template-columns:1fr}.cf-wide{grid-column:auto}}@media(max-width:640px){.cf-provider-grid{grid-template-columns:1fr}}
  `;
  document.head.appendChild(css);

  const modal = document.createElement('div');
  modal.className = 'cf-modal';
  modal.innerHTML = `<div class="cf-box"><div class="cf-head"><h2>Connect Form Source</h2><p>Connect a third-party form account, choose a form, or download a site-specific webhook setup file.</p></div><div class="cf-body"><div class="cf-platforms" id="cfPlatforms"></div><div class="cf-main"><div class="cf-card"><div class="cf-grid"><div class="cf-field"><label>Site / client name</label><input id="cfSiteName" value="Constrava Demo Site"></div><div class="cf-field"><label>Form name</label><input id="cfName" value="Website Lead Capture"></div><div class="cf-field"><label>Default CRM status</label><select id="cfStatus"><option selected>New</option><option>Qualified</option><option>Needs Analysis</option><option>Proposal</option></select></div><div class="cf-field"><label>Assigned owner</label><input id="cfOwner" value="Constrava Demo Team"></div></div></div><div class="cf-card" id="cfConnection"></div><div class="cf-card" id="cfWebhook"></div><div class="cf-card"><h3>Connected providers</h3><div id="cfConnectedList" class="cf-muted">No providers connected yet.</div></div><div class="cf-card"><h3>Field mapping and test lead</h3><div class="cf-grid"><div class="cf-field"><label>Name field</label><input id="cfMapName" value="name"></div><div class="cf-field"><label>Email field</label><input id="cfMapEmail" value="email"></div><div class="cf-field"><label>Company field</label><input id="cfMapCompany" value="company"></div><div class="cf-field"><label>Message field</label><input id="cfMapMessage" value="message"></div><div class="cf-field"><label>Test lead name</label><input id="cfTestName" value="Third Party Form Lead"></div><div class="cf-field"><label>Test email</label><input id="cfTestEmail" value="form.lead@example.com"></div><div class="cf-field"><label>Test company</label><input id="cfTestCompany" value="Form Client Co"></div><div class="cf-field"><label>Estimated value</label><input id="cfTestValue" type="number" value="6800"></div><div class="cf-field cf-wide"><label>Test message</label><textarea id="cfTestMessage">This lead came from an external form integration test.</textarea></div></div></div></div></div><div class="cf-foot"><button id="cfClose" class="cf-btn" type="button">Close</button><div><button id="cfSignin" class="cf-btn cf-dark" type="button">Sign in with provider</button> <button id="cfDownload" class="cf-btn" type="button">Download webhook setup</button> <button id="cfCopy" class="cf-btn" type="button">Copy webhook</button> <button id="cfTest" class="cf-btn cf-primary" type="button">Send test lead</button></div></div></div>`;
  document.body.appendChild(modal);

  const providerModal = document.createElement('div');
  providerModal.className = 'cf-provider-modal';
  providerModal.innerHTML = `<div class="cf-provider-box"><div class="cf-head"><h2>Sign in with a form provider</h2><p>Choose a major online form provider. Private mode lets you connect providers and pick forms for testing. Public demo mode blocks sign-in.</p></div><div id="cfProviderLock"></div><div class="cf-provider-grid" id="cfProviderGrid"></div><div class="cf-foot"><button id="cfProviderClose" class="cf-btn" type="button">Back</button><button id="cfProviderDone" class="cf-btn cf-primary" type="button">Done</button></div></div>`;
  document.body.appendChild(providerModal);

  function clean(value, fallback){ return String(value||fallback||'item').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || fallback || 'item'; }
  function siteSlug(){ return clean(document.getElementById('cfSiteName')?.value, 'demo-site'); }
  function formSlug(){ return clean(document.getElementById('cfName')?.value, 'website-lead-capture'); }
  function siteKey(){ return clean(token, 'demo-token').slice(0,48); }
  function connectionId(key=selected){ return `${siteSlug()}-${formSlug()}-${platforms[key].name.toLowerCase().replace(/[^a-z0-9]+/g,'-')}`; }
  function webhookUrl(){ return `${baseUrl}/api/forms/intake/${siteSlug()}/${formSlug()}`; }
  function secret(){ return `cx_${siteSlug().replace(/-/g,'_')}_${formSlug().replace(/-/g,'_')}_${siteKey().replace(/-/g,'_')}`; }
  function platform(){ return platforms[selected]; }
  function toast(msg){ const t=document.getElementById('toast'); if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);} else alert(msg); }
  function dash(){ try{ if(typeof data !== 'undefined' && data) return data; }catch(e){} window.data=window.data||{leads:[]}; return window.data; }
  function saved(){ try{return JSON.parse(sessionStorage.getItem(STORE_KEY)||'[]');}catch(e){return[];} }
  function save(record){ const d=dash(); d.leads=Array.isArray(d.leads)?d.leads:[]; d.leads.unshift(record); const list=saved(); list.unshift(record); sessionStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0,80))); }
  function rerender(){ if(typeof renderCRM==='function') renderCRM('leads'); else if(window.renderCRM) window.renderCRM('leads'); }
  function loadConnections(){ try{return JSON.parse(sessionStorage.getItem(CONNECTION_KEY)||'{}');}catch(e){return{};} }
  function persistConnections(){ sessionStorage.setItem(CONNECTION_KEY, JSON.stringify(connected)); }

  function config(){
    return { product:'Constrava CRM', connection_id:connectionId(), site:{name:document.getElementById('cfSiteName')?.value||'Constrava Demo Site',slug:siteSlug(),dashboard_token:token}, form:{name:document.getElementById('cfName')?.value||'Website Lead Capture',slug:formSlug(),platform:platform().name}, webhook:{url:webhookUrl(),method:'POST',content_type:'application/json',header:'x-constrava-key',key:secret()}, crm_defaults:{status:document.getElementById('cfStatus')?.value||'New',owner:document.getElementById('cfOwner')?.value||'Constrava Demo Team',source:platform().name}, field_mapping:{name:document.getElementById('cfMapName')?.value||'name',email:document.getElementById('cfMapEmail')?.value||'email',company:document.getElementById('cfMapCompany')?.value||'company',message:document.getElementById('cfMapMessage')?.value||'message'}, connected_provider:connected[selected]||null, sample_payload:{name:'Taylor Reed',email:'taylor@example.com',phone:'610-555-0198',company:'Reed HVAC',message:'I need a quote for a custom dashboard.',source:platform().name} };
  }

  function platformButtons(){
    const wrap=document.getElementById('cfPlatforms');
    wrap.innerHTML = Object.entries(platforms).map(([k,p])=>`<button type="button" data-platform="${k}"><span class="cf-logo">${p.icon}</span><span>${p.name}${connected[k]?' ✓':''}</span></button>`).join('');
    wrap.querySelectorAll('[data-platform]').forEach(btn=>{ btn.classList.toggle('active',btn.dataset.platform===selected); btn.onclick=()=>{ selected=btn.dataset.platform; render(); }; });
  }
  function connectionBlock(){
    const p=platform(), ok=connected[selected];
    const forms = ok ? `<div class="cf-form-list">${(ok.forms||[]).map(f=>`<div class="cf-form-row"><span>${f}</span><button class="cf-btn cf-primary" type="button" data-use-form="${f}">Use form</button></div>`).join('')}</div>` : '';
    return `<h3>${p.name}</h3><p class="cf-muted">${p.method}</p><div class="cf-methods"><div class="cf-method"><strong>${p.signin}</strong><p>Opens a provider pop-up where you can connect any major online form platform and choose one of its forms. In private mode this fully works as a CRM-session test connection.</p><button id="cfInlineSignin" class="cf-btn cf-dark" type="button">Sign in with ${p.name}</button><div class="cf-status ${ok?'ok':''}">${ok?`Connected as ${ok.account}. Selected form: ${ok.selectedForm||'none yet'}`:'Not connected yet.'}</div>${forms}</div><div class="cf-method"><strong>Webhook fallback</strong><p>For clients who do not want account sign-in, download a site-specific webhook setup file with endpoint, key, headers, sample payload, and field mapping.</p><button id="cfInlineDownload" class="cf-btn" type="button">Download setup file</button><div class="cf-status">Connection ID: <b>${connectionId()}</b></div></div></div><br><span class="cf-pill">Sign-in provider</span><span class="cf-pill">Choose forms</span><span class="cf-pill">Webhook fallback</span><span class="cf-pill">Private-site only</span>`;
  }
  function webhookBlock(){
    if(!isPrivate){ return `<h3>Private webhook details</h3><div class="cf-locked"><b>Blocked on public demo.</b><br>Provider sign-in, webhook URLs, secret keys, code snippets, and downloads are disabled here. Open the private site to test the form connection system.</div>`; }
    const c=config(), sample=JSON.stringify(c.sample_payload,null,2);
    return `<h3>Site-specific webhook</h3><p class="cf-muted">This webhook is specific to <b>${c.site.name}</b>, <b>${c.form.name}</b>, and the selected provider <b>${c.form.platform}</b>.</p><div class="cf-grid"><div class="cf-field cf-wide"><label>Webhook URL</label><div class="cf-code">${c.webhook.url}</div></div><div class="cf-field cf-wide"><label>Private key header</label><div class="cf-code">${c.webhook.header}: ${c.webhook.key}</div></div><div class="cf-field cf-wide"><label>Sample payload</label><div class="cf-code">${sample}</div></div><div class="cf-field cf-wide"><label>Example fetch code</label><div class="cf-code">fetch('${c.webhook.url}', {\n  method: 'POST',\n  headers: {\n    'Content-Type': 'application/json',\n    '${c.webhook.header}': '${c.webhook.key}'\n  },\n  body: JSON.stringify(${sample.replace(/\n/g,'\n  ')})\n});</div></div></div>`;
  }
  function connectedList(){
    const entries=Object.entries(connected);
    if(!entries.length) return 'No providers connected yet.';
    return `<table class="cf-connection-table"><tr><th>Provider</th><th>Account</th><th>Selected form</th><th>Status</th></tr>${entries.map(([k,c])=>`<tr><td>${platforms[k].name}</td><td>${c.account}</td><td>${c.selectedForm||'—'}</td><td>Connected</td></tr>`).join('')}</table>`;
  }
  function render(){
    platformButtons();
    document.getElementById('cfConnection').innerHTML=connectionBlock();
    document.getElementById('cfWebhook').innerHTML=webhookBlock();
    document.getElementById('cfConnectedList').innerHTML=connectedList();
    document.getElementById('cfSignin').textContent='Sign in with ' + platform().name;
    const inlineSignin=document.getElementById('cfInlineSignin'); if(inlineSignin) inlineSignin.onclick=openProviderPopup;
    const inlineDownload=document.getElementById('cfInlineDownload'); if(inlineDownload) inlineDownload.onclick=downloadSetup;
    document.querySelectorAll('[data-use-form]').forEach(btn=>btn.onclick=()=>{ document.getElementById('cfName').value=btn.getAttribute('data-use-form'); connected[selected].selectedForm=btn.getAttribute('data-use-form'); persistConnections(); toast('Selected '+btn.getAttribute('data-use-form')); render(); });
  }

  function renderProviderPopup(){
    const lock=document.getElementById('cfProviderLock');
    lock.innerHTML = isPrivate ? '' : `<div class="cf-private-banner"><div class="cf-locked"><b>Sign-in blocked on public demo.</b><br>This screen shows supported providers, but real/testing connections only work on the private site.</div></div>`;
    const grid=document.getElementById('cfProviderGrid');
    grid.innerHTML = Object.entries(platforms).map(([k,p])=>{
      const ok=connected[k];
      const formRows = ok ? `<div class="cf-form-list">${p.forms.map(f=>`<div class="cf-form-row"><span>${f}</span><button class="cf-btn cf-primary" type="button" data-provider-form="${k}|${f}">Use</button></div>`).join('')}</div>` : '';
      return `<div class="cf-provider-card ${ok?'connected':''}"><div class="cf-provider-top"><span class="cf-logo">${p.icon}</span><h3>${p.name}</h3></div><p>${p.method}</p><button class="cf-btn ${ok?'':'cf-dark'}" type="button" data-provider-signin="${k}">${ok?'Reconnect':'Sign in with '+p.name}</button><div class="cf-status ${ok?'ok':''}">${ok?'Connected as '+ok.account:'Not connected'}</div>${formRows}</div>`;
    }).join('');
    grid.querySelectorAll('[data-provider-signin]').forEach(btn=>btn.onclick=()=>signIn(btn.getAttribute('data-provider-signin')));
    grid.querySelectorAll('[data-provider-form]').forEach(btn=>btn.onclick=()=>{ const [k,f]=btn.getAttribute('data-provider-form').split('|'); selected=k; connected[k]=connected[k]||providerConnection(k); connected[k].selectedForm=f; document.getElementById('cfName').value=f; persistConnections(); toast('Using '+f+' from '+platforms[k].name); closeProviderPopup(); render(); });
  }
  function openProviderPopup(){ if(!isPrivate){ providerModal.classList.add('open'); renderProviderPopup(); return; } providerModal.classList.add('open'); renderProviderPopup(); }
  function closeProviderPopup(){ providerModal.classList.remove('open'); }
  function providerConnection(key){ return { provider:key, account:`demo-user@${clean(platforms[key].name,'provider')}.example`, connected_at:new Date().toISOString(), forms:platforms[key].forms.slice(), selectedForm:platforms[key].forms[0], mode:'private-session-test' }; }
  function signIn(key=selected){
    if(!isPrivate){ toast('Provider sign-in is blocked on the public demo.'); renderProviderPopup(); return; }
    selected=key;
    connected[key]=providerConnection(key);
    document.getElementById('cfName').value=connected[key].selectedForm;
    persistConnections();
    toast(platforms[key].name+' connected.');
    renderProviderPopup();
    render();
  }
  function open(){ modal.classList.add('open'); render(); }
  function close(){ modal.classList.remove('open'); }
  function copy(){ if(!isPrivate){ toast('Webhook details are only available on the private site.'); return; } navigator.clipboard?.writeText(webhookUrl()).then(()=>toast('Webhook URL copied.')).catch(()=>toast(webhookUrl())); }
  function downloadSetup(){
    if(!isPrivate){ toast('Webhook setup download is only available on the private site.'); return; }
    const c=config(), text=JSON.stringify(c,null,2), blob=new Blob([text],{type:'application/json'}), a=document.createElement('a');
    a.href=URL.createObjectURL(blob); a.download=`constrava-webhook-${c.site.slug}-${c.form.slug}-${selected}.json`; document.body.appendChild(a); a.click(); setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500); toast('Webhook setup file downloaded.');
  }
  function sendTest(){
    if(!isPrivate){ toast('Testing form connections is blocked on the public demo.'); return; }
    const value=Number(document.getElementById('cfTestValue').value||0), conn=connected[selected];
    const record={lead_id:'FORM-'+Math.floor(100000+Math.random()*900000),record_type:'third_party_form_lead',module:'leads',name:document.getElementById('cfTestName').value,email:document.getElementById('cfTestEmail').value,company:document.getElementById('cfTestCompany').value,title:'External Form Lead',source:platform().name,owner:document.getElementById('cfOwner').value,status:document.getElementById('cfStatus').value,priority:'High',deal_name:'External form intake - '+platform().name,value,probability:35,expected_revenue:Math.round(value*.35),close_date:new Date().toISOString().slice(0,10),created_at:new Date().toISOString().slice(0,10),last_contacted:new Date().toISOString().slice(0,10),tags:['third-party-form',selected,'intake','private-test'],notes:document.getElementById('cfTestMessage').value+' Provider: '+platform().name+'. Form: '+((conn&&conn.selectedForm)||document.getElementById('cfName').value)+'. Connection ID: '+connectionId()};
    save(record); close(); rerender(); toast('Test '+platform().name+' lead added to CRM.');
  }

  document.getElementById('cfClose').onclick=close;
  document.getElementById('cfSignin').onclick=openProviderPopup;
  document.getElementById('cfDownload').onclick=downloadSetup;
  document.getElementById('cfCopy').onclick=copy;
  document.getElementById('cfTest').onclick=sendTest;
  document.getElementById('cfProviderClose').onclick=closeProviderPopup;
  document.getElementById('cfProviderDone').onclick=closeProviderPopup;
  modal.onclick=e=>{ if(e.target===modal) close(); };
  providerModal.onclick=e=>{ if(e.target===providerModal) closeProviderPopup(); };
  document.addEventListener('click',function(e){ const btn=e.target.closest('[data-cx-flow="website"]'); if(!btn)return; e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); open(); },true);
})();
