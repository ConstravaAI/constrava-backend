(function(){
  if(window.__constravaThirdPartyFormsLoaded) return;
  window.__constravaThirdPartyFormsLoaded = true;

  const params = new URLSearchParams(window.location.search);
  const isPrivate = params.get('mode') === 'private' || window.location.pathname.startsWith('/app') || window.top !== window.self;
  const STORE_KEY = 'constravaCrmDemoAdds';
  const baseUrl = window.location.origin || 'https://constrava-backend.onrender.com';
  const token = params.get('token') || 'demo';
  const platforms = {
    google: {name:'Google Forms', icon:'G', signin:'Sign in with Google', method:'Google Forms usually connects through the linked response Sheet, Apps Script, Zapier, or Make.'},
    typeform: {name:'Typeform', icon:'T', signin:'Sign in with Typeform', method:'Use Typeform webhooks or OAuth/API access.'},
    jotform: {name:'Jotform', icon:'J', signin:'Sign in with Jotform', method:'Use Jotform webhooks/API keys to forward submissions.'},
    tally: {name:'Tally', icon:'Ta', signin:'Sign in with Tally', method:'Use Tally webhooks to send each response to the CRM.'},
    webflow: {name:'Webflow', icon:'W', signin:'Sign in with Webflow', method:'Use Webflow forms, site API access, or a webhook bridge.'},
    framer: {name:'Framer', icon:'F', signin:'Connect Framer site', method:'Use a custom action, webhook bridge, or form forwarding.'},
    wix: {name:'Wix', icon:'Wi', signin:'Connect Wix site', method:'Use Wix automations, Velo, or webhook forwarding.'},
    squarespace: {name:'Squarespace', icon:'Sq', signin:'Connect Squarespace', method:'Use Zapier/Make or form storage forwarding.'},
    wordpress: {name:'WordPress / Elementor', icon:'WP', signin:'Connect WordPress', method:'Use a form plugin webhook action or automation bridge.'},
    zapier: {name:'Zapier', icon:'Z', signin:'Connect with Zapier', method:'Use any form trigger, then POST to the CRM endpoint.'},
    make: {name:'Make', icon:'M', signin:'Connect with Make', method:'Use a form module, then HTTP POST to the CRM endpoint.'},
    custom: {name:'Custom HTML Form', icon:'</>', signin:'Use custom code', method:'Use an HTML form action or JavaScript fetch request.'}
  };
  let selected = 'google';
  let connected = {};

  const css = document.createElement('style');
  css.textContent = `
    .cf-modal{position:fixed;inset:0;z-index:1500;display:none;place-items:center;background:rgba(2,18,14,.66);backdrop-filter:blur(10px);padding:20px}.cf-modal.open{display:grid}.cf-box{width:min(1160px,100%);max-height:92vh;overflow:auto;background:white;border:1px solid rgba(16,185,129,.2);border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.34)}.cf-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:radial-gradient(circle at 15% 0,rgba(16,185,129,.2),transparent 36%),linear-gradient(135deg,#f8fffc,#ecfdf5)}.cf-head h2{margin:0;color:#022c22}.cf-head p{margin:8px 0 0;color:#475569;line-height:1.5}.cf-body{display:grid;grid-template-columns:292px 1fr;gap:18px;padding:22px 24px}.cf-platforms{border:1px solid #dbe8e4;border-radius:16px;background:#f8fafc;padding:10px;display:grid;gap:7px;align-content:start}.cf-platforms button{border:1px solid transparent;background:transparent;border-radius:12px;padding:10px 11px;text-align:left;color:#073d32;font-weight:900;cursor:pointer;display:flex;gap:9px;align-items:center}.cf-platforms button.active,.cf-platforms button:hover{background:white;border-color:#10b981;box-shadow:0 8px 20px rgba(15,23,42,.05)}.cf-logo{width:28px;height:28px;border-radius:9px;background:#ecfdf5;color:#047857;display:grid;place-items:center;font-size:11px;font-weight:1000}.cf-main{display:grid;gap:14px}.cf-card{border:1px solid #dbe8e4;border-radius:16px;background:white;padding:15px;box-shadow:0 8px 22px rgba(15,23,42,.04)}.cf-card h3{margin:0 0 8px;color:#022c22}.cf-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.cf-field label{display:block;margin-bottom:6px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#047857;font-weight:950}.cf-field input,.cf-field select,.cf-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;color:#0f172a;padding:12px 13px;font:inherit}.cf-field textarea{min-height:95px;resize:vertical}.cf-wide{grid-column:1/-1}.cf-methods{display:grid;grid-template-columns:1fr 1fr;gap:12px}.cf-method{border:1px solid #dbe8e4;border-radius:16px;background:#f8fffc;padding:15px;display:grid;gap:10px}.cf-method strong{color:#022c22}.cf-method p{margin:0;color:#64748b;font-size:13px;line-height:1.45}.cf-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5}.cf-locked{border:1px solid rgba(245,158,11,.35);background:#fffbeb;color:#92400e;border-radius:14px;padding:13px 14px;font-weight:850;line-height:1.45}.cf-steps{margin:0;padding-left:19px;color:#334155;line-height:1.55}.cf-foot{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}.cf-btn{border:1px solid #dbe8e4;border-radius:13px;background:white;color:#073d32;min-height:45px;padding:0 14px;font-weight:900;cursor:pointer}.cf-primary{background:#10b981;border-color:#10b981;color:#022c22}.cf-dark{background:#052e24;border-color:#052e24;color:#d1fae5}.cf-muted{color:#64748b;font-size:12px;line-height:1.45}.cf-pill{display:inline-flex;border:1px solid rgba(16,185,129,.25);background:#ecfdf5;color:#047857;border-radius:999px;padding:6px 9px;font-size:11px;font-weight:950;margin:4px 6px 0 0}.cf-status{border:1px solid #dbe8e4;border-radius:14px;background:#f8fafc;padding:12px;color:#334155;font-size:13px;line-height:1.45}.cf-status.ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}@media(max-width:900px){.cf-body,.cf-grid,.cf-methods{grid-template-columns:1fr}.cf-wide{grid-column:auto}}
  `;
  document.head.appendChild(css);

  const modal = document.createElement('div');
  modal.className = 'cf-modal';
  modal.innerHTML = `<div class="cf-box"><div class="cf-head"><h2>Connect Form Source</h2><p>Connect a third-party account, or download a site-specific webhook setup file for a client website/form.</p></div><div class="cf-body"><div class="cf-platforms" id="cfPlatforms"></div><div class="cf-main"><div class="cf-card"><div class="cf-grid"><div class="cf-field"><label>Site / client name</label><input id="cfSiteName" value="Constrava Demo Site"></div><div class="cf-field"><label>Form name</label><input id="cfName" value="Website Lead Capture"></div><div class="cf-field"><label>Default CRM status</label><select id="cfStatus"><option selected>New</option><option>Qualified</option><option>Needs Analysis</option><option>Proposal</option></select></div><div class="cf-field"><label>Assigned owner</label><input id="cfOwner" value="Constrava Demo Team"></div></div></div><div class="cf-card" id="cfConnection"></div><div class="cf-card" id="cfWebhook"></div><div class="cf-card"><h3>Field mapping preview</h3><div class="cf-grid"><div class="cf-field"><label>Name field</label><input id="cfMapName" value="name"></div><div class="cf-field"><label>Email field</label><input id="cfMapEmail" value="email"></div><div class="cf-field"><label>Company field</label><input id="cfMapCompany" value="company"></div><div class="cf-field"><label>Message field</label><input id="cfMapMessage" value="message"></div><div class="cf-field"><label>Test lead name</label><input id="cfTestName" value="Third Party Form Lead"></div><div class="cf-field"><label>Test email</label><input id="cfTestEmail" value="form.lead@example.com"></div><div class="cf-field"><label>Test company</label><input id="cfTestCompany" value="Form Client Co"></div><div class="cf-field"><label>Estimated value</label><input id="cfTestValue" type="number" value="6800"></div><div class="cf-field cf-wide"><label>Test message</label><textarea id="cfTestMessage">This lead came from an external form integration test.</textarea></div></div></div></div></div><div class="cf-foot"><button id="cfClose" class="cf-btn" type="button">Close</button><div><button id="cfSignin" class="cf-btn cf-dark" type="button">Sign in</button> <button id="cfDownload" class="cf-btn" type="button">Download webhook setup</button> <button id="cfCopy" class="cf-btn" type="button">Copy webhook</button> <button id="cfTest" class="cf-btn cf-primary" type="button">Send test lead</button></div></div></div>`;
  document.body.appendChild(modal);

  function clean(value, fallback){ return String(value||fallback||'item').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || fallback || 'item'; }
  function siteSlug(){ return clean(document.getElementById('cfSiteName')?.value, 'demo-site'); }
  function formSlug(){ return clean(document.getElementById('cfName')?.value, 'website-lead-capture'); }
  function siteKey(){ return clean(token, 'demo-token').slice(0,48); }
  function connectionId(){ return `${siteSlug()}-${formSlug()}-${platforms[selected].name.toLowerCase().replace(/[^a-z0-9]+/g,'-')}`; }
  function webhookUrl(){ return `${baseUrl}/api/forms/intake/${siteSlug()}/${formSlug()}`; }
  function secret(){ return `cx_${siteSlug().replace(/-/g,'_')}_${formSlug().replace(/-/g,'_')}_${siteKey().replace(/-/g,'_')}`; }
  function platform(){ return platforms[selected]; }
  function toast(msg){ const t=document.getElementById('toast'); if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);} else alert(msg); }
  function dash(){ try{ if(typeof data !== 'undefined' && data) return data; }catch(e){} window.data=window.data||{leads:[]}; return window.data; }
  function saved(){ try{return JSON.parse(sessionStorage.getItem(STORE_KEY)||'[]');}catch(e){return[];} }
  function save(record){ const d=dash(); d.leads=Array.isArray(d.leads)?d.leads:[]; d.leads.unshift(record); const list=saved(); list.unshift(record); sessionStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0,80))); }
  function rerender(){ if(typeof renderCRM==='function') renderCRM('leads'); else if(window.renderCRM) window.renderCRM('leads'); }

  function config(){
    return {
      product: 'Constrava CRM',
      connection_id: connectionId(),
      site: { name: document.getElementById('cfSiteName')?.value || 'Constrava Demo Site', slug: siteSlug(), dashboard_token: token },
      form: { name: document.getElementById('cfName')?.value || 'Website Lead Capture', slug: formSlug(), platform: platform().name },
      webhook: { url: webhookUrl(), method: 'POST', content_type: 'application/json', header: 'x-constrava-key', key: secret() },
      crm_defaults: { status: document.getElementById('cfStatus')?.value || 'New', owner: document.getElementById('cfOwner')?.value || 'Constrava Demo Team', source: platform().name },
      field_mapping: { name: document.getElementById('cfMapName')?.value || 'name', email: document.getElementById('cfMapEmail')?.value || 'email', company: document.getElementById('cfMapCompany')?.value || 'company', message: document.getElementById('cfMapMessage')?.value || 'message' },
      sample_payload: { name: 'Taylor Reed', email: 'taylor@example.com', phone: '610-555-0198', company: 'Reed HVAC', message: 'I need a quote for a custom dashboard.', source: platform().name }
    };
  }

  function platformButtons(){
    const wrap=document.getElementById('cfPlatforms');
    wrap.innerHTML = Object.entries(platforms).map(([k,p])=>`<button type="button" data-platform="${k}"><span class="cf-logo">${p.icon}</span><span>${p.name}</span></button>`).join('');
    wrap.querySelectorAll('[data-platform]').forEach(btn=>{ btn.classList.toggle('active',btn.dataset.platform===selected); btn.onclick=()=>{ selected=btn.dataset.platform; render(); }; });
  }
  function connectionBlock(){
    const p = platform();
    const ok = connected[selected];
    return `<h3>${p.name}</h3><p class="cf-muted">${p.method}</p><div class="cf-methods"><div class="cf-method"><strong>${p.signin}</strong><p>Best UX. The client authorizes their account, chooses a form, maps fields, and turns on sync. This demo simulates that connection state.</p><button id="cfInlineSignin" class="cf-btn cf-dark" type="button">${ok?'Reconnect':'Start connection'}</button><div class="cf-status ${ok?'ok':''}">${ok?'Connected in demo mode. A production version would store OAuth/API credentials securely on the server.':'Not connected yet.'}</div></div><div class="cf-method"><strong>Webhook setup file</strong><p>For clients who do not want to sign in, download a site-specific webhook config that includes endpoint, key, headers, sample payload, and field mapping.</p><button id="cfInlineDownload" class="cf-btn" type="button">Download setup file</button><div class="cf-status">Connection ID: <b>${connectionId()}</b></div></div></div><br><span class="cf-pill">Account connection</span><span class="cf-pill">Webhook fallback</span><span class="cf-pill">Field mapping</span><span class="cf-pill">Test lead</span>`;
  }
  function webhookBlock(){
    if(!isPrivate){
      return `<h3>Private webhook details</h3><div class="cf-locked"><b>Locked on public demo.</b><br>Platform choices and sign-in flow are visible here, but the actual webhook URL, secret key, code snippet, and downloadable setup file are only available in the private site.</div>`;
    }
    const c = config();
    const sample = JSON.stringify(c.sample_payload, null, 2);
    return `<h3>Site-specific webhook</h3><p class="cf-muted">This webhook is specific to <b>${c.site.name}</b> and the <b>${c.form.name}</b> form.</p><div class="cf-grid"><div class="cf-field cf-wide"><label>Webhook URL</label><div class="cf-code">${c.webhook.url}</div></div><div class="cf-field cf-wide"><label>Private key header</label><div class="cf-code">${c.webhook.header}: ${c.webhook.key}</div></div><div class="cf-field cf-wide"><label>Sample payload</label><div class="cf-code">${sample}</div></div><div class="cf-field cf-wide"><label>Example fetch code</label><div class="cf-code">fetch('${c.webhook.url}', {\n  method: 'POST',\n  headers: {\n    'Content-Type': 'application/json',\n    '${c.webhook.header}': '${c.webhook.key}'\n  },\n  body: JSON.stringify(${sample.replace(/\n/g,'\n  ')})\n});</div></div></div>`;
  }
  function render(){
    platformButtons();
    document.getElementById('cfConnection').innerHTML = connectionBlock();
    document.getElementById('cfWebhook').innerHTML = webhookBlock();
    document.getElementById('cfSignin').textContent = platform().signin;
    const inlineSignin=document.getElementById('cfInlineSignin'); if(inlineSignin) inlineSignin.onclick=signIn;
    const inlineDownload=document.getElementById('cfInlineDownload'); if(inlineDownload) inlineDownload.onclick=downloadSetup;
  }
  function open(){ modal.classList.add('open'); render(); }
  function close(){ modal.classList.remove('open'); }
  function signIn(){
    connected[selected] = true;
    toast(platform().name + ' connected in demo mode.');
    render();
  }
  function copy(){
    if(!isPrivate){ toast('Webhook details are only available on the private site.'); return; }
    navigator.clipboard?.writeText(webhookUrl()).then(()=>toast('Webhook URL copied.')).catch(()=>toast(webhookUrl()));
  }
  function downloadSetup(){
    if(!isPrivate){ toast('Webhook setup download is only available on the private site.'); return; }
    const c = config();
    const text = JSON.stringify(c, null, 2);
    const blob = new Blob([text], {type:'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `constrava-webhook-${c.site.slug}-${c.form.slug}.json`;
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast('Webhook setup file downloaded.');
  }
  function sendTest(){
    const value = Number(document.getElementById('cfTestValue').value||0);
    const record = { lead_id:'FORM-'+Math.floor(100000+Math.random()*900000), record_type:'third_party_form_lead', module:'leads', name:document.getElementById('cfTestName').value, email:document.getElementById('cfTestEmail').value, company:document.getElementById('cfTestCompany').value, title:'External Form Lead', source:platform().name, owner:document.getElementById('cfOwner').value, status:document.getElementById('cfStatus').value, priority:'High', deal_name:'External form intake - '+platform().name, value, probability:35, expected_revenue:Math.round(value*.35), close_date:new Date().toISOString().slice(0,10), created_at:new Date().toISOString().slice(0,10), last_contacted:new Date().toISOString().slice(0,10), tags:['third-party-form', selected, 'intake', isPrivate?'private-config':'public-demo'], notes:document.getElementById('cfTestMessage').value + ' Connection ID: ' + connectionId() };
    save(record); close(); rerender(); toast('Test '+platform().name+' lead added to CRM.');
  }

  document.getElementById('cfClose').onclick=close;
  document.getElementById('cfSignin').onclick=signIn;
  document.getElementById('cfDownload').onclick=downloadSetup;
  document.getElementById('cfCopy').onclick=copy;
  document.getElementById('cfTest').onclick=sendTest;
  modal.onclick=e=>{ if(e.target===modal) close(); };

  document.addEventListener('click', function(e){
    const btn = e.target.closest('[data-cx-flow="website"]');
    if(!btn) return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    open();
  }, true);
})();
