(function(){
  if(window.__constravaThirdPartyFormsLoaded) return;
  window.__constravaThirdPartyFormsLoaded = true;

  const params = new URLSearchParams(window.location.search);
  const isPrivate = params.get('mode') === 'private' || window.location.pathname.startsWith('/app');
  const STORE_KEY = 'constravaCrmDemoAdds';
  const baseUrl = window.location.origin || 'https://constrava-backend.onrender.com';
  const platforms = {
    google: ['Google Forms','Google Forms does not directly support normal webhooks. Use Google Sheets responses + Apps Script, Zapier, or Make to forward submissions.'],
    typeform: ['Typeform','Paste the Constrava webhook URL into Typeform webhooks.'],
    tally: ['Tally','Use Tally webhooks to send each submission to Constrava.'],
    jotform: ['Jotform','Use Jotform webhooks/integrations to post submissions to Constrava.'],
    webflow: ['Webflow','Use Webflow form notification/webhook tools or an automation bridge.'],
    framer: ['Framer','Send form submissions through a custom action, webhook, or automation tool.'],
    wix: ['Wix','Connect the form with Velo, automations, or webhook forwarding.'],
    squarespace: ['Squarespace','Forward form storage/submissions through Zapier or Make.'],
    wordpress: ['WordPress / Elementor','Use a form plugin webhook action or Zapier/Make connector.'],
    zapier: ['Zapier','Use any form trigger, then POST the submission to Constrava.'],
    make: ['Make','Use any form module, then send an HTTP POST to Constrava.'],
    custom: ['Custom HTML Form','Point your form action or JavaScript fetch request to the Constrava endpoint.']
  };

  const css = document.createElement('style');
  css.textContent = `
    .cf-modal{position:fixed;inset:0;z-index:1500;display:none;place-items:center;background:rgba(2,18,14,.66);backdrop-filter:blur(10px);padding:20px}.cf-modal.open{display:grid}.cf-box{width:min(1080px,100%);max-height:92vh;overflow:auto;background:white;border:1px solid rgba(16,185,129,.2);border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.34)}.cf-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:radial-gradient(circle at 15% 0,rgba(16,185,129,.2),transparent 36%),linear-gradient(135deg,#f8fffc,#ecfdf5)}.cf-head h2{margin:0;color:#022c22}.cf-head p{margin:8px 0 0;color:#475569;line-height:1.5}.cf-body{display:grid;grid-template-columns:280px 1fr;gap:18px;padding:22px 24px}.cf-platforms{border:1px solid #dbe8e4;border-radius:16px;background:#f8fafc;padding:10px;display:grid;gap:7px;align-content:start}.cf-platforms button{border:1px solid transparent;background:transparent;border-radius:12px;padding:10px 11px;text-align:left;color:#073d32;font-weight:900;cursor:pointer}.cf-platforms button.active,.cf-platforms button:hover{background:white;border-color:#10b981;box-shadow:0 8px 20px rgba(15,23,42,.05)}.cf-main{display:grid;gap:14px}.cf-card{border:1px solid #dbe8e4;border-radius:16px;background:white;padding:15px;box-shadow:0 8px 22px rgba(15,23,42,.04)}.cf-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.cf-field label{display:block;margin-bottom:6px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#047857;font-weight:950}.cf-field input,.cf-field select,.cf-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;color:#0f172a;padding:12px 13px;font:inherit}.cf-field textarea{min-height:110px;resize:vertical}.cf-wide{grid-column:1/-1}.cf-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5}.cf-locked{border:1px solid rgba(245,158,11,.35);background:#fffbeb;color:#92400e;border-radius:14px;padding:13px 14px;font-weight:850;line-height:1.45}.cf-steps{margin:0;padding-left:19px;color:#334155;line-height:1.55}.cf-foot{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}.cf-btn{border:1px solid #dbe8e4;border-radius:13px;background:white;color:#073d32;min-height:45px;padding:0 14px;font-weight:900;cursor:pointer}.cf-primary{background:#10b981;border-color:#10b981;color:#022c22}.cf-muted{color:#64748b;font-size:12px;line-height:1.45}.cf-pill{display:inline-flex;border:1px solid rgba(16,185,129,.25);background:#ecfdf5;color:#047857;border-radius:999px;padding:6px 9px;font-size:11px;font-weight:950;margin:4px 6px 0 0}@media(max-width:850px){.cf-body,.cf-grid{grid-template-columns:1fr}.cf-wide{grid-column:auto}}
  `;
  document.head.appendChild(css);

  const modal = document.createElement('div');
  modal.className = 'cf-modal';
  modal.innerHTML = `<div class="cf-box"><div class="cf-head"><h2>Third-Party Form Intake</h2><p>Connect forms from Google Forms, Typeform, Tally, Jotform, Webflow, Framer, Wix, Squarespace, WordPress, Zapier, Make, or a custom website.</p></div><div class="cf-body"><div class="cf-platforms" id="cfPlatforms"></div><div class="cf-main"><div class="cf-card"><div class="cf-grid"><div class="cf-field"><label>Connection name</label><input id="cfName" value="Website Lead Capture"></div><div class="cf-field"><label>Lead status</label><select id="cfStatus"><option selected>New</option><option>Qualified</option><option>Needs Analysis</option><option>Proposal</option></select></div><div class="cf-field"><label>Assigned owner</label><input id="cfOwner" value="Constrava Demo Team"></div><div class="cf-field"><label>Default source</label><input id="cfSource" value="Third-Party Form"></div></div></div><div class="cf-card" id="cfInstructions"></div><div class="cf-card" id="cfWebhook"></div><div class="cf-card"><div class="cf-grid"><div class="cf-field"><label>Test name</label><input id="cfTestName" value="Third Party Form Lead"></div><div class="cf-field"><label>Test email</label><input id="cfTestEmail" value="form.lead@example.com"></div><div class="cf-field"><label>Test company</label><input id="cfTestCompany" value="Form Client Co"></div><div class="cf-field"><label>Estimated value</label><input id="cfTestValue" type="number" value="6800"></div><div class="cf-field cf-wide"><label>Test message</label><textarea id="cfTestMessage">This lead came from an external form integration test.</textarea></div></div></div></div></div><div class="cf-foot"><button id="cfClose" class="cf-btn" type="button">Close</button><div><button id="cfCopy" class="cf-btn" type="button">Copy private webhook</button> <button id="cfTest" class="cf-btn cf-primary" type="button">Send test lead to CRM</button></div></div></div>`;
  document.body.appendChild(modal);

  let selected = 'google';
  function formId(){ return (document.getElementById('cfName')?.value || 'website-lead-capture').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || 'website-lead-capture'; }
  function webhookUrl(){ return `${baseUrl}/api/forms/intake/${formId()}`; }
  function secret(){ return 'cx_private_' + formId().replace(/-/g,'_') + '_key'; }
  function toast(msg){ const t=document.getElementById('toast'); if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);} else alert(msg); }
  function dash(){ try{ if(typeof data !== 'undefined' && data) return data; }catch(e){} window.data=window.data||{leads:[]}; return window.data; }
  function saved(){ try{return JSON.parse(sessionStorage.getItem(STORE_KEY)||'[]');}catch(e){return[];} }
  function save(record){ const d=dash(); d.leads=Array.isArray(d.leads)?d.leads:[]; d.leads.unshift(record); const list=saved(); list.unshift(record); sessionStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0,80))); }
  function rerender(){ if(typeof renderCRM==='function') renderCRM('leads'); else if(window.renderCRM) window.renderCRM('leads'); }
  function platformButtons(){ const wrap=document.getElementById('cfPlatforms'); wrap.innerHTML = Object.entries(platforms).map(([k,v])=>`<button type="button" data-platform="${k}">${v[0]}</button>`).join(''); wrap.querySelectorAll('[data-platform]').forEach(btn=>{ btn.classList.toggle('active',btn.dataset.platform===selected); btn.onclick=()=>{ selected=btn.dataset.platform; render(); }; }); }
  function instructions(){
    const [name,desc]=platforms[selected];
    const common = `<p><b>${name}</b></p><p class="cf-muted">${desc}</p><span class="cf-pill">Creates CRM lead</span><span class="cf-pill">Field mapping</span><span class="cf-pill">Test submission</span>`;
    const steps = {
      google:['Open the Google Form responses spreadsheet.','Use Extensions → Apps Script, or connect the response sheet through Zapier/Make.','Send each response to the Constrava webhook URL.','Map name, email, company, message, and source fields.'],
      typeform:['Open Typeform → Connect → Webhooks.','Add the Constrava webhook URL.','Set the method to POST and send the full response payload.','Submit a test response and verify it appears in CRM.'],
      tally:['Open the form settings in Tally.','Go to Integrations or Webhooks.','Paste the Constrava webhook URL.','Send a test submission.'],
      jotform:['Open Jotform form settings.','Go to Integrations or Webhooks.','Paste the Constrava webhook URL.','Submit a test lead.'],
      webflow:['Open the Webflow project form settings.','Use webhook forwarding or an automation bridge.','POST the form payload to Constrava.','Map Webflow field names to CRM fields.'],
      framer:['Open the form action/settings.','Forward submissions through a webhook or automation tool.','POST name, email, company, and message to Constrava.'],
      wix:['Use Wix Automations or Velo.','Create an action that sends the form submission to the webhook URL.','Map fields to CRM lead properties.'],
      squarespace:['Connect form storage to Zapier or Make.','Use a new submission trigger.','Send an HTTP POST to Constrava.'],
      wordpress:['Open your form plugin settings.','Use a webhook action after submit.','Paste the Constrava webhook URL and field mapping.'],
      zapier:['Choose your form app as the trigger.','Add Webhooks by Zapier as the action.','POST JSON to the Constrava webhook URL.'],
      make:['Choose your form module as the trigger.','Add an HTTP request module.','POST JSON to the Constrava webhook URL.'],
      custom:['Set your HTML form action to the endpoint, or use fetch().','Send name, email, company, phone, message, and source.','Handle the JSON response and show a thank-you message.']
    };
    return `${common}<ol class="cf-steps">${(steps[selected]||steps.custom).map(s=>`<li>${s}</li>`).join('')}</ol>`;
  }
  function webhookBlock(){
    const payload = `{
  "name": "Taylor Reed",
  "email": "taylor@example.com",
  "phone": "610-555-0198",
  "company": "Reed HVAC",
  "message": "I need a quote for a custom dashboard.",
  "source": "${platforms[selected][0]}"
}`;
    if(!isPrivate){
      return `<div class="cf-locked"><b>Private setup locked.</b><br>The public demo shows the connection options, but the actual webhook URL, private key, and code snippet are only shown inside the private site.</div>`;
    }
    return `<div class="cf-field cf-wide"><label>Private webhook URL</label><div class="cf-code">${webhookUrl()}</div></div><br><div class="cf-field cf-wide"><label>Private webhook key</label><div class="cf-code">${secret()}</div></div><br><div class="cf-field cf-wide"><label>Sample JSON payload</label><div class="cf-code">${payload}</div></div><br><div class="cf-field cf-wide"><label>Sample fetch code</label><div class="cf-code">fetch('${webhookUrl()}', {\n  method: 'POST',\n  headers: {\n    'Content-Type': 'application/json',\n    'x-constrava-key': '${secret()}'\n  },\n  body: JSON.stringify(${payload.replace(/\n/g,'\n  ')})\n})</div></div>`;
  }
  function render(){ platformButtons(); document.getElementById('cfInstructions').innerHTML=instructions(); document.getElementById('cfWebhook').innerHTML=webhookBlock(); }
  function open(){ modal.classList.add('open'); render(); }
  function close(){ modal.classList.remove('open'); }
  function sendTest(){
    const record = { lead_id:'FORM-'+Math.floor(100000+Math.random()*900000), record_type:'third_party_form_lead', module:'leads', name:document.getElementById('cfTestName').value, email:document.getElementById('cfTestEmail').value, company:document.getElementById('cfTestCompany').value, title:'External Form Lead', source:platforms[selected][0], owner:document.getElementById('cfOwner').value, status:document.getElementById('cfStatus').value, priority:'High', deal_name:'External form intake - '+platforms[selected][0], value:Number(document.getElementById('cfTestValue').value||0), probability:35, expected_revenue:Math.round(Number(document.getElementById('cfTestValue').value||0)*.35), close_date:new Date().toISOString().slice(0,10), created_at:new Date().toISOString().slice(0,10), last_contacted:new Date().toISOString().slice(0,10), tags:['third-party-form', selected, 'intake'], notes:document.getElementById('cfTestMessage').value };
    save(record); close(); rerender(); toast('Test '+platforms[selected][0]+' lead added to CRM.');
  }
  function copy(){ if(!isPrivate){ toast('Webhook code is only available on the private site.'); return; } navigator.clipboard?.writeText(webhookUrl()).then(()=>toast('Private webhook URL copied.')).catch(()=>toast(webhookUrl())); }

  document.getElementById('cfClose').onclick=close;
  document.getElementById('cfTest').onclick=sendTest;
  document.getElementById('cfCopy').onclick=copy;
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
