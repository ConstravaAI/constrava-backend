(function(){
  const config = {
    dashboards: { label:'Dashboard Component', title:'Add Dashboard Component', recordType:'dashboard_component', status:'Qualified', deal:'Dashboard Component Setup', note:'Demo dashboard component added for CRM reporting.' },
    home: { label:'CRM Item', title:'Add CRM Item', recordType:'crm_item', status:'New', deal:'CRM Workspace Item', note:'Demo CRM item added from the home module.' },
    feeds: { label:'Feed Update', title:'Add Feed Update', recordType:'feed_update', status:'New', deal:'CRM Feed Update', note:'Demo feed update logged for the CRM timeline.' },
    leads: { label:'Lead', title:'Add Lead', recordType:'lead', status:'New', deal:'New Lead Opportunity', note:'Demo lead created from the Leads module.' },
    vip: { label:'VIP Lead', title:'Add VIP Lead', recordType:'vip_lead', status:'Qualified', deal:'VIP Client Opportunity', note:'Demo VIP lead logged with higher priority.' },
    contacts: { label:'Contact', title:'Add Contact', recordType:'contact', status:'Qualified', deal:'Contact Relationship Record', note:'Demo contact added to the CRM.' },
    accounts: { label:'Account', title:'Add Account', recordType:'account', status:'Needs Analysis', deal:'Account Setup Record', note:'Demo account added with company-level information.' },
    deals: { label:'Deal', title:'Add Deal', recordType:'deal', status:'Proposal', deal:'Custom Software Deal', note:'Demo sales deal added to the pipeline.' },
    activities: { label:'Activity', title:'Add Activity', recordType:'activity', status:'Negotiation', deal:'Follow-up Activity', note:'Demo activity logged as a follow-up task.' },
    documents: { label:'Document', title:'Add Document', recordType:'document', status:'Proposal', deal:'Document Request', note:'Demo document record added for proposal tracking.' },
    reports: { label:'Report', title:'Add Report', recordType:'report', status:'Qualified', deal:'CRM Report Record', note:'Demo report record added to the CRM.' }
  };
  let currentType = 'dashboards';
  const style = document.createElement('style');
  style.textContent = `
    .crm-demo-backdrop{position:fixed;inset:0;z-index:1000;display:none;place-items:center;background:rgba(2,18,14,.62);backdrop-filter:blur(10px);padding:20px}.crm-demo-backdrop.open{display:grid}.crm-demo-modal{width:min(980px,100%);max-height:92vh;overflow:auto;background:#fff;border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.32);border:1px solid rgba(16,185,129,.18)}.crm-demo-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:radial-gradient(circle at 20% 0,rgba(16,185,129,.18),transparent 35%),linear-gradient(135deg,#f8fffc,#ecfdf5)}.crm-demo-head h2{margin:0;color:#022c22;letter-spacing:-.03em}.crm-demo-head p{margin:8px 0 0;color:#475569;line-height:1.5}.crm-demo-warning{margin-top:14px;border:1px solid rgba(245,158,11,.35);background:#fffbeb;color:#92400e;border-radius:14px;padding:12px 14px;font-weight:800;line-height:1.45}.crm-demo-body{padding:22px 24px}.crm-demo-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.crm-demo-field label{display:block;margin-bottom:6px;font-size:12px;font-weight:950;letter-spacing:.08em;text-transform:uppercase;color:#047857}.crm-demo-field input,.crm-demo-field select,.crm-demo-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;padding:12px 13px;background:#f8fafc;color:#0f172a;font:inherit}.crm-demo-field textarea{min-height:92px;resize:vertical}.crm-demo-wide{grid-column:1/-1}.crm-demo-foot{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}.crm-demo-left,.crm-demo-right{display:flex;gap:10px;flex-wrap:wrap}.crm-demo-btn{border:1px solid #dbe8e4;border-radius:13px;min-height:46px;padding:0 15px;background:#fff;color:#073d32;font-weight:900;cursor:pointer}.crm-demo-primary{background:#10b981;border-color:#10b981;color:#022c22}.crm-demo-disabled{opacity:.65;cursor:not-allowed}.crm-demo-note{font-size:12px;color:#64748b;margin-top:10px;line-height:1.45}.crm-section-add{background:#022c22!important;border-color:#022c22!important;color:#d1fae5!important}.crm-entry-type-pill{display:inline-flex;align-items:center;border:1px solid rgba(16,185,129,.28);border-radius:999px;background:#ecfdf5;color:#047857;font-weight:950;padding:6px 10px;margin-top:10px;font-size:12px;letter-spacing:.08em;text-transform:uppercase}@media(max-width:760px){.crm-demo-grid{grid-template-columns:1fr}.crm-demo-foot{display:block}.crm-demo-left,.crm-demo-right{margin-top:10px}}
  `;
  document.head.appendChild(style);

  const modal = document.createElement('div');
  modal.className = 'crm-demo-backdrop';
  modal.id = 'crmDemoFormBackdrop';
  modal.innerHTML = `
    <div class="crm-demo-modal" role="dialog" aria-modal="true" aria-labelledby="crmDemoTitle">
      <div class="crm-demo-head">
        <h2 id="crmDemoTitle">Add CRM Data</h2>
        <p id="crmDemoDescription">This is the same kind of record-entry form a real CRM component would use for creating a new lead, account, deal, activity, document, report, or pipeline opportunity.</p>
        <div id="crmDemoType" class="crm-entry-type-pill">CRM DATA POINT</div>
        <div class="crm-demo-warning">Live CRM entry is intentionally disabled in this public demo. This protects the demo database from random or fake submissions. Use <b>Submit demo data</b> to safely preview what a real submission would look like.</div>
      </div>
      <form id="crmDemoForm" class="crm-demo-body">
        <div class="crm-demo-grid">
          <div class="crm-demo-field"><label>Record owner</label><input name="owner" value="Constrava Demo Team" readonly></div>
          <div class="crm-demo-field"><label>Stage / status</label><select name="status"><option>New</option><option selected>Qualified</option><option>Needs Analysis</option><option>Proposal</option><option>Negotiation</option><option>Closed Won</option></select></div>
          <div class="crm-demo-field"><label>First name</label><input name="first_name" placeholder="Example: Taylor"></div>
          <div class="crm-demo-field"><label>Last name</label><input name="last_name" placeholder="Example: Brooks"></div>
          <div class="crm-demo-field"><label>Email</label><input name="email" type="email" placeholder="taylor@company.com"></div>
          <div class="crm-demo-field"><label>Phone</label><input name="phone" placeholder="(610) 555-0198"></div>
          <div class="crm-demo-field"><label>Company / account</label><input name="company" placeholder="Company name"></div>
          <div class="crm-demo-field"><label>Title / role</label><input name="title" placeholder="Operations Manager"></div>
          <div class="crm-demo-field"><label>Industry / category</label><select name="industry"><option>Manufacturing</option><option>Home Services</option><option>Fitness</option><option>Creative Services</option><option>Restaurant</option><option>Technology</option><option>CRM Operations</option><option>Sales Activity</option><option>Document</option><option>Reporting</option></select></div>
          <div class="crm-demo-field"><label>Source / channel</label><select name="source"><option>Contact form</option><option>Search</option><option>Referral</option><option>Pricing CTA</option><option>LinkedIn</option><option>Email Campaign</option><option>Manual CRM Entry</option><option>Demo Form</option></select></div>
          <div class="crm-demo-field"><label>Record / deal name</label><input name="deal_name" placeholder="Custom dashboard build"></div>
          <div class="crm-demo-field"><label>Value / score</label><input name="value" type="number" placeholder="8500"></div>
          <div class="crm-demo-field"><label>Probability</label><select name="probability"><option>10</option><option>20</option><option selected>40</option><option>60</option><option>80</option><option>100</option></select></div>
          <div class="crm-demo-field"><label>Due / close date</label><input name="close_date" type="date"></div>
          <div class="crm-demo-field crm-demo-wide"><label>Next step</label><input name="next_step" placeholder="Schedule discovery call and confirm required dashboard modules."></div>
          <div class="crm-demo-field crm-demo-wide"><label>Notes</label><textarea name="notes" placeholder="Describe the CRM data point, timeline, constraints, and what should happen next."></textarea></div>
        </div>
        <div class="crm-demo-note">The regular submit button is present so visitors understand the real workflow, but it is blocked in the demo. A production version would send this form to the CRM database and create a real record in the selected CRM module.</div>
      </form>
      <div class="crm-demo-foot">
        <div class="crm-demo-left"><button class="crm-demo-btn" id="crmDemoClose" type="button">Cancel</button></div>
        <div class="crm-demo-right"><button class="crm-demo-btn crm-demo-disabled" id="crmRealSubmit" type="button">Submit</button><button class="crm-demo-btn crm-demo-primary" id="crmDemoSubmit" type="button">Submit demo data</button></div>
      </div>
    </div>`;
  document.body.appendChild(modal);

  function toast(message){
    const t = document.getElementById('toast');
    if(t){ t.textContent = message; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2600); }
    else alert(message);
  }
  function activeModule(){
    const active = document.querySelector('.crm-tab.active,[data-crm].active');
    return (active && active.getAttribute('data-crm')) || currentType || 'dashboards';
  }
  function moduleConfig(type){ return config[type] || config.dashboards; }
  function removeExtraZohoTab(){
    const navTitles = Array.from(document.querySelectorAll('.navtitle'));
    navTitles.forEach(title => {
      if(title.textContent.trim().toLowerCase() === 'crm'){
        const next = title.nextElementSibling;
        if(next && next.textContent.trim().toLowerCase().includes('zoho-style crm')){ title.remove(); next.remove(); }
      }
    });
    Array.from(document.querySelectorAll('button')).forEach(btn => { if(btn.textContent.trim().toLowerCase() === 'zoho-style crm') btn.remove(); });
  }
  function setFormContext(type){
    currentType = type || activeModule();
    const cfg = moduleConfig(currentType);
    document.getElementById('crmDemoTitle').textContent = cfg.title;
    document.getElementById('crmDemoType').textContent = cfg.recordType.replaceAll('_',' ');
    document.getElementById('crmDemoDescription').textContent = 'This protected demo form shows how a real CRM would log a ' + cfg.label.toLowerCase() + ' data point into the selected module.';
    const form = document.getElementById('crmDemoForm');
    if(form.status) form.status.value = cfg.status;
    if(form.deal_name) form.deal_name.placeholder = cfg.deal;
    if(form.notes) form.notes.placeholder = cfg.note;
  }
  function openForm(type){ setFormContext(type); modal.classList.add('open'); }
  function closeForm(){ modal.classList.remove('open'); }
  function demoLead(){
    const form = document.getElementById('crmDemoForm');
    const data = Object.fromEntries(new FormData(form).entries());
    const cfg = moduleConfig(currentType);
    const first = data.first_name || ({accounts:'Account',deals:'Deal',activities:'Activity',documents:'Document',reports:'Report',dashboards:'Dashboard'}[currentType] || 'Taylor');
    const last = data.last_name || ({accounts:'Record',deals:'Opportunity',activities:'Log',documents:'File',reports:'Entry',dashboards:'Component'}[currentType] || 'Reed');
    const value = Number(data.value || ({deals:13200,accounts:9800,activities:1200,documents:800,reports:2400,dashboards:6500}[currentType] || 8700));
    const probability = Number(data.probability || ({deals:60,activities:80,reports:40,documents:40}[currentType] || 40));
    return {
      lead_id: 'CL-DEMO-' + Math.floor(1000 + Math.random()*9000),
      record_type: cfg.recordType,
      module: currentType,
      name: first + ' ' + last,
      first_name: first,
      last_name: last,
      email: data.email || (currentType + '.demo@constrava-demo.example'),
      phone: data.phone || '(610) 555-0198',
      mobile: data.phone || '(610) 555-0198',
      company: data.company || ({accounts:'Demo Account Co',deals:'Pipeline Client Co',activities:'Follow-up Client Co',documents:'Proposal Client Co',reports:'Reporting Client Co'}[currentType] || 'Demo Operations Co'),
      title: data.title || ({accounts:'Account Contact',deals:'Decision Maker',activities:'Task Owner',documents:'Document Owner',reports:'Report Owner'}[currentType] || 'Operations Manager'),
      industry: data.industry || ({activities:'Sales Activity',documents:'Document',reports:'Reporting'}[currentType] || 'Manufacturing'),
      employees: '11-50',
      website: 'https://demo-company.example',
      location: 'Lehigh Valley, PA',
      source: data.source || 'Demo Form',
      owner: data.owner || 'Constrava Demo Team',
      status: data.status || cfg.status,
      priority: currentType === 'vip' ? 'Critical' : 'High',
      deal_name: data.deal_name || cfg.deal,
      value,
      probability,
      expected_revenue: Math.round(value * probability / 100),
      close_date: data.close_date || '2026-07-22',
      next_step: data.next_step || 'Review this demo CRM entry and confirm the next workflow step.',
      last_contacted: new Date().toISOString().slice(0,10),
      created_at: new Date().toISOString().slice(0,10),
      tags: ['demo-submit', cfg.recordType, 'preview'],
      notes: data.notes || cfg.note + ' In production, this would create a real record in the ' + cfg.label + ' module.'
    };
  }
  function submitDemo(){
    window.data = window.data || {};
    window.data.leads = window.data.leads || [];
    window.data.leads.unshift(demoLead());
    closeForm();
    if(typeof window.renderCRM === 'function') window.renderCRM(currentType || 'dashboards');
    if(typeof window.render === 'function') window.render();
    toast('Demo ' + moduleConfig(currentType).label.toLowerCase() + ' data added. Live entry stayed disabled.');
  }
  function ensureSectionButton(){
    const add = document.getElementById('crmAdd');
    if(!add || !add.parentElement) return null;
    let sectionBtn = document.getElementById('crmSectionAdd');
    if(!sectionBtn){
      sectionBtn = document.createElement('button');
      sectionBtn.id = 'crmSectionAdd';
      sectionBtn.type = 'button';
      sectionBtn.className = add.className + ' crm-section-add';
      add.insertAdjacentElement('afterend', sectionBtn);
    }
    const type = activeModule();
    sectionBtn.textContent = 'Add ' + moduleConfig(type).label;
    sectionBtn.onclick = function(ev){ ev.preventDefault(); ev.stopPropagation(); openForm(activeModule()); };
    return sectionBtn;
  }
  function bind(){
    removeExtraZohoTab();
    ensureSectionButton();
    document.querySelectorAll('[data-crm]').forEach(btn => {
      if(!btn.dataset.sectionButtonBound){
        btn.dataset.sectionButtonBound = 'true';
        btn.addEventListener('click', () => setTimeout(ensureSectionButton, 80));
      }
    });
    const add = document.getElementById('crmAdd');
    if(add && !add.dataset.demoFormBound){
      add.dataset.demoFormBound = 'true';
      add.addEventListener('click', function(ev){ ev.preventDefault(); ev.stopImmediatePropagation(); openForm('dashboards'); }, true);
    }
  }
  document.getElementById('crmDemoClose').onclick = closeForm;
  document.getElementById('crmRealSubmit').onclick = function(){ toast('Real submission is disabled in this public demo. Use Submit demo data to preview safely.'); };
  document.getElementById('crmDemoSubmit').onclick = submitDemo;
  modal.addEventListener('click', function(ev){ if(ev.target === modal) closeForm(); });
  bind();
  setInterval(bind, 500);
})();
