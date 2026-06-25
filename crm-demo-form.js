(function(){
  const style = document.createElement('style');
  style.textContent = `
    .crm-demo-backdrop{position:fixed;inset:0;z-index:1000;display:none;place-items:center;background:rgba(2,18,14,.62);backdrop-filter:blur(10px);padding:20px}.crm-demo-backdrop.open{display:grid}.crm-demo-modal{width:min(980px,100%);max-height:92vh;overflow:auto;background:#fff;border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.32);border:1px solid rgba(16,185,129,.18)}.crm-demo-head{padding:22px 24px;border-bottom:1px solid #dbe8e4;background:radial-gradient(circle at 20% 0,rgba(16,185,129,.18),transparent 35%),linear-gradient(135deg,#f8fffc,#ecfdf5)}.crm-demo-head h2{margin:0;color:#022c22;letter-spacing:-.03em}.crm-demo-head p{margin:8px 0 0;color:#475569;line-height:1.5}.crm-demo-warning{margin-top:14px;border:1px solid rgba(245,158,11,.35);background:#fffbeb;color:#92400e;border-radius:14px;padding:12px 14px;font-weight:800;line-height:1.45}.crm-demo-body{padding:22px 24px}.crm-demo-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.crm-demo-field label{display:block;margin-bottom:6px;font-size:12px;font-weight:950;letter-spacing:.08em;text-transform:uppercase;color:#047857}.crm-demo-field input,.crm-demo-field select,.crm-demo-field textarea{width:100%;border:1px solid #dbe8e4;border-radius:12px;padding:12px 13px;background:#f8fafc;color:#0f172a;font:inherit}.crm-demo-field textarea{min-height:92px;resize:vertical}.crm-demo-wide{grid-column:1/-1}.crm-demo-foot{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:18px 24px;border-top:1px solid #dbe8e4;background:#f8fffc}.crm-demo-left,.crm-demo-right{display:flex;gap:10px;flex-wrap:wrap}.crm-demo-btn{border:1px solid #dbe8e4;border-radius:13px;min-height:46px;padding:0 15px;background:#fff;color:#073d32;font-weight:900;cursor:pointer}.crm-demo-primary{background:#10b981;border-color:#10b981;color:#022c22}.crm-demo-disabled{opacity:.65;cursor:not-allowed}.crm-demo-note{font-size:12px;color:#64748b;margin-top:10px;line-height:1.45}@media(max-width:760px){.crm-demo-grid{grid-template-columns:1fr}.crm-demo-foot{display:block}.crm-demo-left,.crm-demo-right{margin-top:10px}}
  `;
  document.head.appendChild(style);

  const modal = document.createElement('div');
  modal.className = 'crm-demo-backdrop';
  modal.id = 'crmDemoFormBackdrop';
  modal.innerHTML = `
    <div class="crm-demo-modal" role="dialog" aria-modal="true" aria-labelledby="crmDemoTitle">
      <div class="crm-demo-head">
        <h2 id="crmDemoTitle">Add CRM Component</h2>
        <p>This is the same kind of record-entry form a real CRM component would use for creating a new lead, account, deal, or pipeline opportunity.</p>
        <div class="crm-demo-warning">Live CRM entry is intentionally disabled in this public demo. This protects the demo database from random or fake submissions. Use <b>Submit demo data</b> to safely preview what a real submission would look like.</div>
      </div>
      <form id="crmDemoForm" class="crm-demo-body">
        <div class="crm-demo-grid">
          <div class="crm-demo-field"><label>Lead owner</label><input name="owner" value="Blake Jernegan" readonly></div>
          <div class="crm-demo-field"><label>Lead status</label><select name="status"><option>New</option><option selected>Qualified</option><option>Needs Analysis</option><option>Proposal</option><option>Negotiation</option></select></div>
          <div class="crm-demo-field"><label>First name</label><input name="first_name" placeholder="Example: Taylor"></div>
          <div class="crm-demo-field"><label>Last name</label><input name="last_name" placeholder="Example: Brooks"></div>
          <div class="crm-demo-field"><label>Email</label><input name="email" type="email" placeholder="taylor@company.com"></div>
          <div class="crm-demo-field"><label>Phone</label><input name="phone" placeholder="(610) 555-0198"></div>
          <div class="crm-demo-field"><label>Company</label><input name="company" placeholder="Company name"></div>
          <div class="crm-demo-field"><label>Title</label><input name="title" placeholder="Operations Manager"></div>
          <div class="crm-demo-field"><label>Industry</label><select name="industry"><option>Manufacturing</option><option>Home Services</option><option>Fitness</option><option>Creative Services</option><option>Restaurant</option><option>Technology</option></select></div>
          <div class="crm-demo-field"><label>Lead source</label><select name="source"><option>Contact form</option><option>Search</option><option>Referral</option><option>Pricing CTA</option><option>LinkedIn</option><option>Email Campaign</option></select></div>
          <div class="crm-demo-field"><label>Deal name</label><input name="deal_name" placeholder="Custom dashboard build"></div>
          <div class="crm-demo-field"><label>Deal value</label><input name="value" type="number" placeholder="8500"></div>
          <div class="crm-demo-field"><label>Probability</label><select name="probability"><option>10</option><option>20</option><option selected>40</option><option>60</option><option>80</option><option>100</option></select></div>
          <div class="crm-demo-field"><label>Close date</label><input name="close_date" type="date"></div>
          <div class="crm-demo-field crm-demo-wide"><label>Next step</label><input name="next_step" placeholder="Schedule discovery call and confirm required dashboard modules."></div>
          <div class="crm-demo-field crm-demo-wide"><label>Notes</label><textarea name="notes" placeholder="Describe the client's request, timeline, constraints, and what should happen next."></textarea></div>
        </div>
        <div class="crm-demo-note">The regular submit button is present so visitors understand the real workflow, but it is blocked in the demo. A production version would send this form to the CRM database and create a real record.</div>
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
  function openForm(){ modal.classList.add('open'); }
  function closeForm(){ modal.classList.remove('open'); }
  function demoLead(){
    const form = document.getElementById('crmDemoForm');
    const data = Object.fromEntries(new FormData(form).entries());
    const first = data.first_name || 'Taylor';
    const last = data.last_name || 'Reed';
    const value = Number(data.value || 8700);
    const probability = Number(data.probability || 40);
    return {
      lead_id: 'CL-DEMO-' + Math.floor(1000 + Math.random()*9000),
      name: first + ' ' + last,
      first_name: first,
      last_name: last,
      email: data.email || 'taylor.reed@demo-company.example',
      phone: data.phone || '(610) 555-0198',
      mobile: data.phone || '(610) 555-0198',
      company: data.company || 'Demo Operations Co',
      title: data.title || 'Operations Manager',
      industry: data.industry || 'Manufacturing',
      employees: '11-50',
      website: 'https://demo-company.example',
      location: 'Lehigh Valley, PA',
      source: data.source || 'Contact form',
      owner: data.owner || 'Blake Jernegan',
      status: data.status || 'Qualified',
      priority: 'High',
      deal_name: data.deal_name || 'Custom CRM Dashboard Build',
      value,
      probability,
      expected_revenue: Math.round(value * probability / 100),
      close_date: data.close_date || '2026-07-22',
      next_step: data.next_step || 'Schedule discovery call and confirm required dashboard modules.',
      last_contacted: new Date().toISOString().slice(0,10),
      created_at: new Date().toISOString().slice(0,10),
      tags: ['demo-submit','crm-component','preview'],
      notes: data.notes || 'Demo-submitted CRM component. In production, this would create a real CRM lead/deal record in the database.'
    };
  }
  function submitDemo(){
    window.data = window.data || {};
    window.data.leads = window.data.leads || [];
    window.data.leads.unshift(demoLead());
    closeForm();
    if(typeof window.renderCRM === 'function') window.renderCRM(window.activeCrm || 'dashboards');
    if(typeof window.render === 'function') window.render();
    toast('Demo CRM data added. Live entry stayed disabled.');
  }
  function bind(){
    const add = document.getElementById('crmAdd');
    if(add && !add.dataset.demoFormBound){
      add.dataset.demoFormBound = 'true';
      add.addEventListener('click', function(ev){ ev.preventDefault(); ev.stopImmediatePropagation(); openForm(); }, true);
    }
  }
  document.getElementById('crmDemoClose').onclick = closeForm;
  document.getElementById('crmRealSubmit').onclick = function(){ toast('Real submission is disabled in this public demo. Use Submit demo data to preview safely.'); };
  document.getElementById('crmDemoSubmit').onclick = submitDemo;
  modal.addEventListener('click', function(ev){ if(ev.target === modal) closeForm(); });
  bind();
  setInterval(bind, 600);
})();
