import fs from "fs";

const file = "crm-form-integrations.js";

const ui = String.raw`(function(){
  if (window.__constravaFormConnectionsRebuilt) return;
  window.__constravaFormConnectionsRebuilt = true;

  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || 'demo';
  const isPrivate = params.get('mode') === 'private' || params.get('private') === '1' || window.location.pathname.startsWith('/app');
  const origin = 'https://constravaai.com';
  const CONNECTION_KEY = 'constravaGoogleFormsConnectionId';
  const SELECTED_FORM_KEY = 'constravaSelectedGoogleForm';

  if (isPrivate && params.get('googleFormsConnected') === '1' && params.get('connectionId')) {
    sessionStorage.setItem(CONNECTION_KEY, params.get('connectionId'));
  }

  const style = document.createElement('style');
  style.textContent = '.cx-form-panel{border:1px solid #d8e0e7;border-radius:16px;background:linear-gradient(135deg,#ffffff,#f8fffc);box-shadow:0 12px 28px rgba(15,23,42,.06);margin:0 0 14px;overflow:hidden}.cx-form-head{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;padding:16px;border-bottom:1px solid #e6edf2}.cx-form-head h3{margin:0;color:#022c22}.cx-form-head p{margin:5px 0 0;color:#64748b;font-size:12px;line-height:1.45}.cx-form-pill{border:1px solid rgba(16,185,129,.35);background:#ecfdf5;color:#047857;border-radius:999px;padding:7px 10px;font-size:11px;font-weight:950;white-space:nowrap}.cx-form-body{padding:15px;display:grid;gap:12px}.cx-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.cx-form-card{border:1px solid #e5e7eb;border-radius:14px;background:white;padding:14px}.cx-form-card h4{margin:0 0 7px;color:#022c22}.cx-form-card p{margin:0 0 10px;color:#64748b;font-size:12px;line-height:1.45}.cx-form-field label{display:block;margin-bottom:6px;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#047857;font-weight:950}.cx-form-field input,.cx-form-field textarea{width:100%;border:1px solid #d8e0e7;border-radius:11px;background:#f8fafc;color:#0f172a;padding:10px 11px;font:inherit}.cx-form-field textarea{min-height:92px;resize:vertical}.cx-form-wide{grid-column:1/-1}.cx-form-actions{display:flex;flex-wrap:wrap;gap:8px}.cx-form-btn{border:1px solid #d8e0e7;border-radius:11px;background:white;color:#073d32;font-weight:900;padding:10px 12px;cursor:pointer}.cx-form-primary{background:#10b981;border-color:#10b981;color:#022c22}.cx-form-dark{background:#052e24;border-color:#052e24;color:#d1fae5}.cx-form-status{border:1px solid #d8e0e7;border-radius:12px;background:#f8fafc;padding:10px 12px;color:#334155;font-size:12px;line-height:1.45}.cx-form-ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}.cx-form-warn{background:#fffbeb;color:#92400e;border-color:rgba(245,158,11,.35)}.cx-form-list{display:grid;gap:8px}.cx-form-row{border:1px solid #d8e0e7;border-radius:12px;background:#f8fafc;padding:10px;display:flex;justify-content:space-between;align-items:center;gap:8px}.cx-form-row b{color:#073d32;font-size:13px}.cx-form-row small{display:block;color:#64748b;margin-top:3px}.cx-form-code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#022c22;color:#d1fae5;border-radius:13px;padding:13px;white-space:pre-wrap;overflow:auto;font-size:12px;line-height:1.5;max-height:360px}.cx-form-mini{font-size:11px;color:#64748b;margin-top:8px}.cx-form-hidden{display:none}@media(max-width:920px){.cx-form-grid{grid-template-columns:1fr}.cx-form-wide{grid-column:auto}.cx-form-head{display:block}.cx-form-pill{display:inline-flex;margin-top:8px}.cx-form-row{display:block}.cx-form-row button{margin-top:8px}}';
  document.head.appendChild(style);

  function $(id){ return document.getElementById(id); }
  function esc(v){ return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]; }); }
  function slug(value, fallback){ return String(value || fallback || 'form').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || fallback || 'form'; }
  function conn(){ return sessionStorage.getItem(CONNECTION_KEY) || ''; }
  function selected(){ try { return JSON.parse(sessionStorage.getItem(SELECTED_FORM_KEY) || '{}'); } catch { return {}; } }
  function saveSelected(form){ sessionStorage.setItem(SELECTED_FORM_KEY, JSON.stringify(form || {})); }
  function siteSlug(){ return slug($('cxFormSite') && $('cxFormSite').value, 'constrava-crm'); }
  function formSlug(){ return slug($('cxFormName') && $('cxFormName').value, 'google-form'); }
  function endpoint(){ return origin + '/api/forms/intake/' + encodeURIComponent(siteSlug()) + '/' + encodeURIComponent(formSlug()); }
  function hookKey(){ return 'cx_' + siteSlug().replace(/-/g,'_') + '_' + formSlug().replace(/-/g,'_') + '_google'; }
  function toast(msg){ const t = $('toast'); if (t) { t.textContent = msg; t.classList.add('show'); setTimeout(function(){ t.classList.remove('show'); }, 2600); } }
  function setStatus(id, message, mode){ const el = $(id); if (!el) return; el.className = 'cx-form-status ' + (mode === 'ok' ? 'cx-form-ok' : mode === 'warn' ? 'cx-form-warn' : ''); el.textContent = message; }

  function buildScript(){
    const form = selected();
    return [
      'const CONSTRAVA_ENDPOINT = "' + endpoint() + '";',
      'const CONSTRAVA_KEY = "' + hookKey() + '";',
      '',
      'function onFormSubmit(e) {',
      '  const data = {};',
      '  if (e && e.namedValues) {',
      '    Object.keys(e.namedValues).forEach(function(fieldName) {',
      '      const value = e.namedValues[fieldName];',
      '      data[fieldName] = Array.isArray(value) ? value.join(", ") : value;',
      '    });',
      '  }',
      '  data.provider = "Google Forms";',
      '  data.source = "Google Forms";',
      '  data.google_form_id = "' + (form.id || '') + '";',
      '  data.google_form_name = "' + String(form.name || '').replace(/"/g, '\\"') + '";',
      '  data.site_slug = "' + siteSlug() + '";',
      '  data.form_slug = "' + formSlug() + '";',
      '',
      '  UrlFetchApp.fetch(CONSTRAVA_ENDPOINT, {',
      '    method: "post",',
      '    contentType: "application/json",',
      '    muteHttpExceptions: true,',
      '    headers: {',
      '      "x-constrava-key": CONSTRAVA_KEY,',
      '      "x-form-provider": "Google Forms"',
      '    },',
      '    payload: JSON.stringify(data)',
      '  });',
      '}',
      '',
      '// Setup:',
      '// 1. Open the Google Form response spreadsheet.',
      '// 2. Extensions -> Apps Script.',
      '// 3. Paste this file.',
      '// 4. Triggers -> Add Trigger.',
      '// 5. Choose onFormSubmit, event source From spreadsheet, event type On form submit.'
    ].join('\n');
  }

  function renderScript(){ const el = $('cxFormScript'); if (el) el.textContent = buildScript(); }

  async function signIn(){
    if (!isPrivate) { setStatus('cxFormStatus','Open the private dashboard before connecting Google Forms.','warn'); return; }
    const returnTo = window.location.pathname + window.location.search;
    const qs = 'private=1&siteSlug=' + encodeURIComponent(siteSlug()) + '&formSlug=' + encodeURIComponent(formSlug()) + '&token=' + encodeURIComponent(token) + '&returnTo=' + encodeURIComponent(returnTo);
    try {
      const r = await fetch('/debug/google-oauth?' + qs, { cache: 'no-store', headers: { 'x-constrava-private': '1' } });
      const j = await r.json();
      if (j && j.oauth_url) { window.location.href = j.oauth_url; return; }
    } catch {}
    window.location.href = origin + '/auth/google/forms/start?' + qs;
  }

  async function checkStatus(){
    if (!isPrivate) { setStatus('cxFormStatus','Public demo mode: Google account connection is disabled.','warn'); return; }
    if (!conn()) { setStatus('cxFormStatus','Not connected. Click Connect Google Account.',''); return; }
    try {
      const r = await fetch('/api/google/forms/status?private=1&connectionId=' + encodeURIComponent(conn()), { cache: 'no-store', headers: { 'x-constrava-private': '1' } });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Connection not found.');
      setStatus('cxFormStatus','Connected as ' + (j.connection.account || 'Google account') + '.','ok');
    } catch (err) {
      setStatus('cxFormStatus','Connection needs to be refreshed: ' + (err.message || 'sign in again') + '.','warn');
    }
  }

  async function loadForms(){
    if (!conn()) { setStatus('cxFormStatus','Connect Google first, then load forms.','warn'); return; }
    const list = $('cxFormList');
    list.innerHTML = '<div class="cx-form-status">Loading Google Forms...</div>';
    try {
      const r = await fetch('/api/google/forms/list?private=1&connectionId=' + encodeURIComponent(conn()), { cache: 'no-store', headers: { 'x-constrava-private': '1' } });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Could not load Google Forms.');
      if (!j.forms || !j.forms.length) { list.innerHTML = '<div class="cx-form-status">No Google Forms found in this Google account.</div>'; return; }
      list.innerHTML = j.forms.map(function(f){ return '<div class="cx-form-row"><span><b>' + esc(f.name || 'Untitled form') + '</b><small>' + esc(f.id || '') + '</small></span><button class="cx-form-btn cx-form-primary" data-form-id="' + esc(f.id || '') + '" data-form-name="' + esc(f.name || 'Google Form') + '" type="button">Use form</button></div>'; }).join('');
      list.querySelectorAll('[data-form-id]').forEach(function(btn){
        btn.onclick = async function(){
          const form = { id: btn.getAttribute('data-form-id'), name: btn.getAttribute('data-form-name') };
          saveSelected(form);
          if ($('cxFormName')) $('cxFormName').value = form.name || 'Google Form';
          renderScript();
          try {
            await fetch('/api/google/forms/select?private=1', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-constrava-private': '1' }, body: JSON.stringify({ connectionId: conn(), formId: form.id, formName: form.name }) });
          } catch {}
          setStatus('cxFormSelected','Selected: ' + (form.name || form.id),'ok');
          toast('Google Form selected.');
        };
      });
    } catch (err) {
      list.innerHTML = '<div class="cx-form-status cx-form-warn">' + esc(err.message || 'Could not load forms.') + '</div>';
    }
  }

  async function sendTest(){
    const body = {
      name: $('cxFormTestName').value,
      email: $('cxFormTestEmail').value,
      phone: $('cxFormTestPhone').value,
      company: $('cxFormTestCompany').value,
      message: $('cxFormTestMessage').value,
      value: Number($('cxFormTestValue').value || 0),
      provider: 'Google Forms',
      source: 'Google Forms Test',
      dashboard_token: token,
      google_form_id: (selected().id || '')
    };
    try {
      const r = await fetch(endpoint(), { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-constrava-key': hookKey(), 'x-form-provider': 'Google Forms' }, body: JSON.stringify(body) });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Test failed.');
      setStatus('cxFormTestStatus','Test sent. The lead should appear in the unified CRM list.','ok');
      if (window.loadEntries) window.loadEntries();
      toast('Test lead sent to CRM.');
    } catch (err) {
      setStatus('cxFormTestStatus', err.message || 'Test failed.', 'warn');
    }
  }

  function copyScript(){ renderScript(); navigator.clipboard && navigator.clipboard.writeText($('cxFormScript').textContent).then(function(){ toast('Apps Script copied.'); }).catch(function(){ setStatus('cxFormSelected','Could not copy. Select the script manually.','warn'); }); }

  function panelHtml(){
    const form = selected();
    return '<section class="cx-form-panel" id="cxFormConnectionsPanel">' +
      '<div class="cx-form-head"><div><h3>Form Connections</h3><p>Connect Google Forms and route every response through the AI interpreter into the unified CRM list.</p></div><div class="cx-form-pill">Google Forms + AI CRM Intake</div></div>' +
      '<div class="cx-form-body">' +
      '<div class="cx-form-grid">' +
      '<div class="cx-form-card"><h4>Connection</h4><p>Connect the Google account that owns the forms.</p><div class="cx-form-actions"><button class="cx-form-btn cx-form-dark" id="cxFormConnect" type="button">Connect Google Account</button><button class="cx-form-btn" id="cxFormCheck" type="button">Check Status</button></div><div id="cxFormStatus" class="cx-form-status" style="margin-top:10px">Not connected yet.</div></div>' +
      '<div class="cx-form-card"><h4>CRM destination</h4><div class="cx-form-grid"><div class="cx-form-field"><label>CRM Workspace</label><input id="cxFormSite" value="Constrava CRM"></div><div class="cx-form-field"><label>Connection Name</label><input id="cxFormName" value="' + esc(form.name || 'Google Form Lead Capture') + '"></div></div><div class="cx-form-mini">Responses will be sent to: <span id="cxFormEndpointText"></span></div></div>' +
      '<div class="cx-form-card cx-form-wide"><h4>Choose a Google Form</h4><p>Load forms from the connected Google account, then choose the form that should feed the CRM.</p><div class="cx-form-actions"><button class="cx-form-btn cx-form-primary" id="cxFormLoad" type="button">Load Google Forms</button><button class="cx-form-btn" id="cxFormRenderScript" type="button">Refresh Script</button></div><div id="cxFormSelected" class="cx-form-status" style="margin-top:10px">' + (form.id ? 'Selected: ' + esc(form.name || form.id) : 'No form selected yet.') + '</div><div id="cxFormList" class="cx-form-list" style="margin-top:10px"></div></div>' +
      '<div class="cx-form-card cx-form-wide"><h4>Install response forwarder</h4><p>Paste this into the Google Form response Sheet Apps Script trigger. It forwards every new response into the CRM AI intake endpoint.</p><div class="cx-form-actions"><button class="cx-form-btn" id="cxFormCopy" type="button">Copy Script</button></div><pre class="cx-form-code" id="cxFormScript"></pre></div>' +
      '<div class="cx-form-card cx-form-wide"><h4>Send test lead</h4><div class="cx-form-grid"><div class="cx-form-field"><label>Name</label><input id="cxFormTestName" value="Google Forms Test Lead"></div><div class="cx-form-field"><label>Email</label><input id="cxFormTestEmail" value="google.form.lead@example.com"></div><div class="cx-form-field"><label>Phone</label><input id="cxFormTestPhone" value="610-555-0142"></div><div class="cx-form-field"><label>Company</label><input id="cxFormTestCompany" value="Google Forms Client Co"></div><div class="cx-form-field"><label>Value</label><input id="cxFormTestValue" type="number" value="7200"></div><div class="cx-form-field cx-form-wide"><label>Message</label><textarea id="cxFormTestMessage">This is a test lead sent through the Google Forms CRM connection.</textarea></div></div><div class="cx-form-actions" style="margin-top:10px"><button class="cx-form-btn cx-form-primary" id="cxFormTest" type="button">Send Test Lead</button></div><div id="cxFormTestStatus" class="cx-form-status" style="margin-top:10px">No test sent yet.</div></div>' +
      '</div></div></section>';
  }

  function bindPanel(){
    $('cxFormConnect').onclick = signIn;
    $('cxFormCheck').onclick = checkStatus;
    $('cxFormLoad').onclick = loadForms;
    $('cxFormRenderScript').onclick = renderScript;
    $('cxFormCopy').onclick = copyScript;
    $('cxFormTest').onclick = sendTest;
    ['cxFormSite','cxFormName'].forEach(function(id){ const el = $(id); if (el) el.oninput = function(){ updateEndpoint(); renderScript(); }; });
    updateEndpoint();
    renderScript();
    checkStatus();
  }

  function updateEndpoint(){ const el = $('cxFormEndpointText'); if (el) el.textContent = endpoint(); }

  function crmRoot(){ return document.querySelector('.crm-main') || document.querySelector('.crm-shell') || document.querySelector('#crm') || null; }
  function ensurePanel(){
    if (document.getElementById('cxFormConnectionsPanel')) return;
    const root = crmRoot();
    if (!root) return;
    const wrap = document.createElement('div');
    wrap.innerHTML = panelHtml();
    const entryHub = document.getElementById('cxEntryHub');
    if (entryHub && entryHub.parentElement) entryHub.parentElement.insertBefore(wrap.firstElementChild, entryHub.nextSibling);
    else root.insertBefore(wrap.firstElementChild, root.firstElementChild || null);
    bindPanel();
  }

  setInterval(ensurePanel, 1200);
  document.addEventListener('click', function(e){
    const btn = e.target.closest('[data-cx-flow="website"], [data-cx-flow="api"]');
    if (btn) { setTimeout(ensurePanel, 80); }
  }, true);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensurePanel); else ensurePanel();
})();`;

fs.writeFileSync(file, ui);
console.log("Rebuilt Form Connections UI.");

async function runSafeCrmPatches() {
  // Do not import crm-ai-form-intake-patch.js here because that script intentionally calls process.exit.
  await import("./crm-universal-ai-form-router-patch.js");
  await import("./crm-demo-lead-shape-patch.js");
  await import("./crm-unified-lead-list-patch.js");
  await import("./crm-entry-system-patch.js");
  await import("./crm-entry-system-hotfix-patch.js");
}

await runSafeCrmPatches();
