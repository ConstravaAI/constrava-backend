(function () {
  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function installSnippet(token) {
    return '<scr' + 'ipt async src="' + location.origin + '/tracker.js" data-token="' + escapeHtml(token || 'demo') + '"></scr' + 'ipt>';
  }

  function addGlobalStyles() {
    if (document.getElementById('connectWebsiteStableStyles')) return;
    var style = document.createElement('style');
    style.id = 'connectWebsiteStableStyles';
    style.textContent = [
      '.side{display:flex;flex-direction:column}',
      '.side-tools{margin-top:auto;padding-top:18px;display:grid;gap:4px;border-top:1px solid rgba(236,253,245,.12)}',
      '.side-tool{width:100%;border:0;border-radius:10px;padding:8px 10px;text-align:left;font-size:12px;font-weight:800;text-decoration:none;color:rgba(236,253,245,.62);background:transparent;box-shadow:none}',
      '.side-tool:hover,.side-tool.active{color:rgba(236,253,245,.92);background:rgba(255,255,255,.06);box-shadow:none}',
      '.side-tool.signout{color:rgba(254,215,170,.68);background:transparent}',
      '.settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}',
      '.settings-card{min-height:190px;padding:20px;border:1px solid rgba(16,185,129,.18);border-radius:18px;background:rgba(255,255,255,.92);box-shadow:var(--shadow)}',
      '.settings-card h2{margin:0 0 8px;color:#073d32}',
      '.settings-card p{margin:0 0 14px;color:var(--muted);line-height:1.5;font-size:14px}',
      '.settings-value{display:block;padding:11px 12px;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;color:#0f172a;font-weight:850;overflow-wrap:anywhere}',
      '.cw-profile{display:grid;grid-template-columns:1.2fr .8fr auto;gap:10px;margin:14px 0}',
      '.cw-code{display:flex;gap:8px;align-items:center;padding:10px;border:1px solid #dbe8e4;border-radius:12px;background:#06251e;color:#d1fae5;overflow:auto}',
      '.cw-code code{font-size:12px;white-space:nowrap}',
      '.cw-status{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:10px}',
      '.cw-status span{padding:8px 10px;border-radius:10px;background:#f8fafc;border:1px solid #dbe8e4;color:#475569;font-size:12px;font-weight:850}',
      '.cw-checklist{display:grid;gap:6px;margin-top:10px}',
      '.cw-checklist div{padding:8px 10px;border-radius:10px;background:#ecfdf5;color:#047857;font-size:12px;font-weight:850}',
      '@media(max-width:1200px){.settings-grid{grid-template-columns:1fr}}',
      '@media(max-width:900px){.cw-profile,.cw-status{grid-template-columns:1fr}}'
    ].join('');
    document.head.appendChild(style);
  }

  function installSidebarSettings(dashboardToken) {
    var sidebar = document.querySelector('.side');
    var shell = document.querySelector('.shell');
    if (!sidebar || !shell || document.getElementById('sidebarSettingsTools')) return;

    var settingsSection = document.createElement('section');
    settingsSection.id = 'settings';
    settingsSection.className = 'hidden';
    settingsSection.innerHTML = [
      '<div class="settings-grid">',
        '<article class="settings-card">',
          '<span class="badge">Account</span>',
          '<h2>Signed in</h2>',
          '<p>Manage the current dashboard session and leave the workspace when you are done.</p>',
          '<span class="settings-value" id="settingsAccount">Checking account...</span>',
          '<div class="crm-actions" style="margin-top:14px"><a class="btn danger" href="/logout">Sign out</a></div>',
        '</article>',
        '<article class="settings-card">',
          '<span class="badge">Dashboard</span>',
          '<h2>Website token</h2>',
          '<p>This token connects website events to this Constrava dashboard.</p>',
          '<span class="settings-value">' + escapeHtml(dashboardToken) + '</span>',
          '<div class="crm-actions" style="margin-top:14px"><a class="btn" href="/analytics/install?token=' + encodeURIComponent(dashboardToken) + '" target="_blank" rel="noopener">Open install helper</a></div>',
        '</article>',
        '<article class="settings-card">',
          '<span class="badge">Local CRM</span>',
          '<h2>Session records</h2>',
          '<p>Clear records and deletions saved only in this browser session.</p>',
          '<div class="crm-actions"><button class="btn danger" id="settingsClearSession">Clear session</button><button class="btn" id="settingsOpenCrm">Open CRM</button></div>',
        '</article>',
      '</div>'
    ].join('');
    shell.appendChild(settingsSection);

    var tools = document.createElement('div');
    tools.id = 'sidebarSettingsTools';
    tools.className = 'side-tools';
    tools.innerHTML = '<button class="side-tool" id="settingsNavBtn" type="button">Settings</button><a class="side-tool signout" href="/logout">Sign out</a>';
    sidebar.appendChild(tools);

    function setTitle(title, subtitle) {
      var pageTitle = document.getElementById('pageTitle');
      var pageSubtitle = document.getElementById('pageSubtitle');
      if (pageTitle) pageTitle.textContent = title;
      if (pageSubtitle) {
        pageSubtitle.textContent = subtitle || '';
        pageSubtitle.classList.toggle('hidden', !subtitle);
      }
    }
    function showSettings() {
      ['analytics', 'crm', 'sources'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.classList.add('hidden');
      });
      settingsSection.classList.remove('hidden');
      document.querySelectorAll('[data-main]').forEach(function (button) { button.classList.remove('active'); });
      document.getElementById('settingsNavBtn').classList.add('active');
      setTitle('Settings', 'Manage your account, dashboard token, and local CRM session.');
    }
    function hideSettings() {
      settingsSection.classList.add('hidden');
      var settingsButton = document.getElementById('settingsNavBtn');
      if (settingsButton) settingsButton.classList.remove('active');
    }

    document.querySelectorAll('[data-main]').forEach(function (button) { button.addEventListener('click', hideSettings); });
    document.getElementById('settingsNavBtn').addEventListener('click', showSettings);
    document.getElementById('settingsOpenCrm').addEventListener('click', function () {
      hideSettings();
      var crmButton = document.querySelector('[data-main="crm"]');
      if (crmButton) crmButton.click();
    });
    document.getElementById('settingsClearSession').addEventListener('click', function () {
      if (!confirm('Clear session-added CRM records and deletions from this browser?')) return;
      sessionStorage.removeItem('constravaCrmRecordsV2');
      sessionStorage.removeItem('constravaCrmDeletedV2');
      var crmButton = document.querySelector('[data-main="crm"]');
      if (crmButton) crmButton.click();
    });

    fetch('/api/auth/me', { cache: 'no-store' })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        var account = document.getElementById('settingsAccount');
        if (account) account.textContent = data && data.user && data.user.email ? data.user.email : 'Active dashboard session';
      })
      .catch(function () {
        var account = document.getElementById('settingsAccount');
        if (account) account.textContent = 'Active dashboard session';
      });
  }

  ready(function () {
    addGlobalStyles();

    var sources = document.getElementById('sources');
    var params = new URLSearchParams(location.search);
    var dashboardToken = params.get('token') || 'demo';
    installSidebarSettings(dashboardToken);
    if (!sources || document.getElementById('connectWebsiteGuide')) return;

    var currentStep = 0;
    var chatHistory = [];
    var stateKey = 'constravaWebsiteConnectCoachV1';
    var steps = [
      { title: 'Name the site', text: 'Tell Constrava which website you are connecting. Use the same site ID on every page of that one website.', tip: 'Example: Main company website, booking site, landing page, or client site.' },
      { title: 'Choose the platform', text: 'Pick the builder or platform your site uses so Constrava can give the safest install path.', tip: 'Squarespace usually uses Code Injection. WordPress often uses a header/footer plugin. Shopify usually starts with theme setup.' },
      { title: 'Copy the install line', text: 'Copy the official Constrava install line for this dashboard.', tip: 'The site ID is already included in the line below.' },
      { title: 'Paste once', text: 'Paste the install line into the site-wide custom code area, usually in the footer or before the closing body tag.', tip: 'Most users only do this once. The guide can help you find the right place.' },
      { title: 'Verify connection', text: 'Visit the live website, then return to Constrava and check that the first page view arrived.', tip: 'Use a private/incognito window if the platform hides custom code while you are logged in.' }
    ];

    function $(id) { return document.getElementById(id); }
    function readState() { try { return JSON.parse(localStorage.getItem(stateKey) || '{}') || {}; } catch { return {}; } }
    function writeState(next) { localStorage.setItem(stateKey, JSON.stringify(Object.assign(readState(), next || {}))); }
    function profile() {
      var saved = readState();
      return { siteUrl: $('cwSiteUrl') ? $('cwSiteUrl').value.trim() : saved.siteUrl || '', platform: $('cwPlatform') ? $('cwPlatform').value : saved.platform || '', installLine: installSnippet(dashboardToken) };
    }
    function updateCoachUi(result) {
      var saved = readState();
      if ($('cwInstallLine')) $('cwInstallLine').textContent = installSnippet(dashboardToken);
      if ($('cwPlatformStatus')) $('cwPlatformStatus').textContent = 'Platform: ' + (saved.platform || result?.platform || 'not set');
      if ($('cwStepStatus')) $('cwStepStatus').textContent = 'Next: ' + (result?.next_step || 'choose platform');
      if ($('cwAiStatus')) $('cwAiStatus').textContent = result?.ai === false ? 'Fallback guidance' : 'AI guide active';
      if ($('cwChecklist')) $('cwChecklist').innerHTML = (result?.checklist || []).map(function (item) { return '<div>' + escapeHtml(item) + '</div>'; }).join('');
    }
    function renderStep() {
      var step = steps[currentStep];
      if ($('cwStepTitle')) $('cwStepTitle').textContent = step.title;
      if ($('cwStepText')) $('cwStepText').textContent = step.text;
      if ($('cwStepTip')) $('cwStepTip').textContent = step.tip;
      if ($('cwStepCount')) $('cwStepCount').textContent = 'Step ' + (currentStep + 1) + ' of ' + steps.length;
      document.querySelectorAll('[data-cw-step]').forEach(function (button, index) { button.classList.toggle('primary', index === currentStep); });
    }
    function addChat(role, text) {
      var log = $('cwChatLog');
      if (!log) return;
      var bubble = document.createElement('div');
      bubble.style.padding = '10px 12px';
      bubble.style.borderRadius = '12px';
      bubble.style.margin = '8px 0';
      bubble.style.background = role === 'user' ? '#ecfdf5' : '#f8fafc';
      bubble.style.border = '1px solid #dbe8e4';
      bubble.innerHTML = '<b>' + (role === 'user' ? 'You' : 'Constrava AI Guide') + ':</b> ' + escapeHtml(text);
      log.appendChild(bubble);
      log.scrollTop = log.scrollHeight;
      chatHistory.push({ role: role, text: text });
      chatHistory = chatHistory.slice(-8);
    }
    function fallbackAnswer(message) {
      var lower = String(message || '').toLowerCase();
      var platform = String(profile().platform || '').toLowerCase();
      if (lower.includes('squarespace') || platform.includes('squarespace')) return 'For Squarespace, open Settings, go to Code Injection, paste the install line into Footer, save, then visit the live site once.';
      if (lower.includes('wordpress') || platform.includes('wordpress')) return 'For WordPress, use a trusted header/footer code tool or your theme footer area. Paste the install line once so it appears on every page.';
      if (lower.includes('shopify') || platform.includes('shopify')) return 'For Shopify, open Online Store, edit the active theme, and place the install line near the closing body tag. A custom pixel can come later.';
      if (lower.includes('webflow') || platform.includes('webflow')) return 'For Webflow, open Site Settings, Custom Code, paste the install line in Footer Code, publish, then visit the live domain.';
      if (lower.includes('wix') || platform.includes('wix')) return 'For Wix, use Settings, Custom Code, add the install line to all pages, place it in body end, then publish.';
      if (lower.includes('verify') || lower.includes('test')) return 'After saving, open the live site in a private window. Then return to Constrava and look for a recent page view.';
      return 'Tell me your website platform, and I will walk you through the exact place to paste the install line.';
    }
    async function askCoach(message) {
      var input = $('cwChatInput');
      var userMessage = message || (input ? input.value.trim() : '');
      if (!userMessage) return;
      if (input) input.value = '';
      addChat('user', userMessage);
      addChat('assistant', 'Thinking through the safest next step...');
      try {
        var response = await fetch('/api/connect-website-guide/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: userMessage, step: steps[currentStep], token: dashboardToken, profile: profile(), history: chatHistory })
        });
        var data = await response.json();
        var log = $('cwChatLog');
        if (log && log.lastChild) log.removeChild(log.lastChild);
        updateCoachUi(data);
        addChat('assistant', data.reply || fallbackAnswer(userMessage));
      } catch (err) {
        var chatLog = $('cwChatLog');
        if (chatLog && chatLog.lastChild) chatLog.removeChild(chatLog.lastChild);
        updateCoachUi({ ai: false, checklist: ['Copy the install line', 'Paste it site-wide', 'Publish or save', 'Visit the live site'] });
        addChat('assistant', fallbackAnswer(userMessage));
      }
    }

    var saved = readState();
    var section = document.createElement('section');
    section.id = 'connectWebsiteGuide';
    section.className = 'source-card';
    section.style.minHeight = 'auto';
    section.style.marginBottom = '16px';
    section.style.background = 'linear-gradient(135deg,#ffffff,#ecfdf5)';
    section.style.borderColor = 'rgba(16,185,129,.28)';
    section.innerHTML = [
      '<span class="badge">AI Partner</span>',
      '<h2>Connect a Website</h2>',
      '<p style="max-width:900px">Constrava stays with the user through setup: identify the platform, copy the install line, paste it in the right site-wide location, and verify the first page view.</p>',
      '<div class="cw-profile">',
        '<input class="field" id="cwSiteUrl" placeholder="Website URL" value="' + escapeHtml(saved.siteUrl || '') + '">',
        '<select class="field" id="cwPlatform"><option value="">Platform</option><option>Squarespace</option><option>WordPress</option><option>Shopify</option><option>Webflow</option><option>Wix</option><option>Google Tag Manager</option><option>Custom HTML</option><option>Not sure</option></select>',
        '<button class="btn primary" id="cwCoachStart" type="button">Ask AI Guide</button>',
      '</div>',
      '<div class="cw-code"><code id="cwInstallLine"></code><button class="btn tiny" id="cwCopySnippet" type="button">Copy</button></div>',
      '<div class="cw-status"><span id="cwPlatformStatus">Platform: not set</span><span id="cwStepStatus">Next: choose platform</span><span id="cwAiStatus">AI guide ready</span></div>',
      '<div class="cw-checklist" id="cwChecklist"></div>',
      '<div class="source-grid" style="margin-top:16px;grid-template-columns:1.1fr .9fr">',
        '<article class="source-card" style="min-height:auto;box-shadow:none">',
          '<span class="badge" id="cwStepCount">Step 1 of 5</span>',
          '<h2 id="cwStepTitle">Name the site</h2>',
          '<p id="cwStepText">Tell Constrava which website you are connecting.</p>',
          '<p class="hint" id="cwStepTip" style="margin-top:10px"></p>',
          '<div class="crm-actions" style="margin-top:14px">',
            '<button class="btn tiny" data-cw-step="0">1</button>',
            '<button class="btn tiny" data-cw-step="1">2</button>',
            '<button class="btn tiny" data-cw-step="2">3</button>',
            '<button class="btn tiny" data-cw-step="3">4</button>',
            '<button class="btn tiny" data-cw-step="4">5</button>',
            '<button class="btn tiny" id="cwPrev">Back</button>',
            '<button class="btn tiny primary" id="cwNext">Next</button>',
            '<a class="btn tiny dark" href="/analytics/install?token=' + encodeURIComponent(dashboardToken) + '" target="_blank" rel="noopener">Open install helper</a>',
          '</div>',
        '</article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none">',
          '<span class="badge">Always-on help</span>',
          '<h2>Ask the setup guide</h2>',
          '<div id="cwChatLog" style="height:210px;overflow:auto;margin:10px 0;padding:8px;border:1px solid #dbe8e4;border-radius:12px;background:#fff"></div>',
          '<div class="crm-actions"><input class="field" id="cwChatInput" placeholder="Ask: Where do I paste this on Squarespace?" style="flex:1;min-width:220px"><button class="btn primary" id="cwChatSend">Send</button></div>',
        '</article>',
      '</div>',
      '<div class="source-grid" style="margin-top:16px">',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">Squarespace</span><h2>Use Code Injection</h2><p>Open Settings, find Code Injection, paste the install line into Footer, save, then visit the live site.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">WordPress</span><h2>Use header/footer tools</h2><p>Paste the install line into a trusted header/footer plugin or the theme footer code area.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">Shopify</span><h2>Use theme setup</h2><p>Paste the line into your theme/body-end code area. A true app-style pixel can come later.</p></article>',
      '</div>'
    ].join('');

    sources.insertBefore(section, sources.firstChild);
    if (saved.platform && $('cwPlatform')) $('cwPlatform').value = saved.platform;
    updateCoachUi({ checklist: ['Choose platform', 'Copy install line', 'Paste site-wide', 'Publish and verify'] });
    renderStep();
    addChat('assistant', 'I am here while you connect your website. Choose a platform or tell me where you are stuck.');

    $('cwSiteUrl').addEventListener('input', function () { writeState({ siteUrl: this.value.trim() }); updateCoachUi(); });
    $('cwPlatform').addEventListener('change', function () { writeState({ platform: this.value }); updateCoachUi(); askCoach('My platform is ' + (this.value || 'not sure') + '. What should I do next?'); });
    $('cwCoachStart').addEventListener('click', function () { askCoach('Help me connect this website.'); });
    $('cwCopySnippet').addEventListener('click', async function () {
      try { await navigator.clipboard.writeText(installSnippet(dashboardToken)); addChat('assistant', 'Copied. Now paste that line once in your site-wide footer or body-end code area.'); }
      catch { addChat('assistant', 'Copy this install line: ' + installSnippet(dashboardToken)); }
    });
    document.querySelectorAll('[data-cw-step]').forEach(function (button) { button.addEventListener('click', function () { currentStep = Number(button.dataset.cwStep || 0); renderStep(); }); });
    $('cwPrev').addEventListener('click', function () { currentStep = Math.max(0, currentStep - 1); renderStep(); });
    $('cwNext').addEventListener('click', function () { currentStep = Math.min(steps.length - 1, currentStep + 1); renderStep(); });
    $('cwChatSend').addEventListener('click', function () { askCoach(); });
    $('cwChatInput').addEventListener('keydown', function (event) { if (event.key === 'Enter') askCoach(); });
  });
})();
