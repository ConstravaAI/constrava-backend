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

  ready(function () {
    var sources = document.getElementById('sources');
    if (!sources || document.getElementById('connectWebsiteGuide')) return;

    var params = new URLSearchParams(location.search);
    var dashboardToken = params.get('token') || 'demo';
    var installUrl = '/analytics/install?token=' + encodeURIComponent(dashboardToken);
    var currentStep = 0;
    var steps = [
      { title: 'Name the site', text: 'Tell Constrava which website you are connecting. Use the same site ID on every page of that one website.', tip: 'Example: Main company website, booking site, landing page, or client site.' },
      { title: 'Choose the platform', text: 'Pick the builder or platform your site uses so Constrava can give the safest install path.', tip: 'Squarespace usually uses Code Injection. WordPress often uses a header/footer plugin. Shopify usually starts with theme setup.' },
      { title: 'Copy the install line', text: 'Open the install helper and copy the official Constrava install line for this dashboard.', tip: 'The site ID is already included when you open the helper from this dashboard.' },
      { title: 'Paste once', text: 'Paste the install line into the site-wide custom code area, usually in the footer or before the closing body tag.', tip: 'Most users only do this once. The guide can help you find the right place.' },
      { title: 'Verify connection', text: 'Visit the live website, then return to Constrava and check that the first page view arrived.', tip: 'Use a private/incognito window if the platform hides custom code while you are logged in.' }
    ];

    function renderStep() {
      var step = steps[currentStep];
      var title = document.getElementById('cwStepTitle');
      var text = document.getElementById('cwStepText');
      var tip = document.getElementById('cwStepTip');
      var count = document.getElementById('cwStepCount');
      if (!title || !text || !tip || !count) return;
      title.textContent = step.title;
      text.textContent = step.text;
      tip.textContent = step.tip;
      count.textContent = 'Step ' + (currentStep + 1) + ' of ' + steps.length;
      document.querySelectorAll('[data-cw-step]').forEach(function (button, index) {
        button.classList.toggle('primary', index === currentStep);
      });
    }

    function addChat(role, text) {
      var log = document.getElementById('cwChatLog');
      if (!log) return;
      var bubble = document.createElement('div');
      bubble.style.padding = '10px 12px';
      bubble.style.borderRadius = '12px';
      bubble.style.margin = '8px 0';
      bubble.style.background = role === 'user' ? '#ecfdf5' : '#f8fafc';
      bubble.style.border = '1px solid #dbe8e4';
      bubble.innerHTML = '<b>' + (role === 'user' ? 'You' : 'Constrava Guide') + ':</b> ' + escapeHtml(text);
      log.appendChild(bubble);
      log.scrollTop = log.scrollHeight;
    }

    function fallbackAnswer(message) {
      var lower = String(message || '').toLowerCase();
      if (lower.includes('squarespace')) return 'For Squarespace, open Settings, go to Code Injection, paste the install line into Footer, save, then visit the live site once.';
      if (lower.includes('wordpress')) return 'For WordPress, use a trusted header/footer code tool or your theme footer area. Paste the install line once so it appears on every page.';
      if (lower.includes('shopify')) return 'For Shopify, start with the theme/custom-code setup. A deeper app-style pixel can come later, but the first version can use the install line.';
      if (lower.includes('where') || lower.includes('paste')) return 'Look for a site-wide custom code, footer code, header/footer, code injection, tag manager, or theme code area. The goal is to load the line on every public page.';
      if (lower.includes('verify') || lower.includes('test')) return 'After saving, open the live site in a private window. Then return to Constrava and look for a recent page view for this site.';
      return 'I can help with that. Start with the current step, tell me your website platform, and I will keep the instructions simple and code-light.';
    }

    async function sendChat() {
      var input = document.getElementById('cwChatInput');
      if (!input) return;
      var message = input.value.trim();
      if (!message) return;
      input.value = '';
      addChat('user', message);
      addChat('assistant', 'Checking the best next step...');
      try {
        var response = await fetch('/api/connect-website-guide/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: message, step: steps[currentStep], token: dashboardToken })
        });
        var data = await response.json();
        var log = document.getElementById('cwChatLog');
        if (log && log.lastChild) log.removeChild(log.lastChild);
        addChat('assistant', data.reply || fallbackAnswer(message));
      } catch (err) {
        var chatLog = document.getElementById('cwChatLog');
        if (chatLog && chatLog.lastChild) chatLog.removeChild(chatLog.lastChild);
        addChat('assistant', fallbackAnswer(message));
      }
    }

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
      '<p style="max-width:900px">No stress, no developer words first. Constrava stays with you through each step, explains the exact next move, and helps you avoid getting stuck.</p>',
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
            '<a class="btn tiny dark" href="' + escapeHtml(installUrl) + '" target="_blank" rel="noopener">Open install helper</a>',
          '</div>',
        '</article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none">',
          '<span class="badge">Always-on help</span>',
          '<h2>Ask the setup guide</h2>',
          '<div id="cwChatLog" style="height:180px;overflow:auto;margin:10px 0;padding:8px;border:1px solid #dbe8e4;border-radius:12px;background:#fff"></div>',
          '<div class="crm-actions"><input class="field" id="cwChatInput" placeholder="Ask: Where do I paste this on Squarespace?" style="flex:1;min-width:220px"><button class="btn primary" id="cwChatSend">Send</button></div>',
        '</article>',
      '</div>',
      '<div class="source-grid" style="margin-top:16px">',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">Squarespace</span><h2>Use Code Injection</h2><p>Open Settings, find Code Injection, paste the install line into Footer, save, then visit the live site.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">WordPress</span><h2>Use header/footer tools</h2><p>Paste the install line into a trusted header/footer plugin or the theme footer code area.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">Shopify</span><h2>Use theme setup</h2><p>For now, paste the line into your theme/custom-code area. A true app-style pixel can come later.</p></article>',
      '</div>'
    ].join('');

    sources.insertBefore(section, sources.firstChild);
    renderStep();
    addChat('assistant', 'I am here while you connect your website. Tell me your platform, or click through the steps on the left.');

    document.querySelectorAll('[data-cw-step]').forEach(function (button) {
      button.addEventListener('click', function () { currentStep = Number(button.dataset.cwStep || 0); renderStep(); });
    });
    document.getElementById('cwPrev').addEventListener('click', function () { currentStep = Math.max(0, currentStep - 1); renderStep(); });
    document.getElementById('cwNext').addEventListener('click', function () { currentStep = Math.min(steps.length - 1, currentStep + 1); renderStep(); });
    document.getElementById('cwChatSend').addEventListener('click', sendChat);
    document.getElementById('cwChatInput').addEventListener('keydown', function (event) { if (event.key === 'Enter') sendChat(); });
  });
})();
