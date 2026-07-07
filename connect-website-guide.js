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

    var section = document.createElement('section');
    section.id = 'connectWebsiteGuide';
    section.className = 'source-card';
    section.style.minHeight = 'auto';
    section.style.marginBottom = '16px';
    section.style.background = 'linear-gradient(135deg,#ffffff,#ecfdf5)';
    section.style.borderColor = 'rgba(16,185,129,.28)';

    section.innerHTML = [
      '<span class="badge">AI Guide</span>',
      '<h2>Connect a Website</h2>',
      '<p style="max-width:900px">No stress, no developer words first. Constrava will guide you one step at a time, give you the right install line, and then help confirm that your website is connected.</p>',
      '<div class="source-grid" style="margin-top:16px">',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">1</span><h2>Name the site</h2><p>Pick the website you want to connect. One site gets one Constrava site ID.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">2</span><h2>Choose the platform</h2><p>Squarespace, WordPress, Shopify, Wix, Webflow, Framer, or custom HTML. Constrava points you to the safest install path.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">3</span><h2>Paste once</h2><p>Most sites only need one small install line added to a footer, header, theme, tag manager, or custom-code area.</p></article>',
      '</div>',
      '<div class="panel" style="margin:16px 0 0">',
        '<div class="panel-head"><h3>Your official install helper</h3><a class="btn tiny primary" href="' + escapeHtml(installUrl) + '" target="_blank" rel="noopener">Open install line</a></div>',
        '<div class="panel-body"><p class="hint">You do not need to write code. Open the install line, copy it, paste it into your website platform, then visit your live site once so Constrava can see the first page view.</p></div>',
      '</div>',
      '<div class="source-grid" style="margin-top:16px">',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">Squarespace</span><h2>Use Code Injection</h2><p>Open Settings, find Code Injection, paste the install line into Footer, save, then visit the live site.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">WordPress</span><h2>Use header/footer tools</h2><p>Paste the install line into a trusted header/footer plugin or the theme footer code area.</p></article>',
        '<article class="source-card" style="min-height:auto;box-shadow:none"><span class="badge">Shopify</span><h2>Use theme setup</h2><p>For now, paste the line into your theme/custom-code area. A true app-style pixel can come later.</p></article>',
      '</div>'
    ].join('');

    sources.insertBefore(section, sources.firstChild);
  });
})();
