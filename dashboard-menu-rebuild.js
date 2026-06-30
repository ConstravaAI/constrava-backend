(function(){
  if (window.__constravaDashboardMenuRebuilt) return;
  window.__constravaDashboardMenuRebuilt = true;

  var token = new URLSearchParams(location.search).get('token') || 'demo';
  var menuStateKey = 'constravaDashboardMenuOpen:';
  var sidebarHiddenKey = 'constravaDashboardSidebarHidden';
  var activeMain = 'analytics';
  var activeSection = 'home';

  function $(sel){ return document.querySelector(sel); }
  function $all(sel){ return Array.prototype.slice.call(document.querySelectorAll(sel)); }
  function openState(id){ var saved = localStorage.getItem(menuStateKey + id); return saved === null ? true : saved === '1'; }
  function setOpenState(id, open){ localStorage.setItem(menuStateKey + id, open ? '1' : '0'); }
  function sidebarHidden(){ return localStorage.getItem(sidebarHiddenKey) === '1'; }
  function setSidebarHidden(hidden){ localStorage.setItem(sidebarHiddenKey, hidden ? '1' : '0'); applySidebarHidden(); }
  function toggleSidebar(){ setSidebarHidden(!sidebarHidden()); }

  function setMain(main){
    activeMain = main || 'analytics';
    var analytics = $('#analytics');
    var crm = $('#crm');
    if (analytics) analytics.classList.toggle('hidden', activeMain !== 'analytics');
    if (crm) crm.classList.toggle('hidden', activeMain !== 'crm');
    $all('.tab[data-main]').forEach(function(btn){ btn.classList.toggle('active', btn.getAttribute('data-main') === activeMain); });
    updateActive();
  }

  function setSection(section){
    activeSection = section || 'home';
    setMain('analytics');
    $all('#analytics .section').forEach(function(sec){ sec.classList.add('hidden'); });
    var target = $('#section-' + activeSection);
    if (target) target.classList.remove('hidden');
    updateActive();
  }

  function openCrm(){
    setMain('crm');
    var customBtn = document.querySelector('[data-simple-tab="all"], [data-simple-tab="lead"], .crm-top [data-crm="dashboards"], .crm-top [data-crm="leads"], .crm-top [data-crm="home"]');
    if (customBtn) customBtn.click();
  }

  function updateActive(){
    $all('.cx-menu-item').forEach(function(btn){
      var main = btn.getAttribute('data-cx-main');
      var section = btn.getAttribute('data-cx-section');
      var active = false;
      if (section) active = activeMain === 'analytics' && activeSection === section;
      else if (main === 'crm') active = activeMain === 'crm';
      btn.classList.toggle('active', active);
    });
  }

  function menuHtml(){
    var analyticsOpen = openState('analytics') ? ' open' : '';
    return '<div class="cx-menu-brand"><div class="cx-menu-mark">//</div><div><b>CONSTRAVA</b><span>Dashboard</span></div></div>' +
      '<div class="cx-menu-label">Menu</div>' +
      '<details class="cx-menu-group" data-cx-menu-group="analytics"' + analyticsOpen + '>' +
        '<summary><span>📈 Analytics</span><em></em></summary>' +
        '<button class="cx-menu-item active" type="button" data-cx-section="home">Home</button>' +
        '<button class="cx-menu-item" type="button" data-cx-section="realtime">Realtime</button>' +
        '<button class="cx-menu-item" type="button" data-cx-section="acquisition">Acquisition</button>' +
        '<button class="cx-menu-item" type="button" data-cx-section="engagement">Engagement</button>' +
        '<button class="cx-menu-item" type="button" data-cx-section="monetization">Monetization</button>' +
      '</details>' +
      '<button class="cx-menu-item cx-menu-main-button" type="button" data-cx-main="crm">🧩 CRM</button>' +
      '<div class="cx-menu-footer">Token: ' + String(token).slice(0,8) + '…</div>';
  }

  function installStyles(){
    if ($('#cxDashboardMenuRebuildStyle')) return;
    var style = document.createElement('style');
    style.id = 'cxDashboardMenuRebuildStyle';
    style.textContent = '.side.cx-menu-rebuilt{padding:24px 18px!important;background:#071426!important;background-image:none!important}.side.cx-menu-rebuilt .brand,.side.cx-menu-rebuilt>.navbtn,.side.cx-menu-rebuilt>.navtitle{display:none!important}.cx-menu-brand{display:flex;align-items:center;gap:13px;margin-bottom:26px;color:#eafff7}.cx-menu-brand b{display:block;letter-spacing:.22em;font-weight:950}.cx-menu-brand span{display:block;color:rgba(236,253,245,.62);font-size:12px;margin-top:3px}.cx-menu-mark{width:44px;height:44px;border-radius:14px;background:#14b8a6!important;background-image:none!important;display:grid;place-items:center;color:#022c22;font-weight:950;transform:skew(-10deg)}.cx-menu-label{margin:0 8px 12px;color:rgba(236,253,245,.62);font-size:11px;font-weight:950;letter-spacing:.14em;text-transform:uppercase}.cx-menu-group{border:1px solid rgba(167,243,208,.16);border-radius:18px;background:rgba(255,255,255,.045);margin:12px 0;overflow:hidden}.cx-menu-group summary{list-style:none;display:flex;justify-content:space-between;align-items:center;padding:14px 15px;color:#eafff7;font-weight:950;cursor:pointer}.cx-menu-group summary::-webkit-details-marker{display:none}.cx-menu-group summary em:before{content:"▸";font-style:normal;color:#a7f3d0}.cx-menu-group[open] summary em:before{content:"▾"}.cx-menu-group[open] summary{background:rgba(20,184,166,.20)}.cx-menu-item{display:block;width:calc(100% - 18px);margin:6px 9px;border:0;border-radius:13px;padding:11px 13px;background:transparent;color:rgba(236,253,245,.82);font-weight:850;text-align:left}.cx-menu-main-button{width:100%!important;margin:12px 0!important;border:1px solid rgba(167,243,208,.16)!important;border-radius:18px!important;padding:14px 15px!important;background:rgba(255,255,255,.045)!important;color:#eafff7!important;font-weight:950!important}.cx-menu-item:hover,.cx-menu-item.active,.cx-menu-main-button:hover,.cx-menu-main-button.active{background:rgba(20,184,166,.22)!important;background-image:none!important;color:#fff!important;box-shadow:inset 3px 0 0 #5eead4}.cx-menu-footer{margin:22px 9px 0;color:rgba(236,253,245,.45);font-size:11px;font-weight:800}.cx-sidebar-dot-toggle{position:fixed;left:18px;top:18px;z-index:120;width:42px;height:42px;border:1px solid rgba(20,184,166,.32);border-radius:999px;background:#071426;color:#ecfdf5;box-shadow:0 18px 50px rgba(2,8,23,.28);font-size:22px;line-height:1;font-weight:950;display:inline-grid;place-items:center;padding:0}.cx-sidebar-dot-toggle:hover{background:#0f2a44;transform:translateY(-1px)}.app.cx-sidebar-hidden{grid-template-columns:1fr!important}.app.cx-sidebar-hidden .side{display:none!important}.app.cx-sidebar-hidden .main{padding-left:76px!important}.side.cx-menu-rebuilt{padding-top:78px!important}@media(max-width:900px){.app{grid-template-columns:1fr!important}.side.cx-menu-rebuilt{position:relative!important;height:auto!important}.main{padding-top:20px!important}.app.cx-sidebar-hidden .main{padding-left:20px!important}.cx-sidebar-dot-toggle{left:14px;top:14px}}';
    document.head.appendChild(style);
  }

  function ensureDotToggle(){
    var app = $('.app');
    if (!app) return;
    var btn = $('#cxSidebarDotToggle');
    if (!btn) {
      btn = document.createElement('button');
      btn.id = 'cxSidebarDotToggle';
      btn.type = 'button';
      btn.className = 'cx-sidebar-dot-toggle';
      btn.textContent = '⋯';
      btn.setAttribute('aria-label', 'Toggle sidebar');
      btn.addEventListener('click', toggleSidebar);
      document.body.appendChild(btn);
    }
  }

  function applySidebarHidden(){
    var app = $('.app');
    if (!app) return;
    app.classList.toggle('cx-sidebar-hidden', sidebarHidden());
  }

  function rebuild(){
    var side = $('.side');
    if (!side) return false;
    installStyles();
    side.classList.add('cx-menu-rebuilt');
    side.innerHTML = menuHtml();
    ensureDotToggle();

    $all('.cx-menu-group').forEach(function(group){
      group.addEventListener('toggle', function(){ setOpenState(group.getAttribute('data-cx-menu-group'), group.open); });
    });
    $all('[data-cx-section]').forEach(function(btn){
      btn.addEventListener('click', function(){ setSection(btn.getAttribute('data-cx-section')); });
    });
    $all('[data-cx-main="crm"]').forEach(function(btn){
      btn.addEventListener('click', openCrm);
    });
    setSection('home');
    applySidebarHidden();
    return true;
  }

  var tries = 0;
  var timer = setInterval(function(){
    tries++;
    if (rebuild() || tries > 20) clearInterval(timer);
  }, 150);
  window.addEventListener('load', rebuild);
})();
