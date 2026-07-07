import fs from "fs";

const serverFile = "server.js";
if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;
  function replaceAllSafe(search, replacement) {
    if (!source.includes(search)) return false;
    source = source.split(search).join(replacement);
    return true;
  }

  if (replaceAllSafe('app.use(express.static(__dirname));', 'app.use(express.static(__dirname, { redirect: false }));')) changed = true;

  const oldDashboardUrl = 'dashboard_url: `/dashboard?token=${encodeURIComponent(dashboardToken)}`';
  const newDashboardUrl = 'dashboard_url: `${CANONICAL_ORIGIN}/dashboard`';
  if (replaceAllSafe(oldDashboardUrl, newDashboardUrl)) changed = true;

  const olderDashboardUrl = 'dashboard_url: `${CANONICAL_ORIGIN}/dashboard/?token=${encodeURIComponent(dashboardToken)}&mode=private`';
  if (replaceAllSafe(olderDashboardUrl, newDashboardUrl)) changed = true;

  if (changed) fs.writeFileSync(serverFile, source);
}

const dashboardFile = "dashboard.html";
if (fs.existsSync(dashboardFile)) {
  let html = fs.readFileSync(dashboardFile, "utf8");
  let changed = false;
  function patch(search, replacement) {
    if (!html.includes(search)) return;
    html = html.replace(search, replacement);
    changed = true;
  }

  patch('<div class="app">', '<div class="app" id="appShell">');
  patch('<div class="brand"><div class="mark">∕∕</div><div>CONSTRAVA</div></div>', '<div class="brand"><div class="mark">∕∕</div><div class="brand-text">CONSTRAVA</div></div><button class="sidebar-toggle" type="button" onclick="var s=document.getElementById(\'appShell\');s.classList.toggle(\'sidebar-collapsed\');this.textContent=s.classList.contains(\'sidebar-collapsed\')?\'›\':\'‹\';">‹</button>');
  patch('<button class="navbtn active" data-main="analytics">Analytics</button>', '<button class="navbtn active" data-main="analytics" data-short="A"><span>Analytics</span></button>');
  patch('<button class="navbtn" data-main="crm">CRM</button>', '<button class="navbtn" data-main="crm" data-short="C"><span>CRM</span></button>');
  patch('<button class="navbtn" data-main="sources">Outside Sources</button>', '<button class="navbtn" data-main="sources" data-short="O"><span>Outside Sources</span></button>');

  const cssMarker = '@media(max-width:1200px)';
  const cssAdd = '.app{transition:grid-template-columns .22s ease}.app.sidebar-collapsed{grid-template-columns:78px 1fr}.sidebar-toggle{width:100%;height:40px;margin:0 0 16px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.08);color:#ecfdf5;border-radius:12px;font-weight:950;font-size:20px}.app.sidebar-collapsed .side{padding:22px 12px}.app.sidebar-collapsed .brand{justify-content:center;margin-bottom:16px}.app.sidebar-collapsed .brand-text{display:none}.app.sidebar-collapsed .navbtn{padding:13px 0;text-align:center}.app.sidebar-collapsed .navbtn span{display:none}.app.sidebar-collapsed .navbtn::after{content:attr(data-short);font-size:14px}';
  if (!html.includes('.app.sidebar-collapsed{grid-template-columns') && html.includes(cssMarker)) {
    html = html.replace(cssMarker, cssAdd + cssMarker);
    changed = true;
  }

  const crmSearch = "loadCrmData();\n  </script>";
  const crmReplacement = "loadCrmData();\n    switchMain('crm');\n  </script>";
  if (!html.includes(crmReplacement) && html.includes(crmSearch)) {
    html = html.replace(crmSearch, crmReplacement);
    changed = true;
  }

  if (changed) fs.writeFileSync(dashboardFile, html);
}
