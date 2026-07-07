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
  const cssAdd = '.app{transition:grid-template-columns .22s ease}.app.sidebar-collapsed{grid-template-columns:58px 1fr}.sidebar-toggle{width:28px;height:28px;margin:-8px 0 18px auto;display:grid;place-items:center;border:0;background:rgba(255,255,255,.06);color:rgba(236,253,245,.72);border-radius:999px;font-weight:900;font-size:18px;line-height:1;box-shadow:none}.sidebar-toggle:hover{background:rgba(255,255,255,.12);color:#ecfdf5}.app.sidebar-collapsed .side{padding:22px 10px}.app.sidebar-collapsed .brand{justify-content:center;margin-bottom:18px}.app.sidebar-collapsed .brand-text{display:none}.app.sidebar-collapsed .mark{width:32px;height:32px;border-radius:10px}.app.sidebar-collapsed .sidebar-toggle{margin:0 auto 18px}.app.sidebar-collapsed .navbtn{display:none}';
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
