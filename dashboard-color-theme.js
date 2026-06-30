(function(){
  if (window.__constravaColorThemeLoaded) return;
  window.__constravaColorThemeLoaded = true;

  var style = document.createElement('style');
  style.id = 'constrava-color-theme';
  style.textContent = `
:root{
  --green:#14b8a6!important;
  --green2:#0f766e!important;
  --mint:#ccfbf1!important;
  --dark:#0f172a!important;
  --ink:#0f172a!important;
  --muted:#64748b!important;
  --line:#dbe4ee!important;
  --crmTop:#111827!important;
  --crmBlue:#14b8a6!important;
  --shadow:0 18px 45px rgba(15,23,42,.08)!important;
}
body{
  color:#0f172a!important;
  background:radial-gradient(circle at 18% 0,rgba(20,184,166,.13),transparent 32%),linear-gradient(135deg,#f8fafc,#eef4f8 48%,#ffffff)!important;
}
.side,.side.cx-menu-rebuilt{
  background:linear-gradient(180deg,#111827,#0f172a 58%,#020617)!important;
  color:#e5f4f3!important;
  box-shadow:20px 0 70px rgba(15,23,42,.24)!important;
}
.cx-menu-brand,.brand{color:#f8fafc!important;}
.cx-menu-mark,.mark{
  background:linear-gradient(135deg,#5eead4,#14b8a6)!important;
  color:#042f2e!important;
}
.cx-menu-label,.navtitle,.cx-menu-footer{color:rgba(226,232,240,.58)!important;}
.cx-menu-group{
  border-color:rgba(148,163,184,.18)!important;
  background:rgba(255,255,255,.045)!important;
}
.cx-menu-group[open] summary,
.cx-menu-item:hover,
.cx-menu-item.active,
.cx-menu-main-button:hover,
.cx-menu-main-button.active,
.navbtn.active,
.navbtn:hover{
  background:linear-gradient(90deg,rgba(20,184,166,.30),rgba(59,130,246,.10))!important;
  color:#f8fafc!important;
  box-shadow:inset 3px 0 0 #5eead4!important;
}
.cx-menu-group summary,
.cx-menu-main-button,
.navbtn{color:rgba(248,250,252,.86)!important;}
.cx-sidebar-dot-toggle{
  background:#111827!important;
  color:#ccfbf1!important;
  border-color:rgba(20,184,166,.35)!important;
  box-shadow:0 18px 50px rgba(15,23,42,.24)!important;
}
.cx-sidebar-dot-toggle:hover{background:#0f766e!important;}
.card,.crm-panel,.crm-kpi,.cx-simple-card,.cx-simple-row,.activity-row,.deal,.crm-col{
  background:#ffffff!important;
  border-color:#dbe4ee!important;
  box-shadow:0 14px 34px rgba(15,23,42,.06)!important;
}
.hero h1,.head h2,.head h3,.cx-simple-card h2,.cx-simple-card h3,.cx-simple-row h4,.crm-hero h2{
  color:#0f172a!important;
}
.hero p,.head p,.cx-simple-card p,.cx-simple-row p,.crm-panel-body,.crm-left button,.activity-row span,.activity-row em{
  color:#64748b!important;
}
.status,.pill,.cx-simple-pill,.trend{
  background:#ccfbf1!important;
  color:#0f766e!important;
  border-color:rgba(20,184,166,.22)!important;
}
.btn:hover,.tab.active{
  color:#0f766e!important;
  border-color:rgba(20,184,166,.35)!important;
}
.tab.active{
  box-shadow:inset 0 -2px 0 #14b8a6,0 10px 24px rgba(20,184,166,.12)!important;
}
.fill,.crm-primary,.cx-workflow-btn,.cx-titlebar-ai-btn{
  background:linear-gradient(135deg,#14b8a6,#0f766e)!important;
  color:#ecfeff!important;
  border-color:#14b8a6!important;
}
.chart{
  background:radial-gradient(circle at 20% 18%,rgba(20,184,166,.28),transparent 28%),radial-gradient(circle at 84% 16%,rgba(59,130,246,.14),transparent 32%),linear-gradient(135deg,#0f172a 0%,#111827 48%,#020617 100%)!important;
  border-color:rgba(148,163,184,.18)!important;
}
.line{stroke:#5eead4!important;filter:drop-shadow(0 0 10px rgba(20,184,166,.75))!important;}
.dot{stroke:#14b8a6!important;fill:#ecfeff!important;}
.area{opacity:.72!important;}
.crm-top.cx-simple-titlebar,.crm-top{
  background:linear-gradient(135deg,#111827,#0f172a)!important;
  color:#f8fafc!important;
}
.crm-left{
  background:#f8fafc!important;
  border-right-color:#dbe4ee!important;
}
.crm-left button.active,.crm-left button:hover,.cx-simple-side-btn.active,.cx-simple-side-btn:hover{
  background:#ccfbf1!important;
  color:#0f766e!important;
}
.cx-titlebar-ai-input,.cx-workflow-textarea,.cx-simple-input,.crm-search{
  border-color:#cbd5e1!important;
  background:#f8fafc!important;
  color:#0f172a!important;
}
.cx-titlebar-ai-input{
  background:rgba(255,255,255,.10)!important;
  color:#f8fafc!important;
  border-color:rgba(255,255,255,.22)!important;
}
.cx-titlebar-ai-input::placeholder{color:rgba(226,232,240,.70)!important;}
.cx-workflow-tool-grid button:hover{
  border-color:#14b8a6!important;
  background:#f0fdfa!important;
}
`;
  document.head.appendChild(style);
})();
