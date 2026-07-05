import fs from "fs";

const file = "dashboard.html";
if (!fs.existsSync(file)) {
  console.warn("[crm-dark-square-settings-patch] dashboard.html not found; skipping.");
  process.exit(0);
}

let html = fs.readFileSync(file, "utf8");
let changed = false;

const styleMarker = "__crmDarkSquareSettings_v1_styles";
if (!html.includes(styleMarker)) {
  const styles = String.raw`
<style id="__crmDarkSquareSettings_v1_styles">
  :root{--green:#22c55e;--green2:#16a34a;--mint:#86efac;--dark:#020617;--ink:#e5e7eb;--muted:#94a3b8;--line:#1e293b;--crmTop:#020617;--crmBlue:#22c55e;--shadow:0 18px 45px rgba(0,0,0,.34)}
  body{color:#e5e7eb!important;background:radial-gradient(circle at 18% 0,rgba(34,197,94,.16),transparent 28%),linear-gradient(135deg,#020617,#07110d 46%,#030712)!important}
  .main{background:linear-gradient(135deg,rgba(2,6,23,.82),rgba(2,6,23,.96))}.side{background:linear-gradient(180deg,#020617,#07130f 58%,#000);box-shadow:16px 0 54px rgba(0,0,0,.45)}
  .hero h1,.head h2,.head h3,.crm-hero h2,.crm-panel h3,.card h2,.card h3,.value,.crm-kpi strong{color:#f8fafc!important}.hero p,.head p,.crm-hero p,.crm-panel-body,.activity-row span,.activity-row em,.barrow strong,.records td,.records th{color:#cbd5e1!important}
  .card,.tabs,.btn,.select,.status,.crm-shell,.crm-left,.crm-main,.crm-panel,.crm-kpi,.deal,.activity-row,.modal .box,.toast,.box{background:#0f172a!important;border-color:#1e293b!important;color:#e5e7eb!important;box-shadow:0 18px 45px rgba(0,0,0,.34)!important}
  .tabs{background:#020617!important}.tab{color:#cbd5e1!important}.tab.active{background:#111827!important;color:#86efac!important;box-shadow:inset 0 -2px 0 #22c55e!important}.btn,.select,.crm-btn{background:#111827!important;color:#e5e7eb!important;border-color:#334155!important}.crm-primary{background:#16a34a!important;border-color:#22c55e!important;color:#fff!important}.status{background:#052e1b!important;color:#86efac!important}.crm-top{background:#020617!important;border-bottom:1px solid #1e293b}.crm-top button.active,.crm-top button:hover,.navbtn.active,.navbtn:hover{background:#111827!important;color:#86efac!important}.crm-left{background:#020617!important}.crm-left button{color:#cbd5e1!important}.crm-left button.active,.crm-left button:hover{background:#0f2b1d!important;color:#86efac!important}.records table,.records tr,.records td,.records th{background:#0f172a!important;border-color:#1e293b!important}.crm-search,input,select,textarea{background:#020617!important;color:#e5e7eb!important;border-color:#334155!important}.pill{background:#052e1b!important;color:#86efac!important}.track{background:#1e293b!important}.fill{background:linear-gradient(90deg,#15803d,#22c55e)!important}.chart{background:radial-gradient(circle at 20% 18%,rgba(34,197,94,.22),transparent 28%),linear-gradient(135deg,#020617,#061a12 54%,#020617)!important;border-color:#1e293b!important}.crm-stage{color:#ecfdf5!important}.donut:after{background:#0f172a!important}.empty{color:#94a3b8!important}
  .card,.tabs,.tab,.btn,.select,.status,.chart,.frow,.activity-row,.activity-icon,.toast,.modal,.box,.close,.crm-shell,.crm-left,.crm-search,.crm-left button,.crm-panel,.crm-kpi,.crm-btn,.deal,.crm-col,.pill,.track,.bar,.semantic-ai-builder,#aiEditRecordsPanel,#aiEditRecordsLauncher,.ai-edit-card,.ai-edit-inline{border-radius:2px!important}
  .settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.settings-card{background:#0f172a;border:1px solid #1e293b;border-radius:2px;padding:18px;box-shadow:0 18px 45px rgba(0,0,0,.32)}.settings-card h3{margin:0 0 8px;color:#f8fafc}.settings-card p{margin:0;color:#94a3b8;font-size:13px;line-height:1.5}.settings-tag{display:inline-flex;margin-top:12px;border:1px solid #14532d;background:#052e1b;color:#86efac;border-radius:2px;padding:6px 9px;font-size:12px;font-weight:900}.settings-wide{grid-column:1/-1}.settings-list{display:grid;gap:8px;margin-top:12px}.settings-row{display:flex;justify-content:space-between;gap:12px;border-top:1px solid #1e293b;padding-top:10px;color:#cbd5e1}.settings-row strong{color:#f8fafc}.settings-note{border-left:3px solid #22c55e;background:#052e1b;color:#dcfce7;padding:12px;margin-top:14px}
  @media(max-width:900px){.settings-grid{grid-template-columns:1fr}.settings-wide{grid-column:auto}}
</style>`;
  html = html.includes("</head>") ? html.replace("</head>", styles + "\n</head>") : styles + html;
  changed = true;
}

if (!html.includes('data-section="settings"')) {
  html = html.replace('<button class="navbtn" data-section="monetization">Monetization</button>', '<button class="navbtn" data-section="monetization">Monetization</button><button class="navbtn" data-section="settings">Settings</button>');
  changed = true;
}

if (!html.includes('id="section-settings"')) {
  const settingsSection = String.raw`<div id="section-settings" class="section hidden"><div class="head"><div><h2>Settings</h2><p>Appearance and workspace configuration. This page is intentionally visual-only so existing dashboard and CRM behavior stays unchanged.</p></div></div><div class="settings-grid"><article class="settings-card"><h3>Theme</h3><p>Dark workspace theme with green Constrava accents.</p><span class="settings-tag">Dark active</span></article><article class="settings-card"><h3>Shape style</h3><p>Square panels, cards, buttons, forms, CRM tables, and modal surfaces.</p><span class="settings-tag">Squared active</span></article><article class="settings-card"><h3>Safety mode</h3><p>No backend routes, AI record logic, CRM storage, analytics loading, or Google Forms flows are changed by this appearance page.</p><span class="settings-tag">UI-only patch</span></article><article class="settings-card settings-wide"><h3>Workspace status</h3><p>These are display settings only. Existing features keep using the same routes and event handlers they already used.</p><div class="settings-list"><div class="settings-row"><strong>Analytics data</strong><span>Existing /dashboard/data route</span></div><div class="settings-row"><strong>CRM records</strong><span>Existing CRM rendering/data logic</span></div><div class="settings-row"><strong>AI Edit Records</strong><span>Existing /api/crm/ai-entry route</span></div><div class="settings-row"><strong>Google Forms</strong><span>Existing OAuth/forms patches</span></div></div><div class="settings-note">This settings page was added without changing how existing features function. Future controls can be added here one at a time only when you want them.</div></article></div></div>`;
  const crmAnchor = '<section id="crm" class="hidden">';
  if (html.includes(crmAnchor)) {
    html = html.replace(crmAnchor, settingsSection + crmAnchor);
    changed = true;
  } else {
    console.warn("[crm-dark-square-settings-patch] Could not find CRM section anchor for settings page.");
  }
}

if (changed) {
  fs.writeFileSync(file, html);
  console.log("[crm-dark-square-settings-patch] Applied dark square theme and added settings page without changing feature logic.");
} else {
  console.log("[crm-dark-square-settings-patch] Dark square settings patch already applied.");
}
