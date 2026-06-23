import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceOnce(search, replacement) {
  if (text.includes(replacement)) return;
  if (!text.includes(search)) return;
  text = text.replace(search, replacement);
}

// Database compatibility fixes for the live Neon schema.
replaceOnce(
  'const dateCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);',
  'const dateCol = firstExisting(c, ["report_date", "date", "created_at", "generated_at", "timestamp"]);'
);

replaceOnce(
  '  add(siteCol, String(siteId));\n  add(textCol, text);\n  add(dateCol, new Date());',
  '  const now = new Date();\n  const today = now.toISOString().slice(0, 10);\n\n  add(siteCol, String(siteId));\n  add(textCol, text);\n  if (c.includes("report_date")) add("report_date", today);\n  if (c.includes("date")) add("date", today);\n  if (c.includes("created_at")) add("created_at", now);\n  if (c.includes("generated_at")) add("generated_at", now);\n  if (c.includes("timestamp")) add("timestamp", now);\n  if (dateCol && !insertCols.includes(dateCol)) add(dateCol, now);'
);

// Add plan preview styling.
replaceOnce(
  '    .plan small { color: #64748b; line-height: 1.5; display: block; }',
  '    .plan small { color: #64748b; line-height: 1.5; display: block; }\n    .plan-tabs { display:flex; flex-wrap:wrap; gap:10px; margin:14px 0 16px; }\n    .plan-tab { border:1px solid #dbe8e4; border-radius:999px; padding:10px 14px; background:#f8fffc; color:#064e3b; font-weight:950; }\n    .plan-tab.active { background:#064e3b; color:#d1fae5; border-color:#064e3b; }\n    .plan-detail { border:1px solid #dbe8e4; border-radius:20px; padding:18px; background:linear-gradient(180deg,#ffffff,#f3fff9); }\n    .plan-detail h3 { margin:0 0 6px; color:#073d32; }\n    .plan-detail ul { margin:14px 0 0; padding-left:20px; color:#475569; line-height:1.65; }\n    .plan-detail .price { color:#047857; font-size:28px; font-weight:950; margin:8px 0 6px; }\n    .plan-preview-pill { display:inline-flex; align-items:center; gap:8px; margin-top:10px; padding:7px 10px; border-radius:999px; background:#d1fae5; color:#047857; font-weight:950; font-size:12px; }\n    .btn[disabled], .mini-btn[disabled] { opacity:.45; cursor:not-allowed; filter:grayscale(.25); }'
);

// Add a plan preview badge under the dashboard title.
replaceOnce(
  '             <p class="subtitle">Token-auth dashboard • secure it later with accounts if desired 🔒</p>',
  '             <p class="subtitle">Token-auth dashboard • secure it later with accounts if desired 🔒</p>\n             <div class="plan-preview-pill" id="planPreviewPill">Growth plan preview</div>'
);

// Add a top toolbar plan selector.
replaceOnce(
  '          </label>\n          <button class="btn" type="button" id="seedBtn"><span data-icon="database"></span> Seed demo data</button>',
  '          </label>\n          <label class="select-wrap" title="Plan preview">\n            <span data-icon="crown"></span>\n            <select id="planPreviewSelect">\n              <option value="starter">Starter</option>\n              <option value="growth" selected>Growth</option>\n              <option value="custom">Custom</option>\n            </select>\n          </label>\n          <button class="btn" type="button" id="seedBtn"><span data-icon="database"></span> Seed demo data</button>'
);

// Add the active plan state variable.
replaceOnce(
  '    let selectedMetric = "visits";\n    let activeSide = "analytics";',
  '    let selectedMetric = "visits";\n    let activePlanPreview = "growth";\n    let activeSide = "analytics";'
);

// Replace the basic plan modal with an interactive plan preview system.
replaceOnce(
  `    function buildPlansHtml() {
      return '<div class="plan-grid">' +
        '<div class="plan"><strong>Starter</strong><span>$499+</span><small>Landing page, analytics setup, and basic lead routing for a new client project.</small></div>' +
        '<div class="plan"><strong>Growth</strong><span>$1,500+</span><small>Custom dashboard, CRM workflow, reports, and demo automation for active businesses.</small></div>' +
        '<div class="plan"><strong>Custom</strong><span>Quoted</span><small>Full-stack internal tools, AI-assisted operations, and private integrations.</small></div>' +
      '</div>';
    }`,
  `    function planPreviewData(plan) {
      const plans = {
        starter: {
          name: "Starter",
          price: "$499+",
          tagline: "A polished launch package for a small business or first client demo.",
          insight: "Starter preview: website, basic tracking, simple lead capture, and a lightweight report. CRM and advanced AI tools are limited.",
          crm: false,
          ai: false,
          automation: false,
          features: ["Landing page or simple site refresh", "Basic visitor/event tracking", "Contact form and lead notification", "Simple monthly performance summary"]
        },
        growth: {
          name: "Growth",
          price: "$1,500+",
          tagline: "The full Constrava dashboard experience for an active business.",
          insight: "Growth preview: full analytics dashboard, CRM pipeline, event simulation, AI report generation, and conversion insights are enabled.",
          crm: true,
          ai: true,
          automation: true,
          features: ["Custom analytics dashboard", "CRM lead workflow", "AI-style reports and recommendations", "Event simulation and conversion tracking", "CSV export and tracker install snippet"]
        },
        custom: {
          name: "Custom",
          price: "Quoted",
          tagline: "A fully custom internal tool or AI workflow built around the client.",
          insight: "Custom preview: everything in Growth plus private integrations, custom automations, advanced workflows, and client-specific data structures.",
          crm: true,
          ai: true,
          automation: true,
          features: ["Everything in Growth", "Private integrations and custom database logic", "Internal portals or admin systems", "AI-assisted operations workflows", "Custom reporting and automation"]
        }
      };
      return plans[plan] || plans.growth;
    }

    function selectPlanPreview(plan) {
      activePlanPreview = plan || "growth";
      const select = byId("planPreviewSelect");
      if (select) select.value = activePlanPreview;
      applyPlanPreview(true);
      openModal("Constrava Plans", "Switch plans to preview what changes in the demo.", buildPlansHtml());
    }

    function applyPlanPreview(showToast) {
      const cfg = planPreviewData(activePlanPreview);
      const pill = byId("planPreviewPill");
      if (pill) pill.textContent = cfg.name + " plan preview";
      const insight = byId("sidebarInsight");
      if (insight) insight.textContent = cfg.insight;
      const reportButtons = [byId("reportBtn"), byId("reportBtn2")].filter(Boolean);
      reportButtons.forEach(function(btn) { btn.disabled = !cfg.ai; btn.title = cfg.ai ? "Generate AI report" : "AI reports are included in Growth and Custom."; });
      const crmButton = byId("crmBtn");
      if (crmButton) { crmButton.disabled = !cfg.crm; crmButton.title = cfg.crm ? "Open CRM" : "CRM is included in Growth and Custom."; }
      document.querySelectorAll('[data-side="crm"]').forEach(function(btn) { btn.disabled = !cfg.crm; });
      if (!cfg.crm && activeSide === "crm") switchSide("analytics");
      if (showToast) toast(cfg.name + " preview active.");
    }

    function buildPlansHtml() {
      const cfg = planPreviewData(activePlanPreview);
      return '<div class="plan-tabs">' +
        ['starter','growth','custom'].map(function(key){
          const p = planPreviewData(key);
          return '<button class="plan-tab ' + (key === activePlanPreview ? 'active' : '') + '" type="button" onclick="selectPlanPreview(\\'' + key + '\\')">' + p.name + '</button>';
        }).join('') +
        '</div><div class="plan-detail"><h3>' + cfg.name + '</h3><div class="price">' + cfg.price + '</div><p>' + cfg.tagline + '</p><ul>' +
        cfg.features.map(function(feature){ return '<li>' + escapeHtml(feature) + '</li>'; }).join('') +
        '</ul></div>';
    }`
);

// Wire the plan selector to the preview function.
replaceOnce(
  '    byId("rangeSelect").addEventListener("change", function(event) {\n      selectedRange = Number(event.target.value || 7);\n      renderDashboard();\n      toast("Range changed to " + selectedRange + " days.");\n    });',
  '    byId("rangeSelect").addEventListener("change", function(event) {\n      selectedRange = Number(event.target.value || 7);\n      renderDashboard();\n      toast("Range changed to " + selectedRange + " days.");\n    });\n\n    byId("planPreviewSelect").addEventListener("change", function(event) {\n      activePlanPreview = event.target.value || "growth";\n      applyPlanPreview(true);\n    });'
);

// Re-apply plan state after dashboard refreshes.
replaceOnce(
  '      byId("exportBtn").href = "/dashboard/export.csv?token=" + encodeURIComponent(token);\n      byId("dataBtn").href = "/dashboard/data?token=" + encodeURIComponent(token);',
  '      byId("exportBtn").href = "/dashboard/export.csv?token=" + encodeURIComponent(token);\n      byId("dataBtn").href = "/dashboard/data?token=" + encodeURIComponent(token);\n      applyPlanPreview(false);'
);

fs.writeFileSync(target, text);
console.log("Prepared server.js for current Neon schema and plan preview demo.");
