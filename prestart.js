import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceOnce(search, replacement) {
  if (text.includes(replacement)) return false;
  if (!text.includes(search)) return false;
  text = text.replace(search, replacement);
  return true;
}

// Safe database compatibility fixes for the live Neon schema.
replaceOnce(
  'const dateCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);',
  'const dateCol = firstExisting(c, ["report_date", "date", "created_at", "generated_at", "timestamp"]);'
);

replaceOnce(
  '  add(siteCol, String(siteId));\n  add(textCol, text);\n  add(dateCol, new Date());',
  '  const now = new Date();\n  const today = now.toISOString().slice(0, 10);\n\n  add(siteCol, String(siteId));\n  add(textCol, text);\n  if (c.includes("report_date")) add("report_date", today);\n  if (c.includes("date")) add("date", today);\n  if (c.includes("created_at")) add("created_at", now);\n  if (c.includes("generated_at")) add("generated_at", now);\n  if (c.includes("timestamp")) add("timestamp", now);\n  if (dateCol && !insertCols.includes(dateCol)) add(dateCol, now);'
);

// Add plan-preview styles without changing existing graph code.
replaceOnce(
  '    .plan small { color: #64748b; line-height: 1.5; display: block; }',
  '    .plan small { color: #64748b; line-height: 1.5; display: block; }\n    .plan-tabs { display:flex; flex-wrap:wrap; gap:10px; margin:14px 0 16px; }\n    .plan-tab { border:1px solid #dbe8e4; border-radius:999px; padding:10px 14px; background:#f8fffc; color:#064e3b; font-weight:950; }\n    .plan-tab.active { background:#064e3b; color:#d1fae5; border-color:#064e3b; }\n    .plan-detail { border:1px solid #dbe8e4; border-radius:20px; padding:18px; background:linear-gradient(180deg,#ffffff,#f3fff9); }\n    .plan-detail h3 { margin:0 0 6px; color:#073d32; }\n    .plan-detail .price { color:#047857; font-size:28px; font-weight:950; margin:8px 0 6px; }\n    .plan-detail ul { margin:14px 0 0; padding-left:20px; color:#475569; line-height:1.65; }\n    .plan-preview-pill { display:inline-flex; align-items:center; margin-top:10px; padding:7px 10px; border-radius:999px; background:#d1fae5; color:#047857; font-weight:950; font-size:12px; }'
);

// Add a simple plan badge below the title.
replaceOnce(
  '             <p class="subtitle">Token-auth dashboard • secure it later with accounts if desired 🔒</p>',
  '             <p class="subtitle">Token-auth dashboard • secure it later with accounts if desired 🔒</p>\n             <div class="plan-preview-pill" id="planPreviewPill">Growth plan preview</div>'
);

// Add the plan selector beside the date range selector.
replaceOnce(
  '          </label>\n          <button class="btn" type="button" id="seedBtn"><span data-icon="database"></span> Seed demo data</button>',
  '          </label>\n          <label class="select-wrap" title="Plan preview">\n            <span data-icon="crown"></span>\n            <select id="planPreviewSelect">\n              <option value="starter">Starter</option>\n              <option value="growth" selected>Growth</option>\n              <option value="custom">Custom</option>\n            </select>\n          </label>\n          <button class="btn" type="button" id="seedBtn"><span data-icon="database"></span> Seed demo data</button>'
);

// Add plan state.
replaceOnce(
  '    let selectedMetric = "visits";\n    let activeSide = "analytics";',
  '    let selectedMetric = "visits";\n    let activePlanPreview = "growth";\n    let activeSide = "analytics";'
);

// Replace only the plan modal builder. No inline onclick handlers are used.
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
          tagline: "A focused launch package for a new client or small business.",
          insight: "Starter preview: basic website analytics, lead capture, and a simple report. CRM and advanced automation are shown as upgrade paths.",
          features: ["Landing page or simple site refresh", "Basic visitor and CTA tracking", "Contact form / lead routing", "Simple monthly summary"]
        },
        growth: {
          name: "Growth",
          price: "$1,500+",
          tagline: "The full dashboard experience for an active business.",
          insight: "Growth preview: analytics, CRM pipeline, AI-style reports, event simulation, conversion tracking, and CSV export.",
          features: ["Custom analytics dashboard", "CRM lead workflow", "AI-style report generation", "Event simulation and conversion tracking", "CSV export and tracker install snippet"]
        },
        custom: {
          name: "Custom",
          price: "Quoted",
          tagline: "A fully custom internal tool or AI workflow built around the client.",
          insight: "Custom preview: everything in Growth plus private integrations, custom automations, internal portals, and client-specific workflows.",
          features: ["Everything in Growth", "Private integrations and custom database logic", "Internal admin portals", "AI-assisted operations workflows", "Custom reporting and automation"]
        }
      };
      return plans[plan] || plans.growth;
    }

    function applyPlanPreview(showToast) {
      const cfg = planPreviewData(activePlanPreview);
      const pill = byId("planPreviewPill");
      if (pill) pill.textContent = cfg.name + " plan preview";
      const insight = byId("sidebarInsight");
      if (insight) insight.textContent = cfg.insight;
      if (showToast) toast(cfg.name + " preview active.");
    }

    function buildPlansHtml() {
      const cfg = planPreviewData(activePlanPreview);
      return '<div class="plan-tabs">' +
        ['starter','growth','custom'].map(function(key) {
          const p = planPreviewData(key);
          return '<button class="plan-tab ' + (key === activePlanPreview ? 'active' : '') + '" type="button" data-plan-preview="' + key + '">' + p.name + '</button>';
        }).join('') +
        '</div><div class="plan-detail"><h3>' + escapeHtml(cfg.name) + '</h3><div class="price">' + escapeHtml(cfg.price) + '</div><p>' + escapeHtml(cfg.tagline) + '</p><ul>' +
        cfg.features.map(function(feature) { return '<li>' + escapeHtml(feature) + '</li>'; }).join('') +
        '</ul></div>';
    }`
);

// Add plan selector change handler.
replaceOnce(
  '    byId("rangeSelect").addEventListener("change", function(event) {\n      selectedRange = Number(event.target.value || 7);\n      renderDashboard();\n      toast("Range changed to " + selectedRange + " days.");\n    });',
  '    byId("rangeSelect").addEventListener("change", function(event) {\n      selectedRange = Number(event.target.value || 7);\n      renderDashboard();\n      toast("Range changed to " + selectedRange + " days.");\n    });\n\n    byId("planPreviewSelect").addEventListener("change", function(event) {\n      activePlanPreview = event.target.value || "growth";\n      applyPlanPreview(true);\n    });'
);

// Add modal tab click handling with event delegation.
replaceOnce(
  '    byId("modalBackdrop").addEventListener("click", function(event){ if (event.target.id === "modalBackdrop") closeModal(); });',
  '    byId("modalBackdrop").addEventListener("click", function(event){ if (event.target.id === "modalBackdrop") closeModal(); });\n    byId("modalExtra").addEventListener("click", function(event) {\n      const btn = event.target.closest("[data-plan-preview]");\n      if (!btn) return;\n      activePlanPreview = btn.getAttribute("data-plan-preview") || "growth";\n      byId("planPreviewSelect").value = activePlanPreview;\n      applyPlanPreview(true);\n      byId("modalExtra").innerHTML = buildPlansHtml();\n    });'
);

// Apply plan preview after dashboard render.
replaceOnce(
  '      byId("exportBtn").href = "/dashboard/export.csv?token=" + encodeURIComponent(token);\n      byId("dataBtn").href = "/dashboard/data?token=" + encodeURIComponent(token);',
  '      byId("exportBtn").href = "/dashboard/export.csv?token=" + encodeURIComponent(token);\n      byId("dataBtn").href = "/dashboard/data?token=" + encodeURIComponent(token);\n      applyPlanPreview(false);'
);

// Upgrade seed demo data so the dashboard looks more impressive.
replaceOnce(
  `    const now = Date.now();
    const types = [
      "page_view",
      "page_view",
      "page_view",
      "page_view",
      "page_view",
      "cta_click",
      "cta_click",
      "lead",
      "purchase",
    ];

    let inserted = 0;

    for (let day = 0; day < 7; day++) {
      const count = 9 + Math.floor(Math.random() * 10);

      for (let i = 0; i < count; i++) {
        const type = types[Math.floor(Math.random() * types.length)];
        const time = new Date(now - day * 86400000 - Math.floor(Math.random() * 80000000));
        await insertEvent(siteId, type, {
          time,
          source: ["Direct", "Search", "Social", "Referral"][Math.floor(Math.random() * 4)],
          device: ["Desktop", "Desktop", "Mobile", "Tablet"][Math.floor(Math.random() * 4)],
          campaign: "seed-demo",
        });
        inserted++;
      }
    }

    res.json({ ok: true, inserted, message: "Demo data seeded." });`,
  `    const now = Date.now();
    const pages = ["/", "/services", "/process", "/work", "/contact", "/pricing", "/dashboard"];
    const ctaPages = ["/services", "/pricing", "/contact", "/work"];
    const sources = ["Direct", "Search", "Search", "Social", "Referral", "Newsletter"];
    const devices = ["Desktop", "Desktop", "Desktop", "Mobile", "Mobile", "Tablet"];
    const purchaseAmounts = [299, 499, 750, 1200, 1500, 2500];
    const leadNames = ["Avery Morgan", "Jordan Lee", "Sam Patel", "Taylor Brooks", "Morgan Chen", "Riley Adams", "Casey Rivera", "Jamie Carter"];

    let inserted = 0;
    let leadRecords = 0;

    function pick(list) {
      return list[Math.floor(Math.random() * list.length)];
    }

    function rand(min, max) {
      return min + Math.floor(Math.random() * (max - min + 1));
    }

    async function seedEvent(type, day, index, total, options = {}) {
      const spread = Math.floor(((index + Math.random()) / Math.max(total, 1)) * 78000000);
      const time = new Date(now - day * 86400000 - spread);
      await insertEvent(siteId, type, {
        time,
        source: pick(sources),
        device: pick(devices),
        campaign: "seed-demo-pro",
        path: options.path || pick(pages),
        amount: options.amount || 0,
        visitor: "seed_" + day + "_" + type + "_" + index + "_" + Math.random().toString(16).slice(2, 6),
      });
      inserted++;
    }

    for (let day = 6; day >= 0; day--) {
      const momentum = 7 - day;
      const views = 34 + momentum * 8 + rand(0, 14);
      const clicks = 14 + momentum * 4 + rand(0, 8);
      const leads = 4 + Math.floor(momentum * 1.3) + rand(0, 4);
      const purchases = 2 + Math.floor(momentum * 0.9) + rand(0, 3);

      for (let i = 0; i < views; i++) {
        await seedEvent("page_view", day, i, views, { path: pick(pages) });
      }

      for (let i = 0; i < clicks; i++) {
        await seedEvent("cta_click", day, i, clicks, { path: pick(ctaPages) });
      }

      for (let i = 0; i < leads; i++) {
        await seedEvent("lead", day, i, leads, { path: "/contact" });
      }

      for (let i = 0; i < purchases; i++) {
        await seedEvent("purchase", day, i, purchases, {
          path: "/checkout",
          amount: pick(purchaseAmounts),
        });
      }
    }

    for (let i = 0; i < 12; i++) {
      const name = leadNames[i % leadNames.length];
      const stored = await insertLeadRecord(siteId, {
        name,
        email: name.toLowerCase().replaceAll(" ", ".") + "@example.com",
        company: ["Northstar Studio", "Lee Manufacturing", "Patel Labs", "Greenline HVAC", "Forge Fitness", "Carter Design"][i % 6],
        status: ["New", "Qualified", "Proposal", "Qualified"][i % 4],
        source: pick(sources),
        message: "Demo lead created by the seeded growth dataset.",
      });
      if (stored) leadRecords++;
    }

    res.json({ ok: true, inserted, leadRecords, message: "High-impact demo data seeded." });`
);

fs.writeFileSync(target, text);
console.log("Prepared server.js for Neon schema, plan previews, and stronger demo data.");
