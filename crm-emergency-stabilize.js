import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceRegex(pattern, replacement) {
  const before = text;
  text = text.replace(pattern, replacement);
  return text !== before;
}

// 1) Search should be read-only and local to the already-loaded dashboard data.
// This avoids accidental writes and makes semantic/type searches work on demo data.
const localSearch = `async function runCrmSearch() {
      const input = byId("crmSearchInput");
      const status = byId("crmSearchStatus");
      const query = input ? input.value.trim() : "";

      if (!query) {
        crmSearchResults = null;
        crmStatusFilter = "all";
        renderCrm();
        return;
      }

      function scoreLead(lead, rawQuery) {
        const q = String(rawQuery || "").toLowerCase();
        const text = [lead.name, lead.email, lead.phone, lead.company, lead.status, lead.source, lead.notes, lead.message]
          .join(" ")
          .toLowerCase();
        const generic = new Set(["lead", "leads", "person", "people", "client", "clients", "customer", "customers", "company", "companies", "business", "businesses", "show", "find", "type", "types", "of", "the", "a", "an"]);
        const words = q.split(/\\s+/).map(function(word) { return word.replace(/[^a-z0-9]/g, ""); }).filter(function(word) { return word && !generic.has(word); });
        let score = 0;

        if (text.includes(q)) score += 120;
        words.forEach(function(word) {
          if (text.includes(word)) score += 25;
        });

        const groups = [
          { query: ["manufacturing", "factory", "industrial", "warehouse", "machine", "production"], match: ["manufacturing", "factory", "industrial", "warehouse", "machine", "machining", "production", "hvac", "forge", "fabrication", "maintenance"] },
          { query: ["fitness", "gym", "trainer", "sports", "athlete"], match: ["fitness", "gym", "trainer", "sports", "athlete", "wellness", "boxing", "martial"] },
          { query: ["design", "studio", "creative", "agency", "brand"], match: ["design", "studio", "creative", "agency", "brand", "marketing", "media"] },
          { query: ["tech", "software", "saas", "ai", "data", "lab"], match: ["tech", "software", "saas", "ai", "data", "lab", "labs", "startup", "app"] },
          { query: ["contractor", "construction", "service", "local", "home"], match: ["contractor", "construction", "service", "local", "home", "plumbing", "roofing", "repair", "hvac"] }
        ];

        groups.forEach(function(group) {
          const askingForGroup = group.query.some(function(term) { return q.includes(term); });
          const matchesGroup = group.match.some(function(term) { return text.includes(term); });
          if (askingForGroup && matchesGroup) score += 100;
        });

        const statusText = String(lead.status || "").toLowerCase();
        const intentText = text + " " + statusText;
        if (/ready|buyer|buyers|buy|hot|serious|qualified|proposal|close|decision|urgent|best|high/.test(q)) {
          if (/qualified|proposal|won|contacted/.test(statusText)) score += 70;
          if (/budget|timeline|quote|proposal|urgent|ready|pricing|purchase/.test(intentText)) score += 35;
        }
        if (/new|fresh|uncontacted/.test(q) && /new/.test(statusText)) score += 70;
        if (/proposal|quote|estimate/.test(q) && /proposal/.test(intentText)) score += 70;
        if (/won|closed/.test(q) && /won/.test(statusText)) score += 70;
        if (/lost|dead|bad/.test(q) && /lost/.test(statusText)) score += 70;

        return score;
      }

      const baseLeads = (dashboardData.leads || []).slice();
      const ranked = baseLeads
        .map(function(lead) { return { lead: lead, score: scoreLead(lead, query) }; })
        .filter(function(item) { return item.score > 0; })
        .sort(function(a, b) { return b.score - a.score; })
        .map(function(item) { return item.lead; });

      crmSearchResults = ranked;
      crmStatusFilter = "all";
      renderCrm();
      const nextStatus = byId("crmSearchStatus");
      if (nextStatus) nextStatus.textContent = "Found " + ranked.length + " matching leads for: " + query + ". Search is read-only.";
    }`;

replaceRegex(/async function runCrmSearch\(\) \{[\s\S]*?\n    \}\n\n    function renderCrm\(\)/, localSearch + "\n\n    function renderCrm()");
replaceRegex(/async function runCrmSearch\(\) \{[\s\S]*?\n    \}\n\n    async function submitCrmLead/, localSearch + "\n\n    async function submitCrmLead");

// 2) Require explicit manual intent before POST /crm/leads can write anything.
// Search requests never include this, so they cannot create leads even if a browser misfires.
replaceRegex(
  /app\.post\("\/crm\/leads", async \(req, res\) => \{\n  try \{\n/,
  'app.post("/crm/leads", async (req, res) => {\n  try {\n    const createIntent = String(req.query.intent || req.body?.intent || "");\n    if (createIntent !== "manual") return res.status(400).json({ ok: false, error: "Lead creation requires manual CRM intent." });\n'
);

// 3) Make the add-lead form include the manual intent flag.
replaceRegex(
  /fetch\("\/crm\/leads\?token=" \+ encodeURIComponent\(token\)/g,
  'fetch("/crm/leads?token=" + encodeURIComponent(token) + "&intent=manual"'
);

// 4) Prevent Enter in the search box from ever submitting a surrounding form.
replaceRegex(
  /if \(event\.key === "Enter"\) runCrmSearch\(\);/g,
  'if (event.key === "Enter") { event.preventDefault(); runCrmSearch(); }'
);

fs.writeFileSync(target, text);
console.log("Stabilized CRM search: local read-only semantic search plus guarded lead creation.");
