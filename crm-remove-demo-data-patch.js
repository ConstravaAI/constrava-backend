import fs from "fs";

const serverFile = "server.js";
const tabsFile = "crm-distinct-tabs.js";
let changedAny = false;

function filterHelperSource() {
  return `function isRealCrmEntry(entry) {
  const text = JSON.stringify(entry || {}).toLowerCase();
  const owner = String(entry?.owner || "").toLowerCase();
  const source = String(entry?.source || "").toLowerCase();
  const company = String(entry?.company || "").toLowerCase();
  const title = String(entry?.title || "").toLowerCase();
  const dealName = String(entry?.deal_name || "").toLowerCase();
  const notes = String(entry?.notes || "").toLowerCase();
  const email = String(entry?.email || "").toLowerCase();

  if (notes.includes("demo lead created by seed")) return false;
  if (owner === "constrava demo team") return false;
  if (text.includes("demo lead created by seed")) return false;
  if (company === "external form lead" && title === "external form lead" && source === "form submission") return false;
  if (dealName === "external form lead form inquiry" && source === "form submission") return false;
  if (/@(example\\.com|brightside\\.io|northstar\\.fit)$/.test(email)) return false;
  if (String(entry?.lead_id || "").match(/^\\d+$/) && source === "form submission" && company === "external form lead") return false;

  return true;
}
`;
}

if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;

  if (!source.includes("function isRealCrmEntry(entry)")) {
    const anchor = "function crmListSummary(leads)";
    if (source.includes(anchor)) {
      source = source.replace(anchor, filterHelperSource() + anchor);
      changed = true;
    } else {
      console.warn("[crm-remove-demo-data-patch] Could not find crmListSummary anchor.");
    }
  }

  const beforeReturn = source;
  source = source.replace(
    /return uniqueCrmLeads\(storedLeads\)\.sort\(sortCrmLeadsNewestFirst\);/g,
    "return uniqueCrmLeads(storedLeads.filter(isRealCrmEntry)).sort(sortCrmLeadsNewestFirst);"
  );
  source = source.replace(
    /return uniqueCrmLeads\(storedLeads\.filter\(isRealCrmEntry\)\)\.sort\(sortCrmLeadsNewestFirst\);/g,
    "return uniqueCrmLeads(storedLeads.filter(isRealCrmEntry)).sort(sortCrmLeadsNewestFirst);"
  );
  if (source !== beforeReturn) changed = true;

  const beforeMerged = source;
  source = source.replace(
    /const storedLeads = mergedRaw\.map\(\(lead, i\) => mapLead\(lead, i\)\);\s*return uniqueCrmLeads\(storedLeads\)\.sort\(sortCrmLeadsNewestFirst\);/g,
    "const storedLeads = mergedRaw.map((lead, i) => mapLead(lead, i));\n  return uniqueCrmLeads(storedLeads.filter(isRealCrmEntry)).sort(sortCrmLeadsNewestFirst);"
  );
  if (source !== beforeMerged) changed = true;

  // Final safety for CRM entries route responses that are built from payload.leads.
  const beforeFilterCall = source;
  source = source.replace(
    /const entries = filterCrmEntries\(payload\.leads \|\| \[\], req\.query\.type, req\.query\.q\);/g,
    "const entries = filterCrmEntries((payload.leads || []).filter(isRealCrmEntry), req.query.type, req.query.q);"
  );
  if (source !== beforeFilterCall) changed = true;

  if (changed) {
    fs.writeFileSync(serverFile, source);
    console.log("Fake/demo CRM seed data filtered from server CRM lists.");
    changedAny = true;
  } else {
    console.log("Server CRM demo-data filter already applied or no anchors found.");
  }
}

if (fs.existsSync(tabsFile)) {
  let source = fs.readFileSync(tabsFile, "utf8");
  let changed = false;

  const clientHelper = `  function isRealCrmEntry(entry){
    const text = JSON.stringify(entry || {}).toLowerCase();
    const owner = String(entry && entry.owner || '').toLowerCase();
    const source = String(entry && entry.source || '').toLowerCase();
    const company = String(entry && entry.company || '').toLowerCase();
    const title = String(entry && entry.title || '').toLowerCase();
    const dealName = String(entry && entry.deal_name || '').toLowerCase();
    const notes = String(entry && entry.notes || '').toLowerCase();
    const email = String(entry && entry.email || '').toLowerCase();
    if(notes.includes('demo lead created by seed')) return false;
    if(owner === 'constrava demo team') return false;
    if(text.includes('demo lead created by seed')) return false;
    if(company === 'external form lead' && title === 'external form lead' && source === 'form submission') return false;
    if(dealName === 'external form lead form inquiry' && source === 'form submission') return false;
    if(/@(example\\.com|brightside\\.io|northstar\\.fit)$/.test(email)) return false;
    if(String(entry && entry.lead_id || '').match(/^\\d+$/) && source === 'form submission' && company === 'external form lead') return false;
    return true;
  }
`;

  if (!source.includes("function isRealCrmEntry(entry)")) {
    const anchor = "  function entries(){";
    if (source.includes(anchor)) {
      source = source.replace(anchor, clientHelper + anchor);
      changed = true;
    }
  }

  const beforeEntries = source;
  source = source.replace(
    /function entries\(\)\{ return Array\.isArray\(state\.entries\) \? state\.entries : \[\]; \}/g,
    "function entries(){ return Array.isArray(state.entries) ? state.entries.filter(isRealCrmEntry) : []; }"
  );
  if (source !== beforeEntries) changed = true;

  const beforeSet = source;
  source = source.replace(
    /state\.entries = \(lists\.sort\(\(a,b\)=>b\.length-a\.length\)\[0\] \|\| \[\]\)\.map\(\(e\) => \(\{/g,
    "state.entries = (lists.sort((a,b)=>b.length-a.length)[0] || []).filter(isRealCrmEntry).map((e) => ({"
  );
  if (source !== beforeSet) changed = true;

  if (changed) {
    fs.writeFileSync(tabsFile, source);
    console.log("Fake/demo CRM seed data filtered from side-tab UI.");
    changedAny = true;
  } else {
    console.log("Side-tab CRM demo-data filter already applied or no anchors found.");
  }
}

if (!changedAny) console.log("CRM fake/demo data removal patch made no changes.");
