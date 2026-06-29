import fs from "fs";

const serverFile = "server.js";
const tabsFile = "crm-distinct-tabs.js";
let changedAny = false;

const serverHelper = `function crmEntityHash(value) {
  const s = String(value || "").toLowerCase().trim();
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36).toUpperCase();
}
function crmEntityKey(entry) {
  const src = entry && typeof entry === "object" ? entry : {};
  const email = String(src.email || src.contact_email || "").trim().toLowerCase();
  const phone = String(src.phone || src.mobile || src.phone_number || "").replace(/\D/g, "");
  const name = String(src.name || src.full_name || src.contact_name || "").trim().toLowerCase().replace(/\s+/g, " ");
  const company = String(src.company || src.organization || "").trim().toLowerCase().replace(/\s+/g, " ");
  const website = String(src.website || src.url || src.domain || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/$/, "");

  if (email) return "email:" + email;
  if (phone) return "phone:" + phone;
  if (name && company) return "name-company:" + name + "|" + company;
  if (name) return "name:" + name;
  if (website) return "website:" + website;
  if (company) return "company:" + company;
  return "record:" + String(src.id || src.record_id || src.lead_id || randomBytes(5).toString("hex")).toLowerCase();
}
function ensureCrmEntityLinkId(entry) {
  const src = entry && typeof entry === "object" ? entry : {};
  const key = crmEntityKey(src);
  const entityId = String(src.entity_id || src.person_id || src.contact_id || ("ENT-" + crmEntityHash(key))).trim();
  const companyKey = String(src.company || src.organization || "").trim().toLowerCase().replace(/\s+/g, " ");
  const companyId = String(src.company_id || (companyKey ? "ORG-" + crmEntityHash("company:" + companyKey) : "")).trim();
  return {
    ...src,
    entity_key: src.entity_key || key,
    entity_id: entityId,
    person_id: src.person_id || entityId,
    contact_id: src.contact_id || entityId,
    company_id: companyId || src.company_id || ""
  };
}
`;

if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;

  if (!source.includes("function ensureCrmEntityLinkId(entry)")) {
    const anchor = "function ensureCrmRecordId(entry)";
    if (source.includes(anchor)) {
      source = source.replace(anchor, serverHelper + anchor);
      changed = true;
    } else {
      const fallback = "function normalizeIncompleteCrmEntry(entry";
      if (source.includes(fallback)) {
        source = source.replace(fallback, serverHelper + fallback);
        changed = true;
      } else {
        console.warn("[crm-entity-link-id-patch] Could not find entity-link helper anchor.");
      }
    }
  }

  const beforeReturns = source;
  source = source.replaceAll("return ensureCrmRecordId(safe);", "return ensureCrmEntityLinkId(ensureCrmRecordId(safe));");
  source = source.replaceAll("return ensureCrmRecordId({", "return ensureCrmEntityLinkId(ensureCrmRecordId({");
  source = source.replaceAll("  });\n}\nfunction mergeEntryUpdate", "  }));\n}\nfunction mergeEntryUpdate");
  source = source.replaceAll("ensureCrmRecordId(normalizeIncompleteCrmEntry(mapLead(lead, i), siteId, ''))", "ensureCrmEntityLinkId(ensureCrmRecordId(normalizeIncompleteCrmEntry(mapLead(lead, i), siteId, '')))");
  source = source.replaceAll("finalEntry = ensureCrmRecordId(finalEntry);", "finalEntry = ensureCrmEntityLinkId(ensureCrmRecordId(finalEntry));");
  if (source !== beforeReturns) changed = true;

  const beforePrompt = source;
  source = source.replaceAll(
    "One data point can have multiple types.",
    "One data point can have multiple types. Use entity_id to connect multiple records that belong to the same real-world person or organization over time. For example, Lidia can first be a lead and later have a sale record with the same entity_id."
  );
  if (source !== beforePrompt) changed = true;

  if (changed) {
    fs.writeFileSync(serverFile, source);
    console.log("CRM records now include shared entity IDs across different record types.");
    changedAny = true;
  } else {
    console.log("Server entity-link CRM ID patch already applied or no anchors found.");
  }
}

const clientHelper = `  function clientEntityHash(value){
    const s=String(value||'').toLowerCase().trim(); let h=2166136261;
    for(let i=0;i<s.length;i++){ h^=s.charCodeAt(i); h=Math.imul(h,16777619); }
    return (h>>>0).toString(36).toUpperCase();
  }
  function clientEntityKey(e){
    const email=String(e&&e.email||'').trim().toLowerCase();
    const phone=String(e&&(e.phone||e.mobile)||'').replace(/\D/g,'');
    const name=String(e&&e.name||'').trim().toLowerCase().replace(/\s+/g,' ');
    const company=String(e&&e.company||'').trim().toLowerCase().replace(/\s+/g,' ');
    const website=String(e&&(e.website||e.url||e.domain)||'').trim().toLowerCase().replace(/^https?:\/\//,'').replace(/^www\./,'').replace(/\/$/,'');
    if(email) return 'email:'+email;
    if(phone) return 'phone:'+phone;
    if(name&&company) return 'name-company:'+name+'|'+company;
    if(name) return 'name:'+name;
    if(website) return 'website:'+website;
    if(company) return 'company:'+company;
    return 'record:'+String(e&&(e.id||e.record_id||e.lead_id)||Math.random().toString(16).slice(2)).toLowerCase();
  }
  function ensureClientEntityLinkId(e){
    const key=clientEntityKey(e||{});
    const entityId=String(e&&(e.entity_id||e.person_id||e.contact_id)||('ENT-'+clientEntityHash(key))).trim();
    const company=String(e&&e.company||'').trim().toLowerCase().replace(/\s+/g,' ');
    const companyId=String(e&&e.company_id || (company ? 'ORG-'+clientEntityHash('company:'+company) : '')).trim();
    return { ...(e||{}), entity_key:(e&&e.entity_key)||key, entity_id:entityId, person_id:(e&&e.person_id)||entityId, contact_id:(e&&e.contact_id)||entityId, company_id:companyId };
  }
`;

if (fs.existsSync(tabsFile)) {
  let source = fs.readFileSync(tabsFile, "utf8");
  let changed = false;

  if (!source.includes("function ensureClientEntityLinkId(e)")) {
    const anchor = "  function ensureClientRecordId(e)";
    if (source.includes(anchor)) {
      source = source.replace(anchor, clientHelper + anchor);
      changed = true;
    } else {
      const fallback = "  function getStatus(e)";
      if (source.includes(fallback)) {
        source = source.replace(fallback, clientHelper + fallback);
        changed = true;
      }
    }
  }

  const beforeClient = source;
  source = source.replaceAll("return ensureClientRecordId({", "return ensureClientEntityLinkId(ensureClientRecordId({");
  source = source.replaceAll("    });", "    }));");
  source = source.replaceAll(".map(ensureClientRecordId)", ".map((e)=>ensureClientEntityLinkId(ensureClientRecordId(e)))");
  if (source !== beforeClient) changed = true;

  if (changed) {
    fs.writeFileSync(tabsFile, source);
    console.log("CRM side tabs now preserve shared entity IDs across record types.");
    changedAny = true;
  } else {
    console.log("Side-tab entity-link CRM ID patch already applied or no anchors found.");
  }
}

if (!changedAny) console.log("CRM entity-link ID patch made no changes.");
