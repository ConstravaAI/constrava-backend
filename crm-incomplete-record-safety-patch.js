import fs from "fs";

const serverFile = "server.js";
const tabsFile = "crm-distinct-tabs.js";
let changedAny = false;

const serverHelper = `function crmMissingFields(entry) {
  const missing = [];
  const primary = String(entry?.type || entry?.primary_type || entry?.record_type || "").toLowerCase();
  const types = Array.isArray(entry?.types) ? entry.types.map((t) => String(t).toLowerCase()) : [];
  const isLead = primary.includes("lead") || types.includes("lead");
  const isPerson = primary.includes("person") || types.includes("person") || !!entry?.name;
  const isCompany = primary.includes("company") || types.includes("company") || !!entry?.company;
  const isDeal = primary.includes("deal") || types.includes("deal") || !!entry?.deal_name || Number(entry?.value || 0) > 0;
  const isTask = primary.includes("task") || types.includes("task") || !!entry?.next_step;

  if (isLead || isPerson) {
    if (!entry?.name) missing.push("name");
    if (!entry?.email) missing.push("email");
    if (!entry?.phone && !entry?.mobile) missing.push("phone");
  }
  if ((isLead || isCompany || isDeal) && !entry?.company) missing.push("company");
  if (isDeal && !Number(entry?.value || 0)) missing.push("value");
  if (isTask && !entry?.next_step) missing.push("next_step");
  return Array.from(new Set(missing));
}
function normalizeIncompleteCrmEntry(entry, siteId = "demo", text = "") {
  const src = entry && typeof entry === "object" ? entry : {};
  const now = new Date().toISOString();
  const types = typeof normalizeCrmTypes === "function" ? normalizeCrmTypes(src) : Array.from(new Set([src.type, src.record_type, src.module].filter(Boolean).map((v) => String(v).toLowerCase())));
  const primary = src.primary_type || src.type || (typeof primaryCrmType === "function" ? primaryCrmType(src) : (types[0] || "entry"));
  const safe = {
    ...src,
    id: src.id || src.lead_id || "CRM-" + randomBytes(5).toString("hex").toUpperCase(),
    lead_id: src.lead_id || src.id || "CRM-" + randomBytes(5).toString("hex").toUpperCase(),
    primary_type: String(primary || "entry"),
    type: String(src.type || primary || "entry"),
    types: types.length ? types : [String(primary || "entry")],
    name: src.name || src.full_name || src.contact_name || "",
    company: src.company || src.organization || "",
    email: src.email || src.lead_email || src.contact_email || "",
    phone: src.phone || src.phone_number || src.mobile || "",
    mobile: src.mobile || src.phone || src.phone_number || "",
    source: src.source || "AI Plain Text Note",
    status: src.status || src.stage || "New",
    notes: src.notes || src.message || text || "Incomplete CRM data point.",
    raw_text: src.raw_text || text || src.plain_text || "",
    created_at: src.created_at || now,
    updated_at: now,
    site_id: String(src.site_id || siteId || "demo"),
    site_slug: String(src.site_slug || siteId || "demo"),
    dashboard_token: String(src.dashboard_token || src.token || siteId || "demo")
  };
  const missing = crmMissingFields(safe);
  safe.missing_fields = Array.isArray(src.missing_fields) ? Array.from(new Set([...src.missing_fields.map(String), ...missing])) : missing;
  safe.needs_review = Boolean(src.needs_review || safe.missing_fields.length);
  safe.data_quality = src.data_quality || (safe.missing_fields.length ? "incomplete" : "complete");
  safe.completeness_score = Number.isFinite(Number(src.completeness_score)) ? Number(src.completeness_score) : Math.max(0, Math.round(100 - safe.missing_fields.length * 18));
  return safe;
}
`;

if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;

  if (!source.includes("function normalizeIncompleteCrmEntry(entry")) {
    const anchor = "function mergeEntryUpdate(existing, patch, text = \"\")";
    if (source.includes(anchor)) {
      source = source.replace(anchor, serverHelper + anchor);
      changed = true;
    } else {
      console.warn("[crm-incomplete-record-safety-patch] Could not find mergeEntryUpdate anchor.");
    }
  }

  const beforeSaves = source;
  source = source.replace(
    /finalEntry\.site_slug = siteId;\s*await saveCrmEntryCompat\(siteId, token, finalEntry\);/g,
    "finalEntry.site_slug = siteId;\n      finalEntry = normalizeIncompleteCrmEntry(finalEntry, siteId, text);\n      await saveCrmEntryCompat(siteId, token, finalEntry);"
  );
  source = source.replace(
    /finalEntry\.site_slug = siteId;\s*await insertCrmLead\(siteId, finalEntry\);/g,
    "finalEntry.site_slug = siteId;\n      finalEntry = normalizeIncompleteCrmEntry(finalEntry, siteId, text);\n      await insertCrmLead(siteId, finalEntry);"
  );
  if (source !== beforeSaves) changed = true;

  const beforeLists = source;
  source = source.replace(
    /const storedLeads = \(rawStored \|\| \[\]\)\.map\(\(lead, i\) => mapLead\(lead, i\)\);/g,
    "const storedLeads = (rawStored || []).map((lead, i) => normalizeIncompleteCrmEntry(mapLead(lead, i), siteId, ''));"
  );
  source = source.replace(
    /const storedLeads = mergedRaw\.map\(\(lead, i\) => mapLead\(lead, i\)\);/g,
    "const storedLeads = mergedRaw.map((lead, i) => normalizeIncompleteCrmEntry(mapLead(lead, i), siteId, ''));"
  );
  if (source !== beforeLists) changed = true;

  const beforePrompt = source;
  source = source.replaceAll(
    "Do not invent contact details not present or implied.",
    "Do not invent contact details not present or implied. Incomplete records are valid: when details are missing, still return the best partial data point, set needs_review:true, data_quality:'incomplete', and missing_fields with any important missing fields."
  );
  if (source !== beforePrompt) changed = true;

  if (changed) {
    fs.writeFileSync(serverFile, source);
    console.log("Incomplete CRM records are now normalized safely.");
    changedAny = true;
  } else {
    console.log("Server incomplete-record safety already applied or no anchors found.");
  }
}

const clientHelper = `  function missingFields(e){
    const missing=[];
    const types = typeof normalizeTypes === 'function' ? normalizeTypes(e) : [];
    if(types.includes('lead') || types.includes('person')){
      if(!(e && e.name)) missing.push('name');
      if(!(e && e.email)) missing.push('email');
      if(!(e && (e.phone || e.mobile))) missing.push('phone');
    }
    if((types.includes('lead') || types.includes('company') || types.includes('deal')) && !(e && e.company)) missing.push('company');
    if(types.includes('deal') && !Number(e && e.value || 0)) missing.push('value');
    return Array.from(new Set(missing));
  }
  function normalizeIncompleteClient(e){
    const types = typeof normalizeTypes === 'function' ? normalizeTypes(e) : [String(e && (e.type || e.record_type || 'entry')).toLowerCase()];
    const missing = Array.isArray(e && e.missing_fields) ? e.missing_fields : missingFields(e || {});
    return {
      ...(e || {}),
      type: (e && e.type) || types[0] || 'entry',
      primary_type: (e && (e.primary_type || e.type)) || types[0] || 'entry',
      types,
      status: (e && (e.status || e.stage)) || 'New',
      notes: (e && (e.notes || e.message || e.raw_text)) || '',
      missing_fields: missing,
      needs_review: Boolean(e && e.needs_review) || missing.length > 0,
      data_quality: (e && e.data_quality) || (missing.length ? 'incomplete' : 'complete')
    };
  }
`;

if (fs.existsSync(tabsFile)) {
  let source = fs.readFileSync(tabsFile, "utf8");
  let changed = false;

  if (!source.includes("function normalizeIncompleteClient(e)")) {
    const anchor = "  function getStatus(e)";
    if (source.includes(anchor)) {
      source = source.replace(anchor, clientHelper + anchor);
      changed = true;
    } else {
      console.warn("[crm-incomplete-record-safety-patch] Could not find getStatus anchor.");
    }
  }

  const beforeLoad = source;
  source = source.replace(
    /state\.entries = \(lists\.sort\(\(a,b\)=>b\.length-a\.length\)\[0\] \|\| \[\]\)\.filter\(isRealCrmEntry\)\.map\(\(e\) => \(\{/g,
    "state.entries = (lists.sort((a,b)=>b.length-a.length)[0] || []).filter(isRealCrmEntry).map((e) => normalizeIncompleteClient({"
  );
  source = source.replace(
    /type: e\.type \|\| normalizeTypes\(e\)\[0\] \|\| 'entry'\s*\}\)\);/g,
    "type: e.type || normalizeTypes(e)[0] || 'entry'\n    }));"
  );
  if (source !== beforeLoad) changed = true;

  const beforeTable = source;
  source = source.replace(
    /<th>Next Step<\/th><\/tr><\/thead>/g,
    "<th>Next Step</th><th>Quality</th></tr></thead>"
  );
  source = source.replace(
    /<td>\$\{esc\(e\.next_step \|\| '—'\)\}<\/td><\/tr>`;/g,
    "<td>${esc(e.next_step || '—')}</td><td>${e.needs_review ? '<span class=\"cx-pill warn\">Needs review</span><small>'+esc((e.missing_fields||[]).join(', '))+'</small>' : '<span class=\"cx-pill\">Complete</span>'}</td></tr>`;"
  );
  if (source !== beforeTable) changed = true;

  if (changed) {
    fs.writeFileSync(tabsFile, source);
    console.log("CRM side tabs now tolerate and label incomplete records.");
    changedAny = true;
  } else {
    console.log("Side-tab incomplete-record safety already applied or no anchors found.");
  }
}

if (!changedAny) console.log("CRM incomplete-record safety patch made no changes.");
