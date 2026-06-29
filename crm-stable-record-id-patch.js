import fs from "fs";

const serverFile = "server.js";
const tabsFile = "crm-distinct-tabs.js";
let changedAny = false;

const serverHelper = `function ensureCrmRecordId(entry) {
  const src = entry && typeof entry === "object" ? entry : {};
  const existing = String(src.id || src.record_id || src.lead_id || src.crm_id || "").trim();
  const id = existing || "CRM-" + randomBytes(5).toString("hex").toUpperCase();
  return { ...src, id, record_id: id, lead_id: src.lead_id || id };
}
`;

if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;

  if (!source.includes("function ensureCrmRecordId(entry)")) {
    const anchor = "function normalizeIncompleteCrmEntry(entry";
    if (source.includes(anchor)) {
      source = source.replace(anchor, serverHelper + anchor);
      changed = true;
    } else {
      const fallback = "function completeCrmEntry(input, siteId, text = \"\")";
      if (source.includes(fallback)) {
        source = source.replace(fallback, serverHelper + fallback);
        changed = true;
      } else {
        console.warn("[crm-stable-record-id-patch] Could not find record helper anchor.");
      }
    }
  }

  const beforeIncomplete = source;
  source = source.replace(
    /return safe;\s*}\s*function mergeEntryUpdate/g,
    "return ensureCrmRecordId(safe);\n}\nfunction mergeEntryUpdate"
  );
  if (source !== beforeIncomplete) changed = true;

  const beforeComplete = source;
  source = source.replace(
    /raw_submission: src\.raw_submission \|\| \{ plain_text: text, interpreted_entry: src \}\s*\};\s*}\s*function mergeEntryUpdate/g,
    "raw_submission: src.raw_submission || { plain_text: text, interpreted_entry: src }\n  });\n}\nfunction mergeEntryUpdate"
  );
  source = source.replace(
    /return \{\s*lead_id: entryCleanText\(src\.lead_id \|\| src\.id \|\| "CRM-" \+ randomBytes\(5\)\.toString\("hex"\)\.toUpperCase\(\)\),/g,
    "return ensureCrmRecordId({\n    lead_id: entryCleanText(src.lead_id || src.id || src.record_id || \"\"),"
  );
  if (source !== beforeComplete) changed = true;

  const beforeList = source;
  source = source.replace(
    /normalizeIncompleteCrmEntry\(mapLead\(lead, i\), siteId, ''\)/g,
    "ensureCrmRecordId(normalizeIncompleteCrmEntry(mapLead(lead, i), siteId, ''))"
  );
  source = source.replace(
    /\(\{ \.\.\.e, type: e\.type \|\| primaryCrmType\(e\), types: normalizeCrmTypes\(e\) \}\)/g,
    "ensureCrmRecordId({ ...e, type: e.type || primaryCrmType(e), types: normalizeCrmTypes(e) })"
  );
  if (source !== beforeList) changed = true;

  const beforeSave = source;
  source = source.replace(
    /await saveCrmEntryCompat\(siteId, token, finalEntry\);/g,
    "finalEntry = ensureCrmRecordId(finalEntry);\n      await saveCrmEntryCompat(siteId, token, finalEntry);"
  );
  if (source !== beforeSave) changed = true;

  if (changed) {
    fs.writeFileSync(serverFile, source);
    console.log("All CRM records now receive stable universal IDs.");
    changedAny = true;
  } else {
    console.log("Server stable CRM record ID patch already applied or no anchors found.");
  }
}

const clientHelper = `  function ensureClientRecordId(e){
    const id = String((e && (e.id || e.record_id || e.lead_id || e.crm_id)) || '').trim() || ('CRM-TEMP-' + Math.random().toString(16).slice(2,10).toUpperCase());
    return { ...(e || {}), id, record_id:id, lead_id:(e && e.lead_id) || id };
  }
`;

if (fs.existsSync(tabsFile)) {
  let source = fs.readFileSync(tabsFile, "utf8");
  let changed = false;

  if (!source.includes("function ensureClientRecordId(e)")) {
    const anchor = "  function normalizeIncompleteClient(e)";
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

  const beforeClientNormalize = source;
  source = source.replace(
    /return \{\s*\.\.\.\(e \|\| \{\}\),/g,
    "return ensureClientRecordId({\n      ...(e || {}),"
  );
  source = source.replace(
    /data_quality: \(e && e\.data_quality\) \|\| \(missing\.length \? 'incomplete' : 'complete'\)\s*\};/g,
    "data_quality: (e && e.data_quality) || (missing.length ? 'incomplete' : 'complete')\n    });"
  );
  if (source !== beforeClientNormalize) changed = true;

  const beforeEntries = source;
  source = source.replace(
    /function entries\(\)\{ return Array\.isArray\(state\.entries\) \? state\.entries\.filter\(isRealCrmEntry\) : \[\]; \}/g,
    "function entries(){ return Array.isArray(state.entries) ? state.entries.filter(isRealCrmEntry).map(ensureClientRecordId) : []; }"
  );
  if (source !== beforeEntries) changed = true;

  if (changed) {
    fs.writeFileSync(tabsFile, source);
    console.log("CRM side tabs now guarantee IDs for every displayed record.");
    changedAny = true;
  } else {
    console.log("Side-tab stable CRM record ID patch already applied or no anchors found.");
  }
}

if (!changedAny) console.log("CRM stable record ID patch made no changes.");
