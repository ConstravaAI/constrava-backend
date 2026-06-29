import fs from "fs";

const serverFile = "server.js";
const tabsFile = "crm-distinct-tabs.js";
let changedAny = false;

const serverHelper = `function normalizeCrmTypes(entry) {
  const src = entry && typeof entry === "object" ? entry : {};
  const out = [];
  function add(value) {
    if (Array.isArray(value)) return value.forEach(add);
    String(value || "").split(/[,|/]/).forEach((part) => {
      const t = part.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      if (t && !out.includes(t)) out.push(t);
    });
  }

  add(src.types);
  add(src.type);
  add(src.record_type);
  add(src.module);
  add(src.category);

  const text = [src.type, src.record_type, src.module, src.source, src.provider, src.company, src.title, src.deal_name, src.next_step, src.notes].join(" ").toLowerCase();
  const hasContact = !!(src.name || src.email || src.phone || src.mobile);
  const hasCompany = !!(src.company && !/unknown|individual/.test(String(src.company).toLowerCase()));

  if (/lead|called|emailed|reached out|quote|proposal|opportunity|interested|website|project|form|submission|intake/.test(text) || hasContact) add("lead");
  if (hasContact) add("person");
  if (hasCompany) add("company");
  if (Number(src.value || src.deal_value || src.budget || 0) > 0 || src.deal_name || /deal|proposal|quote|opportunity|purchase|sale/.test(text)) add("deal");
  if (src.next_step || /task|todo|follow up|call back|meeting|appointment/.test(text)) add("task");
  if (/form|google|submission|intake/.test(text)) add("intake");
  if (/client|customer/.test(text)) add("client");
  if (/purchase|order|payment|invoice|sale/.test(text)) add("purchase");

  if (!out.length) add("entry");
  const aliases = { leads:"lead", contacts:"person", people:"person", companies:"company", deals:"deal", tasks:"task", followups:"task", follow-ups:"task", forms:"intake", entries:"entry", crm_entry:"entry", crm-entry:"entry" };
  const normalized = out.map((t) => aliases[t] || t).filter(Boolean);
  return Array.from(new Set(normalized));
}
function primaryCrmType(entry) {
  const types = normalizeCrmTypes(entry);
  const order = ["client", "purchase", "lead", "deal", "person", "company", "task", "intake", "entry"];
  return order.find((t) => types.includes(t)) || types[0] || "entry";
}
`;

if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;

  if (!source.includes("function normalizeCrmTypes(entry)")) {
    const anchor = "function completeCrmEntry(input, siteId, text = \"\")";
    if (source.includes(anchor)) {
      source = source.replace(anchor, serverHelper + anchor);
      changed = true;
    } else {
      console.warn("[crm-multi-type-data-points-patch] Could not find completeCrmEntry anchor.");
    }
  }

  const beforeType = source;
  source = source.replace(
    /const entryType = entryCleanText\(src\.type \|\| src\.record_type \|\| src\.category \|\| \(String\(src\.module \|\| ""\)\.toLowerCase\(\)\.includes\("client"\) \? "client" : "lead"\)\);/g,
    "const entryTypes = normalizeCrmTypes(src);\n  const entryType = entryCleanText(src.type || primaryCrmType(src));"
  );
  source = source.replace(
    /const now = new Date\(\)\.toISOString\(\);\s*return \{/g,
    "const now = new Date().toISOString();\n  const entryTypes = normalizeCrmTypes(src);\n  const entryType = entryCleanText(src.type || primaryCrmType(src));\n  return {"
  );
  if (source !== beforeType) changed = true;

  const beforeReturnFields = source;
  source = source.replace(
    /type: entryType,\s*record_type:/g,
    "type: entryType,\n    types: entryTypes,\n    record_type:"
  );
  source = source.replace(
    /record_type: entryCleanText\(src\.record_type \|\| src\.type \|\| "crm_entry"\),\s*module: entryCleanText\(src\.module \|\| "leads"\),/g,
    "type: entryType,\n    types: entryTypes,\n    record_type: entryCleanText(src.record_type || src.type || entryType || \"crm_entry\"),\n    module: entryCleanText(src.module || (entryTypes.includes(\"lead\") ? \"leads\" : \"entries\")),"
  );
  if (source !== beforeReturnFields) changed = true;

  const beforePrompt = source;
  source = source.replaceAll(
    "Complete CRM fields include type,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type.",
    "Complete CRM fields include type,types,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type. `type` is the primary category. `types` is an array of every CRM tab/category the data point belongs to: lead, person, company, deal, task, intake, client, purchase, note, entry. One data point can have multiple types."
  );
  source = source.replaceAll(
    "Complete CRM fields include name,email,phone,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type.",
    "Complete CRM fields include type,types,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type. `type` is the primary category. `types` is an array of every CRM tab/category the data point belongs to: lead, person, company, deal, task, intake, client, purchase, note, entry. One data point can have multiple types."
  );
  source = source.replaceAll(
    "use type:'lead', module:'leads', record_type:'lead', status:'New'",
    "use type:'lead', types:['lead','person'], module:'leads', record_type:'lead', status:'New'"
  );
  source = source.replaceAll(
    "use module:'leads', record_type:'lead', status:'New'",
    "use type:'lead', types:['lead','person'], module:'leads', record_type:'lead', status:'New'"
  );
  if (source !== beforePrompt) changed = true;

  const beforeFilter = source;
  source = source.replace(
    /function filterCrmEntries\(entries, type, qText\) \{\s*let list = entries \|\| \[\];\s*const t = String\(type \|\| "all"\)\.toLowerCase\(\);/g,
    "function entryHasType(entry, tabType) { const types = normalizeCrmTypes(entry); return types.includes(String(tabType || '').toLowerCase()); }\nfunction filterCrmEntries(entries, type, qText) {\n  let list = (entries || []).map((e) => ({ ...e, type: e.type || primaryCrmType(e), types: normalizeCrmTypes(e) }));\n  const t = String(type || \"all\").toLowerCase();"
  );
  source = source.replace(
    /if \(t === "deals"\) list = list\.filter\(\(e\) => Number\(e\.value\) > 0 \|\| e\.deal_name\);/g,
    "if (t === \"deals\") list = list.filter((e) => entryHasType(e, \"deal\"));"
  );
  source = source.replace(
    /if \(t === "contacts"\) list = list\.filter\(\(e\) => e\.email \|\| e\.phone \|\| e\.mobile\);/g,
    "if (t === \"contacts\") list = list.filter((e) => entryHasType(e, \"person\"));"
  );
  source = source.replace(
    /if \(t === "tasks"\) list = list\.filter\(\(e\) => e\.next_step \|\| \/task\|follow\|call\|meeting\|todo\/i\.test\(String\(e\.record_type \|\| e\.module \|\| e\.notes \|\| ""\)\)\);/g,
    "if (t === \"tasks\") list = list.filter((e) => entryHasType(e, \"task\"));"
  );
  source = source.replace(
    /if \(t === "leads"\) list = list\.filter\(\(e\) => [^;]+;?/g,
    "if (t === \"leads\") list = list.filter((e) => entryHasType(e, \"lead\"));"
  );
  if (source !== beforeFilter) changed = true;

  if (changed) {
    fs.writeFileSync(serverFile, source);
    console.log("Unified CRM data points now support multiple types.");
    changedAny = true;
  } else {
    console.log("Server multi-type CRM data point patch already applied or no anchors found.");
  }
}

const clientHelper = `  function normalizeTypes(e){
    const out=[];
    function add(v){
      if(Array.isArray(v)) return v.forEach(add);
      String(v||'').split(/[,|/]/).forEach(p=>{ const t=p.trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,''); if(t && !out.includes(t)) out.push(t); });
    }
    add(e && e.types); add(e && e.type); add(e && e.record_type); add(e && e.module); add(e && e.category);
    const s=[e&&e.type,e&&e.record_type,e&&e.module,e&&e.source,e&&e.provider,e&&e.company,e&&e.title,e&&e.deal_name,e&&e.next_step,e&&e.notes].join(' ').toLowerCase();
    if(/lead|called|emailed|reached out|quote|proposal|opportunity|interested|website|project|form|submission|intake/.test(s) || !!(e&&e.name||e&&e.email||e&&e.phone||e&&e.mobile)) add('lead');
    if(!!(e&&e.name||e&&e.email||e&&e.phone||e&&e.mobile)) add('person');
    if(e&&e.company && !/unknown|individual/i.test(String(e.company))) add('company');
    if(Number(e&&e.value||0)>0 || e&&e.deal_name || /deal|proposal|quote|opportunity|purchase|sale/.test(s)) add('deal');
    if(e&&e.next_step || /task|todo|follow up|call back|meeting|appointment/.test(s)) add('task');
    if(/form|google|submission|intake/.test(s)) add('intake');
    if(/client|customer/.test(s)) add('client');
    if(/purchase|order|payment|invoice|sale/.test(s)) add('purchase');
    const aliases={leads:'lead',contacts:'person',people:'person',companies:'company',deals:'deal',tasks:'task','follow-ups':'task',forms:'intake',entries:'entry','crm-entry':'entry'};
    const normalized=out.map(t=>aliases[t]||t).filter(Boolean);
    return Array.from(new Set(normalized.length?normalized:['entry']));
  }
  function hasType(e,t){ return normalizeTypes(e).includes(String(t||'').toLowerCase()); }
`;

if (fs.existsSync(tabsFile)) {
  let source = fs.readFileSync(tabsFile, "utf8");
  let changed = false;

  if (!source.includes("function normalizeTypes(e)")) {
    const anchor = "  function getStatus(e)";
    if (source.includes(anchor)) {
      source = source.replace(anchor, clientHelper + anchor);
      changed = true;
    }
  }

  const beforePredicates = source;
  source = source.replace(/function isTask\(e\)\{[^}]+\}/g, "function isTask(e){ return hasType(e,'task'); }");
  source = source.replace(/function isDeal\(e\)\{[^}]+\}/g, "function isDeal(e){ return hasType(e,'deal'); }");
  source = source.replace(/function isForm\(e\)\{[^}]+\}/g, "function isForm(e){ return hasType(e,'intake') || hasType(e,'form'); }");
  if (source !== beforePredicates) changed = true;

  const beforeLoadMap = source;
  source = source.replace(
    /type: e\.type \|\| e\.record_type \|\| \(\/form\|submission\|lead\/i\.test\(\[e\.source,e\.company,e\.title,e\.deal_name,e\.notes\]\.join\(' '\)\) \? 'lead' : 'crm_entry'\),\s*\.\.\.e/g,
    "...e,\n      types: normalizeTypes(e),\n      type: e.type || normalizeTypes(e)[0] || 'entry'"
  );
  if (source !== beforeLoadMap) changed = true;

  const beforeTabs = source;
  source = source.replace(
    /const list = entries\(\)\.filter\(e => isLeadLike\(e\) && !isTask\(e\) && !isClosed\(e\)\);/g,
    "const list = entries().filter(e => hasType(e,'lead') && !isClosed(e));"
  );
  source = source.replace(
    /const list = entries\(\)\.filter\(e => !isTask\(e\) && !isClosed\(e\)\);/g,
    "const list = entries().filter(e => hasType(e,'lead') && !isClosed(e));"
  );
  source = source.replace(
    /const list = entries\(\)\.filter\(e => e\.name \|\| e\.email \|\| e\.phone \|\| e\.mobile\);/g,
    "const list = entries().filter(e => hasType(e,'person'));"
  );
  source = source.replace(
    /entries\(\)\.forEach\(e => \{ const c = e\.company \|\| 'Individual \/ Unknown Company';/g,
    "entries().filter(e => hasType(e,'company')).forEach(e => { const c = e.company || 'Individual / Unknown Company';"
  );
  source = source.replace(
    /const dealList = filtered\(entries\(\)\.filter\(isDeal\)\);/g,
    "const dealList = filtered(entries().filter(e => hasType(e,'deal')));"
  );
  source = source.replace(
    /const list = entries\(\)\.filter\(e => e\.next_step \|\| isTask\(e\)\);/g,
    "const list = entries().filter(e => hasType(e,'task'));"
  );
  if (source !== beforeTabs) changed = true;

  if (changed) {
    fs.writeFileSync(tabsFile, source);
    console.log("CRM side tabs now filter by multi-type data points.");
    changedAny = true;
  } else {
    console.log("Side-tab multi-type CRM data point patch already applied or no anchors found.");
  }
}

if (!changedAny) console.log("CRM multi-type data point patch made no changes.");
