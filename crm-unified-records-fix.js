import fs from "fs";

function writeIfChanged(file, next, label) {
  const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  if (current === next) {
    console.log(`[crm-unified-records-fix] ${label} already current.`);
    return false;
  }
  fs.writeFileSync(file, next);
  console.log(`[crm-unified-records-fix] Updated ${label}.`);
  return true;
}

function patchServer() {
  const target = "server.js";
  if (!fs.existsSync(target)) {
    console.warn("[crm-unified-records-fix] server.js not found; skipping backend record patch.");
    return;
  }

  let text = fs.readFileSync(target, "utf8");
  const start = text.indexOf("function mapLead(lead, i) {");
  const end = start >= 0 ? text.indexOf("async function getDashboardPayload(token)", start) : -1;

  if (start < 0 || end < 0) {
    console.warn("[crm-unified-records-fix] Could not find mapLead block; backend record patch skipped.");
  } else {
    const replacement = String.raw`function normalizeRecordTags(value) {
  if (Array.isArray(value)) return [...new Set(value.map((tag) => String(tag || "").trim()).filter(Boolean))];
  if (typeof value === "string") {
    const raw = value.trim();
    if (!raw) return [];
    try { return normalizeRecordTags(JSON.parse(raw)); } catch {}
    return [...new Set(raw.split(/[;,]/).map((tag) => tag.trim()).filter(Boolean))];
  }
  if (value && typeof value === "object") return normalizeRecordTags(Object.values(value).flat());
  return [];
}
function defaultProbabilityForStatus(status) {
  const key = String(status || "").toLowerCase();
  if (key.includes("closed won") || key === "won") return 100;
  if (key.includes("negotiation")) return 80;
  if (key.includes("proposal") || key.includes("quote")) return 60;
  if (key.includes("qualified")) return 40;
  if (key.includes("analysis") || key.includes("contacted")) return 20;
  if (key.includes("closed lost") || key === "lost") return 0;
  return 10;
}
function inferRecordModule(recordType, lead) {
  const explicit = String(valueFrom(lead, ["module", "crm_module", "record_module"], "") || "").trim().toLowerCase();
  if (explicit) return explicit.endsWith("s") ? explicit : `${explicit}s`;
  const type = String(recordType || "").toLowerCase();
  if (type.includes("contact")) return "contacts";
  if (type.includes("account") || type.includes("company")) return "accounts";
  if (type.includes("deal") || type.includes("opportunity")) return "deals";
  if (type.includes("activity") || type.includes("task") || type.includes("follow")) return "activities";
  return "leads";
}
function mapLead(lead, i) {
  const raw = lead?.raw_submission || lead?.payload || lead?.metadata || lead?.data || lead?.properties || {};
  const status = String(valueFrom(lead, ["status", "stage", "lead_status", "deal_stage"], "New"));
  const recordType = String(valueFrom(lead, ["record_type", "type", "kind", "object_type"], "lead"));
  const moduleName = inferRecordModule(recordType, lead);
  const value = Number(valueFrom(lead, ["value", "deal_value", "amount", "budget", "expected_revenue"], 2200 + i * 700)) || 2200 + i * 700;
  const probability = Number(valueFrom(lead, ["probability", "deal_probability", "confidence"], defaultProbabilityForStatus(status))) || defaultProbabilityForStatus(status);
  const tags = normalizeRecordTags(valueFrom(lead, ["tags", "labels", "categories"], []));
  const name = String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name"], "Demo Lead"));
  const company = String(valueFrom(lead, ["company", "organization", "account", "business", "business_name"], "—"));
  const dealName = String(valueFrom(lead, ["deal_name", "opportunity", "project", "service"], company && company !== "—" ? `${company} opportunity` : `${name} opportunity`));
  return {
    id: String(valueFrom(lead, ["record_id", "lead_id", "id", "crm_id"], `REC-${i + 1}`)),
    record_id: String(valueFrom(lead, ["record_id", "lead_id", "id", "crm_id"], `REC-${i + 1}`)),
    record_type: recordType,
    module: moduleName,
    name,
    email: String(valueFrom(lead, ["email", "lead_email", "contact_email", "email_address"], "lead@example.com")),
    phone: String(valueFrom(lead, ["phone", "phone_number", "mobile"], "")),
    company,
    account_name: company,
    title: String(valueFrom(lead, ["title", "role", "job_title"], "")),
    status,
    stage: status,
    source: String(valueFrom(lead, ["source", "channel", "campaign", "provider", "utm_source"], "Website")),
    owner: String(valueFrom(lead, ["owner", "assigned_to", "rep"], "Constrava Demo Team")),
    priority: String(valueFrom(lead, ["priority", "lead_priority"], probability >= 60 ? "High" : "Normal")),
    deal_name: dealName,
    value,
    probability,
    expected_revenue: Number(valueFrom(lead, ["expected_revenue", "forecast"], Math.round(value * probability / 100))) || Math.round(value * probability / 100),
    close_date: String(valueFrom(lead, ["close_date", "expected_close", "due_date"], "")),
    created_at: String(valueFrom(lead, ["created_at", "timestamp", "received_at", "inserted_at"], "")),
    last_contacted: String(valueFrom(lead, ["last_contacted", "last_activity", "updated_at"], "")),
    tags: [...new Set([...tags, moduleName, recordType].filter(Boolean))],
    notes: String(valueFrom(lead, ["notes", "message", "body", "comments", "description"], "")),
    raw_submission: raw
  };
}
`;
    text = text.slice(0, start) + replacement + text.slice(end);
  }

  const oldLine = "const leads = rawLeads.length ? rawLeads.map(mapLead) : demo.leads;";
  const newLine = "const leads = rawLeads.length ? rawLeads.map(mapLead) : (demo.leads || []).map(mapLead);\n  const records = leads;";
  if (text.includes(oldLine) && !text.includes("const records = leads;")) {
    text = text.replace(oldLine, newLine);
    text = text.replace("return { ...demo, usingFallback: false, dbConnected: hasDb(), site:", "return { ...demo, usingFallback: false, dbConnected: hasDb(), records, site:");
  }

  writeIfChanged(target, text, "server.js unified record mapping");
}

function patchDashboard() {
  const target = "dashboard.html";
  if (!fs.existsSync(target)) {
    console.warn("[crm-unified-records-fix] dashboard.html not found; skipping UI record patch.");
    return;
  }

  let html = fs.readFileSync(target, "utf8");
  const start = html.indexOf("function leads(){");
  const end = start >= 0 ? html.indexOf("function group(list,key){", start) : -1;
  if (start < 0 || end < 0) {
    console.warn("[crm-unified-records-fix] Could not find dashboard leads/filter block; UI record patch skipped.");
    return;
  }

  const replacement = String.raw`function normalizeRecordTags(v){if(Array.isArray(v))return [...new Set(v.map(x=>String(x||'').trim()).filter(Boolean))];if(typeof v==='string'){const raw=v.trim();if(!raw)return[];try{return normalizeRecordTags(JSON.parse(raw))}catch(e){}return [...new Set(raw.split(/[;,]/).map(x=>x.trim()).filter(Boolean))]}if(v&&typeof v==='object')return normalizeRecordTags(Object.values(v).flat());return[]}function crmRecordType(l){return String((l&&(l.record_type||l.type||l.kind||l.object_type))||'lead').toLowerCase()}function crmModule(l){const explicit=String((l&&(l.module||l.crm_module||l.record_module))||'').toLowerCase();if(explicit)return explicit.endsWith('s')?explicit:explicit+'s';const t=crmRecordType(l);if(t.includes('contact'))return'contacts';if(t.includes('account')||t.includes('company'))return'accounts';if(t.includes('deal')||t.includes('opportunity'))return'deals';if(t.includes('activity')||t.includes('task'))return'activities';return'leads'}function crmStage(l){return String((l&&(l.stage||l.status||l.lead_status||l.deal_stage))||'New')}function crmProbability(l,stage){const p=Number(l&&l.probability);if(Number.isFinite(p)&&p>0)return p;return prob[stage]||25}function leads(){return (((data&&data.records)||((data&&data.leads)||[]))||[]).map((l,i)=>{l=l||{};const st=crmStage(l);const module=crmModule(l);const type=crmRecordType(l);const value=n(l.value||l.deal_value||l.amount||l.budget||2200+i*700);const tags=[...new Set([...normalizeRecordTags(l.tags||l.labels||[]),module,type].filter(Boolean))];return {...l,id:String(l.id||l.record_id||l.lead_id||('REC-'+(i+1))),record_type:type,module:module,tags:tags,stage:st,status:st,probability:crmProbability(l,st),value:value,name:String(l.name||l.full_name||l.lead_name||l.contact_name||l.email||'Record '+(i+1)),email:String(l.email||l.lead_email||l.contact_email||''),phone:String(l.phone||l.phone_number||l.mobile||''),company:String(l.company||l.organization||l.account_name||l.business||'—'),source:String(l.source||l.channel||l.provider||'Website'),deal_name:String(l.deal_name||l.opportunity||l.project||((l.company||l.organization||'Record')+' opportunity')),priority:String(l.priority||((value>7500||crmProbability(l,st)>=60)?'High':'Normal')),notes:String(l.notes||l.message||l.body||l.comments||'')}})}function accountRecords(list){const by={};list.forEach(d=>{const key=String(d.company&&d.company!=='—'?d.company:d.email||d.name||'Unknown Account');if(!by[key])by[key]={...d,name:key,company:key,email:'',record_type:'account',module:'accounts',source:'Account rollup',value:0,notes:'Account view built from related CRM records.'};by[key].value+=n(d.value)});return Object.values(by)}function moduleRecords(module,list){module=module||activeCrm;const all=list||leads();if(module==='dashboards'||module==='home'||module==='feeds'||module==='reports'||module==='documents')return all;if(module==='vip')return all.filter(d=>String(d.priority).toLowerCase().includes('high')||String(d.priority).toLowerCase().includes('vip')||d.tags.some(t=>/vip|hot|priority/i.test(t))||n(d.value)>=7500||n(d.probability)>=60);if(module==='contacts')return all.filter(d=>d.email||d.phone||crmModule(d)==='contacts');if(module==='accounts')return accountRecords(all.filter(d=>d.company&&d.company!=='—'||crmModule(d)==='accounts'));if(module==='deals')return all.filter(d=>crmModule(d)==='deals'||d.deal_name||n(d.value)>0).map(d=>({...d,name:d.deal_name||d.name,record_type:d.record_type==='lead'?'deal':d.record_type,module:'deals'}));if(module==='activities')return all.map(d=>({...d,record_type:'activity',module:'activities',name:'Follow up with '+(d.name||d.company),notes:d.notes||'CRM follow-up task generated from this record.'}));return all.filter(d=>crmModule(d)==='leads'||crmRecordType(d).includes('lead')||crmRecordType(d).includes('form'))}function filtered(){const term=(id('crmSearch').value||'').toLowerCase(),stage=id('stageFilter').value;return moduleRecords(activeCrm,leads()).filter(d=>{const text=[d.name,d.email,d.phone,d.company,d.stage,d.status,d.source,d.notes,d.message,d.record_type,d.module,d.priority,d.deal_name,(d.tags||[]).join(' ')].join(' ').toLowerCase();return(!term||text.includes(term))&&(stage==='all'||d.stage===stage)})}function group`;

  html = html.slice(0, start) + replacement + html.slice(end + "function group".length);
  writeIfChanged(target, html, "dashboard.html typed CRM views");
}

try {
  patchServer();
  patchDashboard();
  console.log("[crm-unified-records-fix] Unified CRM record mapping and typed views are active.");
} catch (error) {
  console.warn("[crm-unified-records-fix] skipped after non-fatal error:", error && error.message ? error.message : error);
}
