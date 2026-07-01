import fs from "fs";

function writeIfChanged(file, next, label) {
  const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  if (current === next) {
    console.log(`[crm-record-type-required-fix] ${label} already current.`);
    return false;
  }
  fs.writeFileSync(file, next);
  console.log(`[crm-record-type-required-fix] Updated ${label}.`);
  return true;
}

function patchServer() {
  const target = "server.js";
  if (!fs.existsSync(target)) return console.warn("[crm-record-type-required-fix] server.js not found; skipping backend patch.");
  let text = fs.readFileSync(target, "utf8");

  if (!text.includes("function guessRecordType(lead)")) {
    const marker = "function inferRecordModule(recordType, lead) {";
    const helper = String.raw`function cleanRecordType(value) {
  const raw = String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  if (!raw || raw === "record" || raw === "crm_record" || raw === "item" || raw === "crm_item") return "";
  return raw;
}
function guessRecordType(lead) {
  const explicit = cleanRecordType(valueFrom(lead, ["record_type", "type", "kind", "object_type"], ""));
  if (explicit) return explicit;

  const moduleName = String(valueFrom(lead, ["module", "crm_module", "record_module"], "") || "").toLowerCase();
  if (moduleName.includes("vip")) return "vip_lead";
  if (moduleName.includes("deal")) return "deal";
  if (moduleName.includes("account")) return "account";
  if (moduleName.includes("contact")) return "contact";
  if (moduleName.includes("activit")) return "activity";
  if (moduleName.includes("document")) return "document";
  if (moduleName.includes("report")) return "report";
  if (moduleName.includes("feed")) return "feed_update";
  if (moduleName.includes("dashboard")) return "dashboard_component";

  const raw = lead?.raw_submission || lead?.payload || lead?.metadata || lead?.data || lead?.properties || {};
  const tags = normalizeRecordTags(valueFrom(lead, ["tags", "labels", "categories"], []));
  const source = String(valueFrom(lead, ["source", "provider", "channel", "campaign", "utm_source"], ""));
  const dealName = String(valueFrom(lead, ["deal_name", "opportunity", "project", "service"], ""));
  const notes = String(valueFrom(lead, ["notes", "message", "body", "comments", "description"], ""));
  const text = [source, dealName, notes, tags.join(" "), JSON.stringify(raw || {})].join(" ").toLowerCase();

  if (/google\s*forms|typeform|tally|jotform|external form|form submission|form_lead/.test(text)) return "external_form_lead";
  if (/website form|web lead|contact page|site form/.test(text)) return "website_form_lead";
  if (/csv|spreadsheet|import/.test(text)) return "csv_import_lead";
  if (/email|inbox|thread|reply/.test(text)) return "email_activity";
  if (/call|voicemail|phone conversation/.test(text)) return "call_log";
  if (/task|todo|to do|follow\s*up|due date/.test(text)) return "task";
  if (/api|webhook|payload|endpoint/.test(text)) return "api_payload";
  if (/automation|rule|score|workflow run/.test(text)) return "automation_run";
  if (/report|summary|analysis/.test(text)) return "report";
  if (/document|file|proposal pdf|contract/.test(text)) return "document";
  if (/deal|opportunity|proposal|quote|estimate|budget|project value|pricing|closed won|closed lost|negotiation/.test(text)) return "deal";

  const hasCompany = !!String(valueFrom(lead, ["company", "organization", "account", "business", "business_name"], "")).trim();
  const hasPerson = !!String(valueFrom(lead, ["name", "full_name", "lead_name", "contact_name", "first_name", "last_name"], "")).trim();
  const hasEmailOrPhone = !!String(valueFrom(lead, ["email", "lead_email", "contact_email", "email_address", "phone", "phone_number", "mobile"], "")).trim();
  const hasValue = Number(valueFrom(lead, ["value", "deal_value", "amount", "budget", "expected_revenue"], 0)) > 0;

  if (hasValue && (dealName || hasCompany)) return "deal";
  if (hasEmailOrPhone && !hasPerson && !hasCompany) return "contact";
  if (hasEmailOrPhone || hasPerson) return source.toLowerCase().includes("ai") ? "ai_text_lead" : "lead";
  if (hasCompany) return "account";
  return "lead";
}
`;
    if (text.includes(marker)) text = text.replace(marker, helper + "\n" + marker);
  }

  text = text.replace(
    'const recordType = String(valueFrom(lead, ["record_type", "type", "kind", "object_type"], "lead"));',
    'const recordType = guessRecordType(lead);'
  );

  text = text.replace(
    'tags: [...new Set([...tags, moduleName, recordType].filter(Boolean))],',
    'tags: [...new Set([...tags, moduleName, recordType, "typed-record"].filter(Boolean))],'
  );

  writeIfChanged(target, text, "backend required record type inference");
}

function patchDashboard() {
  const target = "dashboard.html";
  if (!fs.existsSync(target)) return console.warn("[crm-record-type-required-fix] dashboard.html not found; skipping UI patch.");
  let html = fs.readFileSync(target, "utf8");

  const pattern = /function crmRecordType\(l\)\{return String\(\(l&&\(l\.record_type\|\|l\.type\|\|l\.kind\|\|l\.object_type\)\)\|\|'lead'\)\.toLowerCase\(\)\}/;
  const replacement = String.raw`function crmCleanRecordType(v){const raw=String(v||'').trim().toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'');return(!raw||raw==='record'||raw==='crm_record'||raw==='item'||raw==='crm_item')?'':raw}function crmRecordType(l){l=l||{};const explicit=crmCleanRecordType(l.record_type||l.type||l.kind||l.object_type);if(explicit)return explicit;const module=String(l.module||l.crm_module||l.record_module||'').toLowerCase();if(module.includes('vip'))return'vip_lead';if(module.includes('deal'))return'deal';if(module.includes('account'))return'account';if(module.includes('contact'))return'contact';if(module.includes('activit'))return'activity';if(module.includes('document'))return'document';if(module.includes('report'))return'report';if(module.includes('feed'))return'feed_update';if(module.includes('dashboard'))return'dashboard_component';const tags=normalizeRecordTags(l.tags||l.labels||[]).join(' ');let raw='';try{raw=JSON.stringify(l.raw_submission||l.payload||l.metadata||{})}catch(e){}const text=[l.source,l.provider,l.channel,l.deal_name,l.opportunity,l.project,l.service,l.notes,l.message,l.body,l.description,tags,raw].join(' ').toLowerCase();if(/google\s*forms|typeform|tally|jotform|external form|form submission|form_lead/.test(text))return'external_form_lead';if(/website form|web lead|contact page|site form/.test(text))return'website_form_lead';if(/csv|spreadsheet|import/.test(text))return'csv_import_lead';if(/email|inbox|thread|reply/.test(text))return'email_activity';if(/call|voicemail|phone conversation/.test(text))return'call_log';if(/task|todo|to do|follow\s*up|due date/.test(text))return'task';if(/api|webhook|payload|endpoint/.test(text))return'api_payload';if(/automation|rule|score|workflow run/.test(text))return'automation_run';if(/report|summary|analysis/.test(text))return'report';if(/document|file|proposal pdf|contract/.test(text))return'document';if(/deal|opportunity|proposal|quote|estimate|budget|project value|pricing|closed won|closed lost|negotiation/.test(text))return'deal';const hasCompany=!!String(l.company||l.organization||l.account_name||l.business||'').trim();const hasPerson=!!String(l.name||l.full_name||l.first_name||l.last_name||'').trim();const hasContact=!!String(l.email||l.phone||l.contact_email||l.phone_number||'').trim();const hasValue=Number(l.value||l.deal_value||l.amount||l.budget||0)>0;if(hasValue&&(l.deal_name||hasCompany))return'deal';if(hasContact&&!hasPerson&&!hasCompany)return'contact';if(hasContact||hasPerson)return String(l.source||'').toLowerCase().includes('ai')?'ai_text_lead':'lead';if(hasCompany)return'account';return'lead'}`;

  if (pattern.test(html)) {
    html = html.replace(pattern, replacement);
  } else if (!html.includes("function crmCleanRecordType(")) {
    console.warn("[crm-record-type-required-fix] Could not find crmRecordType function to replace.");
  }

  html = html.replace(
    "const tags=[...new Set([...normalizeRecordTags(l.tags||l.labels||[]),module,type].filter(Boolean))];",
    "const tags=[...new Set([...normalizeRecordTags(l.tags||l.labels||[]),module,type,'typed-record'].filter(Boolean))];"
  );

  writeIfChanged(target, html, "frontend required record type inference");
}

try {
  patchServer();
  patchDashboard();
  console.log("[crm-record-type-required-fix] Every CRM record now receives a required guessed record_type.");
} catch (error) {
  console.warn("[crm-record-type-required-fix] skipped after non-fatal error:", error && error.message ? error.message : error);
}
