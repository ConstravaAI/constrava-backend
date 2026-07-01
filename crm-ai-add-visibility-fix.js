import fs from "fs";

const target = "dashboard.html";

try {
  if (!fs.existsSync(target)) {
    console.warn("[crm-ai-add-visibility-fix] dashboard.html not found; skipping.");
    process.exit(0);
  }

  let html = fs.readFileSync(target, "utf8");
  const start = html.indexOf("function leads(){");
  const end = start >= 0 ? html.indexOf("function accountRecords(list){", start) : -1;

  if (start < 0 || end < 0) {
    console.warn("[crm-ai-add-visibility-fix] Could not find unified leads/accountRecords block; skipping.");
    process.exit(0);
  }

  const replacement = String.raw`function rawCrmRecords(){const d=data||{};const merged=[];function addAll(list){if(Array.isArray(list))list.forEach(x=>{if(x&&typeof x==='object')merged.push(x)})}addAll(d.records);addAll(d.leads);try{addAll(JSON.parse(sessionStorage.getItem('constravaCrmDemoAdds')||'[]'))}catch(e){}const seen=new Set();return merged.filter((x,i)=>{const key=String(x.record_id||x.lead_id||x.id||x.email&&x.email+'|'+(x.created_at||'')||x.name&&x.name+'|'+(x.company||'')+'|'+(x.deal_name||'')||'row-'+i);if(seen.has(key))return false;seen.add(key);return true})}function leads(){return rawCrmRecords().map((l,i)=>{l=l||{};const st=crmStage(l);const module=crmModule(l);const type=crmRecordType(l);const value=n(l.value||l.deal_value||l.amount||l.budget||2200+i*700);const tags=[...new Set([...normalizeRecordTags(l.tags||l.labels||[]),module,type].filter(Boolean))];return {...l,id:String(l.id||l.record_id||l.lead_id||('REC-'+(i+1))),record_type:type,module:module,tags:tags,stage:st,status:st,probability:crmProbability(l,st),value:value,name:String(l.name||l.full_name||l.lead_name||l.contact_name||l.email||'Record '+(i+1)),email:String(l.email||l.lead_email||l.contact_email||''),phone:String(l.phone||l.phone_number||l.mobile||''),company:String(l.company||l.organization||l.account_name||l.business||'—'),source:String(l.source||l.channel||l.provider||'Website'),deal_name:String(l.deal_name||l.opportunity||l.project||((l.company||l.organization||'Record')+' opportunity')),priority:String(l.priority||((value>7500||crmProbability(l,st)>=60)?'High':'Normal')),notes:String(l.notes||l.message||l.body||l.comments||'')}})}function accountRecords`;

  html = html.slice(0, start) + replacement + html.slice(end + "function accountRecords".length);
  fs.writeFileSync(target, html);
  console.log("[crm-ai-add-visibility-fix] Dashboard now merges data.records, data.leads, and session AI/demo records.");
} catch (error) {
  console.warn("[crm-ai-add-visibility-fix] skipped after non-fatal error:", error && error.message ? error.message : error);
}
