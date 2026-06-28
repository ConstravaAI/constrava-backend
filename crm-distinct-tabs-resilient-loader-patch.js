import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-distinct-tabs-resilient-loader-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldLoadEntries = `  async function loadEntries(){
    state.loading = true;
    try {
      const r = await fetch('/api/crm/entries?token=' + encodeURIComponent(token) + '&type=all', { cache:'no-store' });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Could not load CRM entries.');
      state.entries = j.entries || j.leads || [];
    } catch (err) {
      try { state.entries = (window.dashboardData && window.dashboardData.leads) || (window.data && window.data.leads) || []; } catch { state.entries = []; }
    }
    state.loading = false;
    render();
  }`;

const newLoadEntries = `  function normalizeCrmList(payload){
    if(!payload) return [];
    if(Array.isArray(payload)) return payload;
    const candidates = [
      payload.entries,
      payload.leads,
      payload.crm && payload.crm.leads,
      payload.data && payload.data.entries,
      payload.data && payload.data.leads,
      payload.payload && payload.payload.leads
    ].filter(Array.isArray);
    return candidates.sort((a,b)=>b.length-a.length)[0] || [];
  }

  async function loadEntries(){
    state.loading = true;
    const lists = [];
    async function tryFetch(url){
      try {
        const r = await fetch(url, { cache:'no-store' });
        const j = await r.json();
        const list = normalizeCrmList(j);
        if(list.length) lists.push(list);
      } catch {}
    }
    await tryFetch('/api/crm/entries?token=' + encodeURIComponent(token) + '&type=all');
    await tryFetch('/api/crm/leads?token=' + encodeURIComponent(token));
    try { const localList = normalizeCrmList(window.dashboardData || window.data || {}); if(localList.length) lists.push(localList); } catch {}
    state.entries = (lists.sort((a,b)=>b.length-a.length)[0] || []).map((e) => ({
      type: e.type || e.record_type || (/form|submission|lead/i.test([e.source,e.company,e.title,e.deal_name,e.notes].join(' ')) ? 'lead' : 'crm_entry'),
      ...e
    }));
    state.loading = false;
    render();
  }`;

if (source.includes(oldLoadEntries)) {
  source = source.replace(oldLoadEntries, newLoadEntries);
  changed = true;
}

const oldIsTask = `function isTask(e){ return /task|follow|todo|call|meeting/i.test([e.record_type,e.module,e.next_step,e.notes].join(' ')); }`;
const newIsTask = `function isTask(e){ return /task|todo|meeting/i.test([e.type,e.record_type,e.module].join(' ')) || /task|todo|meeting/i.test(String(e.notes || '')); }`;
if (source.includes(oldIsTask)) {
  source = source.replace(oldIsTask, newIsTask);
  changed = true;
}

const oldLeads = `  function leads(){
    const list = entries().filter(e => !isTask(e) && !isClosed(e));`;
const newLeads = `  function isLeadLike(e){
    const s = [e.type,e.record_type,e.module,e.source,e.provider,e.company,e.title,e.deal_name,e.notes].join(' ').toLowerCase();
    if(/client|customer|task|todo|meeting|closed lost/i.test(s)) return false;
    return /lead|form|submission|intake|called|emailed|website|quote|proposal|opportunity/i.test(s) || !!(e.name || e.email || e.phone || e.mobile);
  }

  function leads(){
    const list = entries().filter(e => isLeadLike(e) && !isTask(e) && !isClosed(e));`;
if (source.includes(oldLeads)) {
  source = source.replace(oldLeads, newLeads);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM distinct tabs now load from all available CRM sources.");
} else {
  console.log("CRM distinct tabs resilient loader already applied or anchors not found.");
}
