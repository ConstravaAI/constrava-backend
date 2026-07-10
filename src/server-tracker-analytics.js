import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fontSourcePath = path.join(here, "server-fonts.js");
const trackerRuntimePath = path.join(here, ".server-fonts-tracker.js");

let source = await fs.readFile(fontSourcePath, "utf8");

const crmUiGeneratedPatch = "source = source.replace(\"function render(){\", \"function crmUiSyncHeaderTools(){const isCrm=S.tab==='crm';const topSearch=document.getElementById('search');if(topSearch){topSearch.value='';topSearch.hidden=true;topSearch.style.display='none';topSearch.setAttribute('aria-hidden','true')}['priorityCheck','aiAdd'].forEach(function(id){const el=document.getElementById(id);if(!el)return;el.hidden=!isCrm;el.style.display=isCrm?'':'none';el.setAttribute('aria-hidden',isCrm?'false':'true')});const ai=document.getElementById('aiAdd');if(ai&&isCrm){ai.textContent='Edit Records';if(!ai.dataset.crmUiEditBound){ai.dataset.crmUiEditBound='1';ai.addEventListener('click',function(){S.tab='crm';S.crmView='edit';render()})}}}\\nfunction crmSearchValue(){S.crmSearchByView ||= {};return S.crmSearchByView[S.crmView]||''}\\nfunction crmSetSearch(value){S.crmSearchByView ||= {};S.crmSearchByView[S.crmView]=value||''}\\nfunction crmSortValue(){S.crmSortByView ||= {};return S.crmSortByView[S.crmView]||'priority'}\\nfunction crmSetSort(value){S.crmSortByView ||= {};S.crmSortByView[S.crmView]=value||'priority'}\\nfunction crmTitleForView(){return S.crmView==='overview'?'High-priority CRM records':S.crmView==='all'?'All CRM Records':({Person:'Contacts',Company:'Companies',Deal:'Deals',Task:'Tasks',Intake:'Intakes',Note:'Notes'})[S.crmView]||S.crmView}\\nfunction crmBaseRows(){if(S.crmView==='overview')return S.records.filter(function(r){return Number(r.priorityScore||0)>=75});if(S.crmView==='all')return S.records;if(S.crmView==='edit')return [];return S.records.filter(function(r){return r.type===S.crmView})}\\nfunction crmSearchText(r){return [r.id,r.type,r.title,r.status,(r.tags||[]).join(' '),(r.priorityReasons||[]).join(' '),JSON.stringify(r.fields||{})].join(' ').toLowerCase()}\\nfunction crmVisibleRows(){let rows=crmBaseRows();const q=crmSearchValue().trim().toLowerCase();if(q)rows=rows.filter(function(r){return crmSearchText(r).includes(q)});rows=[...rows];const sort=crmSortValue();rows.sort(function(a,b){if(sort==='dateAdded')return String(b.createdAt||'').localeCompare(String(a.createdAt||''));if(sort==='dateEdited')return String(b.updatedAt||'').localeCompare(String(a.updatedAt||''));if(sort==='az')return String(a.title||'').localeCompare(String(b.title||''));return Number(b.priorityScore||0)-Number(a.priorityScore||0)});return rows}\\nfunction crmToolbar(){if(S.crmView==='edit')return '';const sort=crmSortValue();const selected=function(v){return sort===v?' selected':''};return '<div class=\\\"crmToolbar\\\"><input id=\\\"crmSearch\\\" placeholder=\\\"Search '+esc(crmTitleForView())+'...\\\" value=\\\"'+esc(crmSearchValue())+'\\\"><label>Sort by <select id=\\\"crmSort\\\"><option value=\\\"priority\\\"'+selected('priority')+'>Priority</option><option value=\\\"dateAdded\\\"'+selected('dateAdded')+'>Date added</option><option value=\\\"dateEdited\\\"'+selected('dateEdited')+'>Date edited</option><option value=\\\"az\\\"'+selected('az')+'>A-Z</option></select></label><p class=\\\"muted\\\" id=\\\"crmShownCount\\\">'+crmVisibleRows().length+' shown</p></div>'}\\nfunction crmRowsMarkup(){const rows=crmVisibleRows();if(!rows.length)return '<div class=\\\"crmEmpty\\\"><div><b>'+(crmSearchValue()?'No matching records':'No records here yet')+'</b><p>'+(crmSearchValue()?'Try a different search term.':'Add records or connect resources when you want this section filled.')+'</p></div></div>';return rows.map(recordRow).join('')}\\nfunction crmRecordBox(){return '<section class=\\\"card\\\"><div class=\\\"in\\\"><div class=\\\"crmListHead\\\"><div><h2>'+esc(crmTitleForView())+'</h2><p class=\\\"muted\\\">Search and sort this CRM section.</p></div></div>'+crmToolbar()+'<div id=\\\"crmRows\\\">'+crmRowsMarkup()+'</div></div></section>'}\\nfunction refreshCrmResults(){const rows=document.getElementById('crmRows');if(rows){rows.innerHTML=crmRowsMarkup();document.querySelectorAll('[data-edit-record]').forEach(function(b){b.onclick=function(){openRecordEditor(b.dataset.editRecord)}})}const count=document.getElementById('crmShownCount');if(count)count.textContent=crmVisibleRows().length+' shown'}\\nfunction crmContent(){if(S.crmView==='overview'){return crmShell('<div class=\\\"grid metrics\\\">'+metric('All records',S.records.length,'CRM objects')+metric('Contacts',crmCount('Person'),'People')+metric('Deals',crmCount('Deal'),money(S.summary.metrics.revenueOpportunity))+metric('Tasks',crmCount('Task'),'Follow-ups')+'</div><div style=\\\"margin-top:16px\\\">'+crmRecordBox()+'</div>')}if(S.crmView==='edit')return editRecordsContent();return crmShell(crmRecordBox())}\\nfunction render(){\");\nsource = source.replace(\"function bind(){\", \"function bind(){crmUiSyncHeaderTools();\");\nsource = source.replace(\"let typeSelect=document.getElementById('manualType');\", \"crmUiSyncHeaderTools();var crmSearchControl=document.getElementById('crmSearch');if(crmSearchControl)crmSearchControl.oninput=function(){crmSetSearch(crmSearchControl.value);refreshCrmResults()};var crmSortControl=document.getElementById('crmSort');if(crmSortControl)crmSortControl.onchange=function(){crmSetSort(crmSortControl.value);refreshCrmResults()};let typeSelect=document.getElementById('manualType');\");\n";

const crmSearchRuntimePatch = `
const crmSearchResponsiveNeedle = "let responsive = await fs.readFile(responsiveSourcePath, \\"utf8\\");";
if (source.includes(crmSearchResponsiveNeedle)) {
  const crmSearchCssPatch = [
    'responsive = responsive.replace("#search{display:block!important}", "#search{display:none!important}");',
    'responsive = responsive.replace("#search{display:none!important}", "#search{display:none!important}#priorityCheck,#aiAdd{display:none}");',
    'responsive = responsive.replace(".workspace input{min-width:min(420px,100%)}", ".workspace input{min-width:min(420px,100%)}.crmToolbar input{display:block!important}.crmToolbar{display:flex!important}");'
  ].join("\\n") + "\\n";
  source = source.replace(crmSearchResponsiveNeedle, crmSearchResponsiveNeedle + "\\n" + crmSearchCssPatch);
}
`;

const crmUiRuntimePatch =
  "const crmUiGeneratedPatch = " + JSON.stringify(crmUiGeneratedPatch) + ";\n" +
  "source = source.replace(" + JSON.stringify("JSON.stringify(generatedAnalyticsPatch)") + ", " + JSON.stringify("JSON.stringify(generatedAnalyticsPatch + crmUiGeneratedPatch)") + ");\n";

source = source.replace(
  'let source = await fs.readFile(analyticsSourcePath, "utf8");',
  'let source = await fs.readFile(analyticsSourcePath, "utf8");\n' + crmSearchRuntimePatch + crmUiRuntimePatch
);

const helperNeedle = "function analyticsCutoff(){return Date.now()-analyticsRangeDays()*86400000}\n";
const helperPatch = `function analyticsCutoff(){return Date.now()-analyticsRangeDays()*86400000}
function analyticsIsTrackerEvent(e){const m=e.metadata||{};const source=String(e.source||e.sourceType||e.sourceKind||m.source||m.sourceType||m.sourceKind||m.tracker||'').toLowerCase();return Boolean(e.siteId||e.sessionId||e.sourceUrl||e.referrer||source.includes('tracker')||source.includes('website')||source.includes('site'))}
function analyticsTrackerEvents(){return (S.events||[]).filter(analyticsIsTrackerEvent)}
`;
if (!source.includes(helperNeedle)) throw new Error("Could not find analytics cutoff helper.");
source = source.replace(helperNeedle, helperPatch);

source = source
  .replace(
    "function analyticsEvents(){const cutoff=analyticsCutoff();return (S.events||[]).filter(function(e){return analyticsRangeDays()>=99999||(Date.parse(e.createdAt||0)||0)>=cutoff})}",
    "function analyticsEvents(){const cutoff=analyticsCutoff();return analyticsTrackerEvents().filter(function(e){return analyticsRangeDays()>=99999||(Date.parse(e.createdAt||0)||0)>=cutoff})}"
  )
  .replace(
    "function analyticsPreviousEvents(){const days=analyticsRangeDays();if(days>=99999)return [];const now=Date.now(),start=now-days*86400000,prev=start-days*86400000;return (S.events||[]).filter(function(e){const t=Date.parse(e.createdAt||0)||0;return t>=prev&&t<start})}",
    "function analyticsPreviousEvents(){const days=analyticsRangeDays();if(days>=99999)return [];const now=Date.now(),start=now-days*86400000,prev=start-days*86400000;return analyticsTrackerEvents().filter(function(e){const t=Date.parse(e.createdAt||0)||0;return t>=prev&&t<start})}"
  )
  .replaceAll(
    "Standalone analytics. CRM records are not used.",
    "Website tracker script data only. CRM and app records are ignored."
  )
  .replaceAll(
    "Modern event analytics for Constrava website and product activity. This view is completely separate from CRM records, deals, tasks, and lead data.",
    "Modern analytics powered only by the Constrava website tracker script. CRM records, deals, tasks, and manually created app data are ignored for this view."
  )
  .replaceAll(
    "Latest product and website activity.",
    "Latest events captured by the tracker script."
  )
  .replaceAll(
    "Website traffic",
    "Tracker page views"
  )
  .replaceAll(
    "Captured activity",
    "Tracker events"
  );

await fs.writeFile(trackerRuntimePath, source);
await import(`${pathToFileURL(trackerRuntimePath).href}?v=${Date.now()}`);
