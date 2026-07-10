import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fontSourcePath = path.join(here, "server-fonts.js");
const trackerRuntimePath = path.join(here, ".server-fonts-tracker.js");

let source = await fs.readFile(fontSourcePath, "utf8");

const oldCrmToolbar = "function crmToolbar(){if(S.crmView==='edit')return '';const sort=crmSortValue();const selected=function(v){return sort===v?' selected':''};return '<div class=\"crmToolbar\"><input id=\"crmSearch\" placeholder=\"Search this CRM section...\" value=\"'+esc(crmSearchValue())+'\"><label>Sort by <select id=\"crmSort\"><option value=\"priority\"'+selected('priority')+'>Priority</option><option value=\"dateAdded\"'+selected('dateAdded')+'>Date added</option><option value=\"dateEdited\"'+selected('dateEdited')+'>Date edited</option><option value=\"az\"'+selected('az')+'>A-Z</option></select></label><p class=\"muted\" id=\"crmShownCount\">'+crmVisibleRows().length+' shown</p></div>'}";
const newCrmToolbar = "function crmToolbar(){if(S.crmView==='edit')return '';const sort=crmSortValue();const selected=function(v){return sort===v?' selected':''};return '<div class=\"crmToolbar\"><input id=\"crmSearch\" placeholder=\"Search '+esc(crmTitleForView())+'...\" value=\"'+esc(crmSearchValue())+'\"><label class=\"crmSortLabel\">Sort: <select id=\"crmSort\"><option value=\"priority\"'+selected('priority')+'>Highest priority</option><option value=\"az\"'+selected('az')+'>A-Z</option><option value=\"dateAdded\"'+selected('dateAdded')+'>Date added</option><option value=\"dateEdited\"'+selected('dateEdited')+'>Last edited</option></select></label><div class=\"crmActionButtons\"><button class=\"secondary\" onclick=\"(async()=>{this.disabled=true;this.textContent=\\\'Checking...\\\';await api(\\\'/api/records/priority-check\\\',{method:\\\'POST\\\',body:\\\'{}\\\'});await load();render()})().catch(function(err){alert(err.message||err)})\">AI Priority Check</button><button class=\"primary\" onclick=\"S.crmView=\\\'edit\\\';render()\">Edit Records</button></div><p class=\"muted\" id=\"crmShownCount\">'+crmVisibleRows().length+' shown</p></div>'}";

const crmGeneratedPatch = [
  "responsive = responsive.replace(\"#search{display:none!important}\", \"#search{display:none!important}.workspace #priorityCheck,.workspace #aiAdd{display:none!important}.crmToolbar input{display:block!important}.crmToolbar{display:flex!important}.crmToolbar select{border-radius:999px}.crmSortLabel{white-space:nowrap}.crmActionButtons{display:flex;gap:8px;flex-wrap:wrap}.crmActionButtons button{white-space:nowrap}\");",
  "responsive = responsive.replace(" + JSON.stringify(oldCrmToolbar) + ", " + JSON.stringify(newCrmToolbar) + ");"
].join("\n") + "\n";

const crmSearchRuntimePatch = `
const crmControlsNeedle = "let responsive = await fs.readFile(responsiveSourcePath, \\"utf8\\");";
if (source.includes(crmControlsNeedle)) {
  const crmGeneratedPatch = ${JSON.stringify(crmGeneratedPatch)};
  source = source.replace(crmControlsNeedle, crmControlsNeedle + "\\n" + crmGeneratedPatch);
}
`;

source = source.replace(
  'let source = await fs.readFile(analyticsSourcePath, "utf8");',
  'let source = await fs.readFile(analyticsSourcePath, "utf8");\n' + crmSearchRuntimePatch
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
