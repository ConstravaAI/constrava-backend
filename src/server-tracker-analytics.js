import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fontSourcePath = path.join(here, "server-fonts.js");
const trackerRuntimePath = path.join(here, ".server-fonts-tracker.js");

let source = await fs.readFile(fontSourcePath, "utf8");

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
