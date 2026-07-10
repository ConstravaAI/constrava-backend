import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "analytics-horizontal-tabs-v5";

const analyticsHorizontalTabsClientCode = String.raw`function analyticsContent(){
  S.analyticsRange=S.analyticsRange||'30';
  S.analyticsSource=S.analyticsSource||'all';
  S.analyticsView=S.analyticsView||'overview';
  const allEvents=analyticsEvents();
  const events=analyticsFilteredEvents();
  const prev=analyticsPreviousEvents();
  const sessions=new Set(events.map(function(e){return e.sessionId||''}).filter(Boolean));
  const prevSessions=new Set(prev.map(function(e){return e.sessionId||''}).filter(Boolean));
  const pageViews=events.filter(function(e){return e.type==='page_view'}).length;
  const prevPageViews=prev.filter(function(e){return e.type==='page_view'}).length;
  const forms=events.filter(function(e){return e.type==='form_submission'}).length;
  const prevForms=prev.filter(function(e){return e.type==='form_submission'}).length;
  const pages=new Set(events.map(function(e){return analyticsPath(e.sourceUrl)}));
  const conversion=pageViews?Math.round(forms/pageViews*100):0;
  const prevConversion=prevPageViews?Math.round(prevForms/prevPageViews*100):0;
  const items=[['overview','Overview'],['traffic','Traffic'],['sources','Sources'],['pages','Pages'],['events','Events'],['audience','Audience']];
  const hero='<section class="analyticsHero"><div class="analyticsTop"><div><div class="analyticsEyebrow">Tracker analytics</div><h2>Analytics command center</h2><p>Use the selector below to switch between focused analytics tool groups. CRM records, deals, tasks, and app data are excluded.</p></div>'+analyticsControls()+'</div></section>';
  const selector='<div class="analyticsModeTabs" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:white;border:1px solid var(--line);border-radius:18px;padding:8px;box-shadow:0 12px 32px rgba(6,26,51,.07)">'+items.map(function(item){const active=S.analyticsView===item[0];return '<button data-analytics="'+item[0]+'" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:10px 14px;font-weight:950">'+item[1]+'</button>'}).join('')+'</div>';
  let body='';
  if(S.analyticsView==='overview')body='<section class="analyticsKpis">'+analyticsKpi('Unique sessions',sessions.size,sessions.size,prevSessions.size,analyticsRangeLabel())+analyticsKpi('Total events',events.length,events.length,prev.length,'Captured activity')+analyticsKpi('Page views',pageViews,pageViews,prevPageViews,'Website traffic')+analyticsKpi('Form submits',forms,forms,prevForms,'Conversion events')+analyticsKpi('Conversion rate',conversion+'%',conversion,prevConversion,'Forms / views')+analyticsKpi('Active pages',pages.size,pages.size,0,'Tracked URLs')+'</section>'+analyticsSection('Overview tools','Only the top summary tools are shown here.', '<section class="analyticsGrid"><section class="analyticsCard"><div class="in"><div class="analyticsChartHead"><div><h3>Traffic trend</h3><p class="sub">Event volume across the selected window.</p></div><div class="analyticsNumber">'+events.length+'</div></div>'+analyticsTimeline(events)+'</div></section>'+analyticsSummary(events,pageViews,forms,conversion,pages,sessions)+'</section>');
  if(S.analyticsView==='traffic')body=analyticsSection('Traffic tools','Visits, activity volume, and timing tools only.', '<section class="analyticsGrid"><section class="analyticsCard"><div class="in"><div class="analyticsChartHead"><div><h3>Traffic trend</h3><p class="sub">Event volume across the selected window.</p></div><div class="analyticsNumber">'+events.length+'</div></div>'+analyticsTimeline(events)+'</div></section>'+analyticsHeatmap(events)+'</section>');
  if(S.analyticsView==='sources')body=analyticsSection('Source tools','Referrers, event mix, and acquisition-related tools only.', '<section class="analyticsSplit">'+analyticsRows('Top referrers',analyticsCounts(events,analyticsReferrer),8,'Where tracked visitors and sessions originate.')+analyticsRows('Event types',analyticsCounts(allEvents,function(e){return e.type||'unknown'}),8,'The main actions captured by the tracker.')+'</section><section style="margin-top:16px">'+analyticsDonut(events)+'</section>');
  if(S.analyticsView==='pages')body=analyticsSection('Page tools','Page and URL performance tools only.', '<section class="analyticsGrid">'+analyticsPagesTable(events)+analyticsRows('Top paths',analyticsCounts(events,function(e){return analyticsPath(e.sourceUrl)}),10,'Pages ranked by captured tracker events.')+'</section>');
  if(S.analyticsView==='events')body=analyticsSection('Event tools','Raw event and event-type inspection tools only.', '<section class="analyticsGrid">'+analyticsEventStream(events)+analyticsRows('Event types',analyticsCounts(events,function(e){return e.type||'unknown'}),10,'Events currently matching the active filters.')+'</section>');
  if(S.analyticsView==='audience')body=analyticsSection('Audience tools','Device, browser, and environment context tools only.', '<section class="analyticsFooterGrid">'+analyticsRows('Browsers',analyticsCounts(events,analyticsBrowser),6,'Browser mix detected from event metadata.')+analyticsDeviceCards(events)+analyticsRows('Referrers',analyticsCounts(events,analyticsReferrer),6,'Top traffic sources in this section.')+'</section>');
  return '<div class="analyticsShell analyticsHorizontalTabs">'+hero+selector+'<div class="analyticsToolPanel">'+body+'</div></div>';
}`;

let source = await fs.readFile(runtimeWrapperPath, "utf8");

if (!source.includes(marker)) {
  const writeNeedle = "await fs.writeFile(runtimePath, source);";
  const patch = String.raw`
// analytics-horizontal-tabs-v5
const crmActionVisibilityCode = "function syncCrmActionButtons(){var show=S.tab==='crm';['priorityCheck','aiAdd'].forEach(function(id){var el=document.getElementById(id);if(el)el.style.display=show?'':'none'})}";
if (!source.includes("function syncCrmActionButtons()")) {
  source = source.replace("function render(){", crmActionVisibilityCode + "\nfunction render(){");
  source = source.replace("app.innerHTML=h;bind();syncNotifications()", "app.innerHTML=h;bind();syncNotifications();syncCrmActionButtons()");
  source = source.replace("document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};", "document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};syncCrmActionButtons();");
}

const analyticsHorizontalTabsClientCode = ${JSON.stringify(analyticsHorizontalTabsClientCode)};
if (source.includes("function analyticsContent()") && !source.includes("analyticsHorizontalTabs")) {
  source = source.replace("function render(){", analyticsHorizontalTabsClientCode + "\nfunction render(){");
}
if (!source.includes("[data-analytics]") && source.includes("let analyticsRange=document.getElementById('analyticsRange');")) {
  source = source.replace("let analyticsRange=document.getElementById('analyticsRange');", "document.querySelectorAll('[data-analytics]').forEach(function(b){b.onclick=function(){S.analyticsView=b.dataset.analytics;render()}});let analyticsRange=document.getElementById('analyticsRange');");
}
`;

  if (!source.includes(writeNeedle)) throw new Error("Could not find runtime write target in src/server-runtime.js");
  source = source.replace(writeNeedle, `${patch}\n${writeNeedle}`);
  await fs.writeFile(runtimeWrapperPath, `${source}\n// ${marker}\n`);
}

await import("./server-account-persistence.js");