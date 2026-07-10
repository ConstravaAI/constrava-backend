import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "dashboard-section-tabs-v4";

const analyticsTabbedClientCode = String.raw`function analyticsContent(){
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
  const items=[['overview','Overview',events.length],['traffic','Traffic',pageViews],['sources','Sources',analyticsTopEntries(analyticsCounts(events,analyticsReferrer)).length],['pages','Pages',pages.size],['events','Events',events.length],['audience','Audience',sessions.size]];
  const nav='<aside class="crmSide"><div class="crmSideTitle">Analytics sections</div>'+items.map(function(item){return '<button class="crmTab '+(S.analyticsView===item[0]?'active':'')+'" data-analytics="'+item[0]+'"><span>'+item[1]+'</span><span>'+item[2]+'</span></button>'}).join('')+'</aside>';
  const hero='<section class="analyticsHero"><div class="analyticsTop"><div><div class="analyticsEyebrow">Tracker analytics</div><h2>Analytics command center</h2><p>Website and product activity organized into focused sections. CRM records, deals, tasks, and app data are excluded.</p></div>'+analyticsControls()+'</div><section class="analyticsKpis">'+analyticsKpi('Unique sessions',sessions.size,sessions.size,prevSessions.size,analyticsRangeLabel())+analyticsKpi('Total events',events.length,events.length,prev.length,'Captured activity')+analyticsKpi('Page views',pageViews,pageViews,prevPageViews,'Website traffic')+analyticsKpi('Form submits',forms,forms,prevForms,'Conversion events')+analyticsKpi('Conversion rate',conversion+'%',conversion,prevConversion,'Forms / views')+analyticsKpi('Active pages',pages.size,pages.size,0,'Tracked URLs')+'</section></section>';
  let body='';
  if(S.analyticsView==='overview')body=analyticsSection('Performance overview','Start here: overall movement and the most important takeaways.','<section class="analyticsGrid"><section class="analyticsCard"><div class="in"><div class="analyticsChartHead"><div><h3>Traffic trend</h3><p class="sub">Event volume across the selected window.</p></div><div class="analyticsNumber">'+events.length+'</div></div>'+analyticsTimeline(events)+'</div></section>'+analyticsSummary(events,pageViews,forms,conversion,pages,sessions)+'</section>');
  if(S.analyticsView==='traffic')body=analyticsSection('Traffic','A focused view of visits, activity volume, and timing.','<section class="analyticsGrid"><section class="analyticsCard"><div class="in"><div class="analyticsChartHead"><div><h3>Traffic trend</h3><p class="sub">Event volume across the selected window.</p></div><div class="analyticsNumber">'+events.length+'</div></div>'+analyticsTimeline(events)+'</div></section>'+analyticsHeatmap(events)+'</section>');
  if(S.analyticsView==='sources')body=analyticsSection('Sources','Where activity comes from and what type of intent is being captured.','<section class="analyticsSplit">'+analyticsRows('Top referrers',analyticsCounts(events,analyticsReferrer),8,'Where tracked visitors and sessions originate.')+analyticsRows('Event types',analyticsCounts(allEvents,function(e){return e.type||'unknown'}),8,'The main actions captured by the tracker.')+'</section><section style="margin-top:16px">'+analyticsDonut(events)+'</section>');
  if(S.analyticsView==='pages')body=analyticsSection('Pages','Which tracked pages are receiving activity and how dense that activity is.','<section class="analyticsGrid">'+analyticsPagesTable(events)+analyticsRows('Top paths',analyticsCounts(events,function(e){return analyticsPath(e.sourceUrl)}),10,'Pages ranked by captured tracker events.')+'</section>');
  if(S.analyticsView==='events')body=analyticsSection('Events','Recent raw tracker events for debugging and quick inspection.','<section class="analyticsGrid">'+analyticsEventStream(events)+analyticsRows('Event types',analyticsCounts(events,function(e){return e.type||'unknown'}),10,'Events currently matching the active filters.')+'</section>');
  if(S.analyticsView==='audience')body=analyticsSection('Audience context','Device, browser, and environment context from event metadata.','<section class="analyticsFooterGrid">'+analyticsRows('Browsers',analyticsCounts(events,analyticsBrowser),6,'Browser mix detected from event metadata.')+analyticsDeviceCards(events)+analyticsRows('Referrers',analyticsCounts(events,analyticsReferrer),6,'Top traffic sources in this section.')+'</section>');
  return '<div class="crmShell analyticsShell analyticsTabbedShell">'+nav+'<div>'+hero+body+'</div></div>';
}`;

let source = await fs.readFile(runtimeWrapperPath, "utf8");

if (!source.includes(marker)) {
  const writeNeedle = "await fs.writeFile(runtimePath, source);";
  const patch = String.raw`
// dashboard-section-tabs-v4
const crmActionVisibilityCode = "function syncCrmActionButtons(){var show=S.tab==='crm';['priorityCheck','aiAdd'].forEach(function(id){var el=document.getElementById(id);if(el)el.style.display=show?'':'none'})}";
if (!source.includes("function syncCrmActionButtons()")) {
  source = source.replace("function render(){", crmActionVisibilityCode + "\nfunction render(){");
  source = source.replace("app.innerHTML=h;bind();syncNotifications()", "app.innerHTML=h;bind();syncNotifications();syncCrmActionButtons()");
  source = source.replace("document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};", "document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};syncCrmActionButtons();");
}

const analyticsTabbedClientCode = ${JSON.stringify(analyticsTabbedClientCode)};
if (source.includes("function analyticsContent()") && !source.includes("analyticsTabbedShell")) {
  source = source.replace("function render(){", analyticsTabbedClientCode + "\nfunction render(){");
  source = source.replace("let analyticsRange=document.getElementById('analyticsRange');", "document.querySelectorAll('[data-analytics]').forEach(function(b){b.onclick=function(){S.analyticsView=b.dataset.analytics;render()}});let analyticsRange=document.getElementById('analyticsRange');");
}
`;

  if (!source.includes(writeNeedle)) throw new Error("Could not find runtime write target in src/server-runtime.js");
  source = source.replace(writeNeedle, `${patch}\n${writeNeedle}`);
  await fs.writeFile(runtimeWrapperPath, `${source}\n// ${marker}\n`);
}

await import("./server-account-persistence.js");
