import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const scopeWrapperPath = path.join(here, "server-crm-actions-scope.js");
const generatedPath = path.join(here, ".server-crm-actions-scope.generated.js");

let patched = false;
try {
  const wrapper = await fs.readFile(scopeWrapperPath, "utf8");
  const encoded = wrapper.match(/const encoded = "([\s\S]*?)";/)?.[1];
  if (encoded) {
    let generated = Buffer.from(encoded, "base64").toString("utf8");

    const tabs = String.raw`function analyticsModeTab(key,label){const active=S.analyticsView===key;return '<button onclick="S.analyticsView=&quot;'+key+'&quot;;render()" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:9px 13px;font-weight:950">'+label+'</button>'}
function analyticsOverviewTab(){return analyticsModeTab('overview','Overview')}
function analyticsTrafficTab(){return analyticsModeTab('traffic','Traffic')}
function analyticsSourcesTab(){return analyticsModeTab('sources','Sources')}
function analyticsPagesTab(){return analyticsModeTab('pages','Pages')}
function analyticsEventsTab(){return analyticsModeTab('events','Events')}
function analyticsAudienceTab(){return analyticsModeTab('audience','Audience')}
function analyticsModeTabs(){return '<div class="analyticsLooseModeTabs">'+analyticsOverviewTab()+analyticsTrafficTab()+analyticsSourcesTab()+analyticsPagesTab()+analyticsEventsTab()+analyticsAudienceTab()+'</div>'}`;
    generated = generated.replace(/function analyticsModeTabs\(\)\{[\s\S]*?\}function analyticsLiveControl\(\)/, tabs + "\nfunction analyticsLiveControl()");

    const toolbar = String.raw`function analyticsTopBarBottom(){try{const labels=['Analytics','CRM','Connected Resources'];const nodes=[...document.querySelectorAll('header,nav,[role="navigation"],body>div,body>section,body>main,div')];let best=null;nodes.forEach(function(el){const text=(el.innerText||'').replace(/\s+/g,' ');if(!labels.every(function(label){return text.includes(label)}))return;const r=el.getBoundingClientRect();if(r.width<window.innerWidth*.5||r.height<32||r.height>120||r.top>4)return;if(!best||r.height<best.height)best={bottom:Math.round(r.bottom),height:r.height}});return best?best.bottom:69}catch(error){return 69}}
function analyticsSyncStickyToolbar(){requestAnimationFrame(function(){try{const bar=document.querySelector('.analyticsStickyToolbar');if(!bar)return;const top=analyticsTopBarBottom();document.documentElement.style.setProperty('--analytics-sticky-top',top+'px');document.documentElement.style.setProperty('--analytics-toolbar-pull','0px');requestAnimationFrame(function(){try{const pull=Math.max(0,Math.round(bar.getBoundingClientRect().top)-top);document.documentElement.style.setProperty('--analytics-toolbar-pull',pull+'px')}catch(error){}})}catch(error){}});return ''}
function analyticsLiveControl(){return '<button class="'+(S.analyticsLive?'primary':'secondary')+'" type="button" onclick="analyticsToggleLive()" style="border-radius:8px;padding:7px 10px;font-weight:900;box-shadow:none">'+(S.analyticsLive?'Live updating':'Live paused')+'</button>'}
function analyticsStatusItem(text){return '<span class="analyticsStatusItem">'+text+'</span>'}
function analyticsToolbarControls(){return '<div class="analyticsToolbarControlsWrap">'+analyticsControls()+'</div>'}
function analyticsPulseHeader(events,pages){analyticsSyncStickyToolbar();const last=events.length?[...events].sort(function(a,b){return analyticsTime(b)-analyticsTime(a)})[0]:null;return '<section class="analyticsToolbar analyticsStickyToolbar" style="position:sticky;top:var(--analytics-sticky-top,69px);z-index:20">'+'<div class="analyticsToolbarMain">'+analyticsModeTabs()+analyticsToolbarControls()+'</div>'+'<div class="analyticsToolbarStatus">'+analyticsLiveControl()+analyticsStatusItem('Last event: '+esc(last?(last.createdAt||'').slice(5,16).replace('T',' '):'none yet'))+analyticsStatusItem(pages.size+' active pages')+'</div></section>'}`;
    generated = generated.replace(/function analyticsLiveControl\(\)\{[\s\S]*?\}function analyticsPulseHeader\(events,pages\)\{[\s\S]*?\}function analyticsContent\(\)/, toolbar + "\nfunction analyticsContent()");

    const metrics = String.raw`function analyticsMetricRangeDefaults(){return {unique:'month',events:'month',pageViews:'month',forms:'month'}}
function analyticsMetricRange(key){S.analyticsMetricRanges=S.analyticsMetricRanges||analyticsMetricRangeDefaults();return S.analyticsMetricRanges[key]||analyticsMetricRangeDefaults()[key]||'month'}
function analyticsMetricRangeDays(range){return range==='day'?1:range==='week'?7:range==='quarter'?90:range==='all'?99999:30}
function analyticsMetricRangeLabel(range){return range==='day'?'Day':range==='week'?'Week':range==='quarter'?'3 months':range==='all'?'All time':'Month'}
function analyticsMetricEventsFor(key){const rows=S.events||[];const days=analyticsMetricRangeDays(analyticsMetricRange(key));if(days>=99999)return rows;const cutoff=Date.now()-days*86400000;return rows.filter(function(e){return (Date.parse(e.createdAt||0)||0)>=cutoff})}
function analyticsSetMetricRange(key,value){S.analyticsMetricRanges=S.analyticsMetricRanges||analyticsMetricRangeDefaults();S.analyticsMetricRanges[key]=value;render()}
function analyticsRefreshMetric(key){S.analyticsMetricRefreshing=key;render();const done=function(){S.analyticsMetricRefreshing=null;if(typeof analyticsEnsureLive==='function')analyticsEnsureLive();render()};try{if(typeof load==='function'){Promise.resolve(load()).then(done).catch(done)}else done()}catch(error){done()}}
function analyticsMetricsOpen(){return S.analyticsMetricsOpen!==false}
function analyticsToggleMetricsTray(){S.analyticsMetricsOpen=!analyticsMetricsOpen();render()}
function analyticsMetricRangeSelect(key){const current=analyticsMetricRange(key);return '<select class="analyticsMetricSelect" onchange="analyticsSetMetricRange(&quot;'+key+'&quot;,this.value)">'+[['day','Day'],['week','Week'],['month','Month'],['quarter','3 months'],['all','All']].map(function(o){return '<option value="'+o[0]+'" '+(current===o[0]?'selected':'')+'>'+o[1]+'</option>'}).join('')+'</select>'}
function analyticsMetricRefreshButton(key){return '<button class="analyticsMetricRefresh secondary" type="button" onclick="analyticsRefreshMetric(&quot;'+key+'&quot;)">'+(S.analyticsMetricRefreshing===key?'Updating':'Refresh')+'</button>'}
function analyticsMetricTrayHeader(open){return '<div class="analyticsMetricsTrayHeader"><div><p>Analytics metrics tray</p><span>'+(open?'Live counters expanded':'Live counters collapsed')+'</span></div><button class="secondary" type="button" onclick="analyticsToggleMetricsTray()">'+(open?'Collapse':'Expand')+'</button></div>'}
function analyticsMetricTray(cards){const open=analyticsMetricsOpen();return '<section class="analyticsMetricsTrayMenu">'+analyticsMetricTrayHeader(open)+(open?'<div class="analyticsMetricsTray">'+cards+'</div>':'')+'</section>'}
function analyticsMetricShell(key,title,value,note,controls){return '<section class="analyticsMetricCard"><div class="analyticsMetricCardTop"><p>'+esc(title)+'</p><div>'+(controls||'')+analyticsMetricRefreshButton(key)+'</div></div><div><b>'+esc(value)+'</b><span>'+esc(note)+'</span></div></section>'}
function analyticsUniqueSessionsMetric(){const rows=analyticsMetricEventsFor('unique');const sessions=new Set(rows.map(function(e){return e.sessionId||''}).filter(Boolean));return analyticsMetricShell('unique','Unique sessions',sessions.size,analyticsMetricRangeLabel(analyticsMetricRange('unique')),analyticsMetricRangeSelect('unique'))}
function analyticsTotalEventsMetric(){const rows=analyticsMetricEventsFor('events');return analyticsMetricShell('events','Total events',rows.length,analyticsMetricRangeLabel(analyticsMetricRange('events')),analyticsMetricRangeSelect('events'))}
function analyticsPageViewsMetric(){const rows=analyticsMetricEventsFor('pageViews').filter(function(e){return e.type==='page_view'});return analyticsMetricShell('pageViews','Page views',rows.length,analyticsMetricRangeLabel(analyticsMetricRange('pageViews')),analyticsMetricRangeSelect('pageViews'))}
function analyticsFormSubmitsMetric(){const rows=analyticsMetricEventsFor('forms').filter(function(e){return e.type==='form_submission'});return analyticsMetricShell('forms','Form submits',rows.length,analyticsMetricRangeLabel(analyticsMetricRange('forms')),analyticsMetricRangeSelect('forms'))}
function analyticsConversionRateMetric(){const rows=analyticsFilteredEvents();const views=rows.filter(function(e){return e.type==='page_view'}).length;const forms=rows.filter(function(e){return e.type==='form_submission'}).length;return analyticsMetricShell('conversion','Conversion rate',(views?Math.round(forms/views*100):0)+'%','Forms / views','')}
function analyticsActivePagesMetric(){const rows=analyticsFilteredEvents();const pages=new Set(rows.map(function(e){return analyticsPath(e.sourceUrl)}).filter(Boolean));return analyticsMetricShell('activePages','Active pages',pages.size,'Current view','')}
function analyticsDedicatedMetrics(){return analyticsMetricTray(analyticsUniqueSessionsMetric()+analyticsTotalEventsMetric()+analyticsPageViewsMetric()+analyticsFormSubmitsMetric()+analyticsConversionRateMetric()+analyticsActivePagesMetric())}`;
    generated = generated.replace("function analyticsContent(){", metrics + "\nfunction analyticsContent(){");

    generated = generated.replace("+analyticsPulseHeader(events,pages)+analyticsModeTabs()+'<div class=\"analyticsToolPanel\">", "+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">");
    generated = generated.replace("+analyticsPulseHeader(events,pages)+analyticsDedicatedMetrics()+'<div class=\"analyticsToolPanel\">", "+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">");
    generated = generated.replace("+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">", "+analyticsPulseHeader(events,pages)+analyticsDedicatedMetrics()+'<div class=\"analyticsToolPanel\">");
    generated = generated.replace('class="analyticsShell analyticsCommandCenter"', 'class="analyticsShell analyticsPageLayout"');
    generated = generated.replace(/body='<section class="analyticsKpis">'\+analyticsKpi\('Unique sessions'[\s\S]*?\+'<\/section>'\+analyticsSection\('Overview'/, "body=analyticsSection('Overview'");
    generated = generated.replace(/'<section class="analyticsKpis">'\+analyticsKpi\('Unique sessions'[\s\S]*?\+'<\/section>'\+analyticsSection\('Overview'/, "analyticsSection('Overview'");

    const styles = `
      /* analytics-toolbar-v1 */
      .analyticsToolbar{width:calc(100% + 48px)!important;max-width:none!important;box-sizing:border-box!important;margin:calc(-1 * var(--analytics-toolbar-pull,0px)) -24px 0 -24px!important;border-radius:0!important;padding:10px 14px!important;background:#f7fbff!important;background-image:none!important;border:0!important;border-bottom:1px solid #d9e3f2!important;box-shadow:0 10px 28px rgba(6,26,51,.06)!important;overflow:visible!important}
      .analyticsToolbarMain{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:12px!important;flex-wrap:wrap!important}.analyticsLooseModeTabs{display:flex!important;gap:8px!important;flex-wrap:wrap!important;align-items:center!important;margin-top:0!important}.analyticsToolbarControlsWrap{margin-left:auto!important}.analyticsToolbarControlsWrap>div,.analyticsToolbarControlsWrap .analyticsControls{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;flex-wrap:wrap!important}.analyticsToolbarControlsWrap p,.analyticsToolbarControlsWrap .sub,.analyticsToolbarControlsWrap .muted{display:none!important}.analyticsToolbarStatus{display:flex!important;gap:12px!important;align-items:center!important;flex-wrap:wrap!important;margin-top:8px!important}.analyticsStatusItem{color:#607089!important;font-size:13px!important;font-weight:850!important;line-height:1.4!important}
      .analyticsMetricsTrayMenu{display:block!important;width:100%!important;max-width:100%!important;box-sizing:border-box!important;margin:14px 0 0!important;border:1px solid #d9e3f2!important;background:#fff!important;border-radius:8px!important;padding:12px!important;box-shadow:0 10px 28px rgba(6,26,51,.06)!important}.analyticsMetricsTrayHeader{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:12px!important;flex-wrap:wrap!important;border-bottom:1px solid #d9e3f2!important;padding:0 0 10px!important;margin:0 0 10px!important}.analyticsMetricsTrayHeader p{margin:0!important;color:#061a33!important;font-size:12px!important;font-weight:950!important;letter-spacing:.06em!important;text-transform:uppercase!important}.analyticsMetricsTrayHeader span{display:block!important;margin-top:3px!important;color:#607089!important;font-size:12px!important;font-weight:850!important}.analyticsMetricsTrayHeader button,.analyticsMetricRefresh,.analyticsMetricSelect{min-height:28px!important;border-radius:7px!important;border:1px solid #cbd8ea!important;background:#f8fbff!important;color:#061a33!important;font-size:11px!important;font-weight:850!important;padding:4px 7px!important;box-shadow:none!important}.analyticsMetricsTrayHeader button{min-height:32px!important;font-size:12px!important;font-weight:900!important;padding:6px 10px!important}.analyticsMetricsTray{display:flex!important;flex-direction:row!important;flex-wrap:nowrap!important;align-items:stretch!important;gap:10px!important;width:100%!important;max-width:100%!important;box-sizing:border-box!important;overflow-x:auto!important;overflow-y:hidden!important;padding:0 0 5px!important;scrollbar-width:thin!important}.analyticsMetricCard{flex:1 1 0!important;min-width:142px!important;background:#f8fbff!important;border:1px solid #d9e3f2!important;border-radius:8px!important;box-shadow:none!important;padding:12px!important;box-sizing:border-box!important;display:flex!important;flex-direction:column!important;justify-content:space-between!important;gap:10px!important}.analyticsMetricCardTop{display:grid!important;gap:8px!important;align-items:start!important}.analyticsMetricCardTop p{margin:0!important;color:#061a33!important;font-size:11px!important;font-weight:950!important;letter-spacing:.06em!important;line-height:1.15!important;text-transform:uppercase!important}.analyticsMetricCardTop div{display:flex!important;gap:6px!important;flex-wrap:wrap!important;align-items:center!important}.analyticsMetricCard b{display:block!important;color:#061a33!important;font-size:30px!important;line-height:1!important;margin:0 0 6px!important;font-weight:950!important}.analyticsMetricCard span{color:#607089!important;font-size:12px!important;font-weight:850!important}
      @media(max-width:900px){.analyticsMetricCard{flex:0 0 170px!important}}@media(max-width:760px){.analyticsToolbar{width:calc(100% + 32px)!important;margin:calc(-1 * var(--analytics-toolbar-pull,0px)) -16px 0 -16px!important;padding:10px 12px!important}.analyticsToolbarMain{align-items:flex-start!important}.analyticsToolbarControlsWrap{margin-left:0!important;width:100%!important}.analyticsToolbarControlsWrap>div,.analyticsToolbarControlsWrap .analyticsControls{justify-content:flex-start!important}.analyticsMetricCard{flex:0 0 210px!important}}
    `;
    generated = generated.replace("</style>", styles + "</style>");

    await fs.writeFile(generatedPath, generated);
    patched = true;
  }
} catch (error) {
  patched = false;
}

if (patched) {
  await import(`${pathToFileURL(generatedPath).href}?v=${Date.now()}`);
} else {
  await import("./server-crm-actions-scope.js");
}
