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
function analyticsLiveControl(){return '<button class="secondary analyticsLiveButton" type="button" onclick="analyticsToggleLive()">'+(S.analyticsLive?'Live updating':'Live paused')+'</button>'}
function analyticsStatusItem(text){return '<span class="analyticsStatusItem">'+text+'</span>'}
function analyticsToolbarControls(){return '<div class="analyticsToolbarControlsWrap">'+analyticsControls().replace(/<p[\s\S]*?<\/p>/g,'')+'</div>'}
function analyticsPulseHeader(events,pages){analyticsSyncStickyToolbar();const last=events.length?[...events].sort(function(a,b){return analyticsTime(b)-analyticsTime(a)})[0]:null;return '<section class="analyticsToolbar analyticsStickyToolbar" style="position:sticky;top:var(--analytics-sticky-top,69px);z-index:20">'+'<div class="analyticsToolbarMain">'+analyticsModeTabs()+'<div class="analyticsToolbarMeta">'+analyticsToolbarControls()+analyticsLiveControl()+analyticsStatusItem('Last event: '+esc(last?(last.createdAt||'').slice(5,16).replace('T',' '):'none yet'))+analyticsStatusItem(pages.size+' active pages')+'</div></div></section>'}`;
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
function analyticsMetricRangeSelect(key){const current=analyticsMetricRange(key);return '<select class="analyticsMetricSelect" style="min-height:28px;border-radius:7px;border:1px solid #cbd8ea;background:#f8fbff;color:#061a33;font-size:11px;font-weight:850;padding:4px 7px;max-width:100%" onchange="analyticsSetMetricRange(&quot;'+key+'&quot;,this.value)">'+[['day','Day'],['week','Week'],['month','Month'],['quarter','3 months'],['all','All']].map(function(o){return '<option value="'+o[0]+'" '+(current===o[0]?'selected':'')+'>'+o[1]+'</option>'}).join('')+'</select>'}
function analyticsMetricRefreshButton(key){return '<button class="analyticsMetricRefresh secondary" type="button" style="min-height:28px;border-radius:7px;border:1px solid #cbd8ea;background:#f8fbff;color:#061a33;font-size:11px;font-weight:850;padding:4px 7px;box-shadow:none" onclick="analyticsRefreshMetric(&quot;'+key+'&quot;)">'+(S.analyticsMetricRefreshing===key?'Updating':'Refresh')+'</button>'}
function analyticsMetricTrayHeader(open){return '<div class="analyticsMetricsTrayHeader" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;border-bottom:1px solid #d9e3f2;padding:0 0 10px;margin:0 0 10px"><div><p style="margin:0;color:#061a33;font-size:12px;font-weight:950;letter-spacing:.06em;text-transform:uppercase">Analytics metrics tray</p><span style="display:block;margin-top:3px;color:#607089;font-size:12px;font-weight:850">'+(open?'Live counters expanded':'Live counters collapsed')+'</span></div><button class="secondary" type="button" style="min-height:32px;border-radius:7px;border:1px solid #cbd8ea;background:#f8fbff;color:#061a33;font-size:12px;font-weight:900;padding:6px 10px;box-shadow:none" onclick="analyticsToggleMetricsTray()">'+(open?'Collapse':'Expand')+'</button></div>'}
function analyticsMetricTray(cards){const open=analyticsMetricsOpen();return '<section class="analyticsMetricsTrayMenu" style="display:block;width:100%;max-width:100%;box-sizing:border-box;margin:14px 0 0;border:1px solid #d9e3f2;background:#fff;border-radius:8px;padding:12px;box-shadow:0 10px 28px rgba(6,26,51,.06)">'+analyticsMetricTrayHeader(open)+(open?'<div class="analyticsMetricsTray" style="display:flex!important;flex-direction:row!important;flex-wrap:nowrap!important;align-items:stretch!important;gap:10px!important;width:100%!important;max-width:100%!important;box-sizing:border-box!important;overflow-x:auto!important;overflow-y:hidden!important;padding:0 0 5px!important;scrollbar-width:thin">'+cards+'</div>':'')+'</section>'}
function analyticsMetricShell(key,title,value,note,controls){return '<section class="analyticsMetricCard" style="flex:0 0 calc((100% - 50px)/6)!important;min-width:142px!important;background:#f8fbff;border:1px solid #d9e3f2;border-radius:8px;box-shadow:none;padding:12px;box-sizing:border-box;display:flex!important;flex-direction:column!important;justify-content:space-between;gap:10px"><div class="analyticsMetricCardTop" style="display:grid;gap:8px;align-items:start"><p style="margin:0;color:#061a33;font-size:11px;font-weight:950;letter-spacing:.06em;line-height:1.15;text-transform:uppercase">'+esc(title)+'</p><div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">'+(controls||'')+analyticsMetricRefreshButton(key)+'</div></div><div><b style="display:block;color:#061a33;font-size:30px;line-height:1;margin:0 0 6px;font-weight:950">'+esc(value)+'</b><span style="color:#607089;font-size:12px;font-weight:850">'+esc(note)+'</span></div></section>'}
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
      /* analytics-toolbar-horizontal-v3 */
      .analyticsToolbar{width:calc(100% + 48px)!important;max-width:none!important;box-sizing:border-box!important;margin:calc(-1 * var(--analytics-toolbar-pull,0px)) -24px 0 -24px!important;border-radius:0!important;padding:8px 14px!important;background:#f7fbff!important;background-image:none!important;border:0!important;border-bottom:1px solid #d9e3f2!important;box-shadow:0 10px 28px rgba(6,26,51,.05)!important;overflow:visible!important}
      .analyticsToolbarMain{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important;flex-wrap:wrap!important}.analyticsLooseModeTabs{display:flex!important;gap:8px!important;flex-wrap:wrap!important;align-items:center!important;margin-top:0!important}.analyticsToolbarMeta{margin-left:auto!important;display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;flex-wrap:wrap!important}.analyticsToolbarControlsWrap{display:flex!important;align-items:center!important}.analyticsToolbarControlsWrap>div,.analyticsToolbarControlsWrap .analyticsControls{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;flex-wrap:wrap!important}.analyticsToolbarControlsWrap p,.analyticsToolbarControlsWrap .sub,.analyticsToolbarControlsWrap .muted{display:none!important}.analyticsToolbarMeta button,.analyticsToolbarMeta select{min-height:30px!important;border-radius:8px!important;border:1px solid #d5e1f1!important;background:#fff!important;color:#061a33!important;box-shadow:none!important;padding:6px 9px!important;font-size:12px!important;font-weight:850!important;line-height:1.1!important}.analyticsToolbarMeta .analyticsLiveButton{background:#eef4fb!important}.analyticsStatusItem{color:#607089!important;font-size:12px!important;font-weight:850!important;line-height:1.2!important;white-space:nowrap!important}
      .analyticsMetricsTrayMenu>.analyticsMetricsTray{display:flex!important;flex-direction:row!important;flex-wrap:nowrap!important;align-items:stretch!important}.analyticsMetricsTrayMenu>.analyticsMetricsTray>.analyticsMetricCard{flex:0 0 calc((100% - 50px)/6)!important;min-width:142px!important;max-width:none!important}.analyticsMetricCardTop p{color:#061a33!important}.analyticsMetricCard b{color:#061a33!important}.analyticsMetricCard span{color:#607089!important}
      @media(max-width:900px){.analyticsToolbarMeta{margin-left:0!important;justify-content:flex-start!important;width:100%!important}.analyticsMetricsTrayMenu>.analyticsMetricsTray>.analyticsMetricCard{flex:0 0 170px!important}}@media(max-width:760px){.analyticsToolbar{width:calc(100% + 32px)!important;margin:calc(-1 * var(--analytics-toolbar-pull,0px)) -16px 0 -16px!important;padding:8px 12px!important}.analyticsToolbarMain{align-items:flex-start!important}.analyticsToolbarMeta{width:100%!important}.analyticsToolbarControlsWrap>div,.analyticsToolbarControlsWrap .analyticsControls{justify-content:flex-start!important}.analyticsMetricsTrayMenu>.analyticsMetricsTray>.analyticsMetricCard{flex:0 0 210px!important}}
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
