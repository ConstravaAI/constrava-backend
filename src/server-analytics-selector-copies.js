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

    const separatedModeTabsCode = String.raw`function analyticsModeTab(key,label){const active=S.analyticsView===key;return '<button onclick="S.analyticsView=&quot;'+key+'&quot;;render()" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:9px 13px;font-weight:950">'+label+'</button>'}
function analyticsOverviewTab(){return analyticsModeTab('overview','Overview')}
function analyticsTrafficTab(){return analyticsModeTab('traffic','Traffic')}
function analyticsSourcesTab(){return analyticsModeTab('sources','Sources')}
function analyticsPagesTab(){return analyticsModeTab('pages','Pages')}
function analyticsEventsTab(){return analyticsModeTab('events','Events')}
function analyticsAudienceTab(){return analyticsModeTab('audience','Audience')}
function analyticsModeTabs(){return '<div class="analyticsLooseModeTabs" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px">'+analyticsOverviewTab()+analyticsTrafficTab()+analyticsSourcesTab()+analyticsPagesTab()+analyticsEventsTab()+analyticsAudienceTab()+'</div>'}`;
    generated = generated.replace(/function analyticsModeTabs\(\)\{[\s\S]*?\}function analyticsLiveControl\(\)/, separatedModeTabsCode + "\nfunction analyticsLiveControl()");

    const separatedPulseHeaderCode = String.raw`function analyticsTopBarBottom(){try{const labels=['Analytics','CRM','Connected Resources'];const nodes=[...document.querySelectorAll('header,nav,[role="navigation"],body>div,body>section,body>main,div')];let best=null;nodes.forEach(function(el){const text=(el.innerText||'').replace(/\s+/g,' ');if(!labels.every(function(label){return text.includes(label)}))return;const r=el.getBoundingClientRect();if(r.width<window.innerWidth*.5||r.height<32||r.height>120||r.top>4)return;if(!best||r.height<best.height)best={bottom:Math.round(r.bottom),height:r.height}});return best?best.bottom:69}catch(error){return 69}}
function analyticsSyncStickyCommandCenter(){requestAnimationFrame(function(){try{const banner=document.querySelector('.analyticsStickyCommandCenter');if(!banner)return;const top=analyticsTopBarBottom();document.documentElement.style.setProperty('--analytics-sticky-top',top+'px');document.documentElement.style.setProperty('--analytics-command-pull','0px');requestAnimationFrame(function(){try{const currentTop=Math.round(banner.getBoundingClientRect().top);const pull=Math.max(0,currentTop-top);document.documentElement.style.setProperty('--analytics-command-pull',pull+'px')}catch(error){}})}catch(error){}});return ''}
function analyticsLiveControl(){return '<button class="'+(S.analyticsLive?'primary':'secondary')+'" type="button" onclick="analyticsToggleLive()" style="border-radius:8px;padding:7px 10px;font-weight:900;box-shadow:none">'+(S.analyticsLive?'Live updating':'Live paused')+'</button>'}
function analyticsStatusItem(text){return '<span class="analyticsStatusItem" style="color:#607089;font-size:13px;font-weight:850;line-height:1.4">'+text+'</span>'}
function analyticsPulseHeader(events,pages){analyticsSyncStickyCommandCenter();const last=events.length?[...events].sort(function(a,b){return analyticsTime(b)-analyticsTime(a)})[0]:null;return '<section class="analyticsHero analyticsStickyCommandCenter" style="position:sticky;top:var(--analytics-sticky-top,69px);z-index:20;width:calc(100% + 48px);max-width:none;box-sizing:border-box;margin:calc(-1 * var(--analytics-command-pull, 0px)) -24px 0 -24px;border-radius:0"><div class="analyticsTop"><div><div class="analyticsEyebrow">'+(S.analyticsLive?'Live analytics':'Manual refresh')+'</div><h2>Analytics command center</h2>'+analyticsModeTabs()+'</div>'+analyticsControls()+'</div><div class="analyticsStatusLine" style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-top:10px">'+analyticsLiveControl()+analyticsStatusItem('Last event: '+esc(last?(last.createdAt||'').slice(5,16).replace('T',' '):'none yet'))+analyticsStatusItem(pages.size+' active pages')+'</div></section>'}`;
    generated = generated.replace(/function analyticsLiveControl\(\)\{[\s\S]*?\}function analyticsPulseHeader\(events,pages\)\{[\s\S]*?\}function analyticsContent\(\)/, separatedPulseHeaderCode + "\nfunction analyticsContent()");

    const dedicatedMetricsCode = String.raw`function analyticsMetricRangeDefaults(){return {unique:'month',events:'month',pageViews:'month',forms:'month'}}
function analyticsMetricRange(key){S.analyticsMetricRanges=S.analyticsMetricRanges||analyticsMetricRangeDefaults();return S.analyticsMetricRanges[key]||analyticsMetricRangeDefaults()[key]||'month'}
function analyticsMetricRangeDays(range){return range==='day'?1:range==='week'?7:range==='quarter'?90:range==='all'?99999:30}
function analyticsMetricRangeLabel(range){return range==='day'?'Day':range==='week'?'Week':range==='quarter'?'3 months':range==='all'?'All time':'Month'}
function analyticsMetricEventsFor(key){const range=analyticsMetricRange(key);const days=analyticsMetricRangeDays(range);const rows=S.events||[];if(days>=99999)return rows;const cutoff=Date.now()-days*86400000;return rows.filter(function(e){return (Date.parse(e.createdAt||0)||0)>=cutoff})}
function analyticsSetMetricRange(key,value){S.analyticsMetricRanges=S.analyticsMetricRanges||analyticsMetricRangeDefaults();S.analyticsMetricRanges[key]=value;render()}
function analyticsRefreshMetric(key){S.analyticsMetricRefreshing=key;render();const done=function(){S.analyticsMetricRefreshing=null;if(typeof analyticsEnsureLive==='function')analyticsEnsureLive();render()};try{if(typeof load==='function'){Promise.resolve(load()).then(done).catch(done)}else{done()}}catch(error){done()}}
function analyticsMetricRangeSelect(key){const current=analyticsMetricRange(key);const opts=[['day','Day'],['week','Week'],['month','Month'],['quarter','3 months'],['all','All']];return '<select class="analyticsMetricSelect" onchange="analyticsSetMetricRange(&quot;'+key+'&quot;,this.value)">'+opts.map(function(o){return '<option value="'+o[0]+'" '+(current===o[0]?'selected':'')+'>'+o[1]+'</option>'}).join('')+'</select>'}
function analyticsMetricRefreshButton(key){return '<button class="analyticsMetricRefresh secondary" type="button" onclick="analyticsRefreshMetric(&quot;'+key+'&quot;)">'+(S.analyticsMetricRefreshing===key?'Updating':'Refresh')+'</button>'}
function analyticsMetricControls(key){return analyticsMetricRangeSelect(key)}
function analyticsMetricShell(key,title,value,note,controls){return '<section class="analyticsMetricCard"><div class="analyticsMetricCardTop"><p>'+esc(title)+'</p><div class="analyticsMetricControls">'+(controls||'')+analyticsMetricRefreshButton(key)+'</div></div><b>'+esc(value)+'</b><span>'+esc(note)+'</span></section>'}
function analyticsUniqueSessionsMetric(){const rows=analyticsMetricEventsFor('unique');const sessions=new Set(rows.map(function(e){return e.sessionId||''}).filter(Boolean));return analyticsMetricShell('unique','Unique sessions',sessions.size,analyticsMetricRangeLabel(analyticsMetricRange('unique')),analyticsMetricControls('unique'))}
function analyticsTotalEventsMetric(){const rows=analyticsMetricEventsFor('events');return analyticsMetricShell('events','Total events',rows.length,analyticsMetricRangeLabel(analyticsMetricRange('events')),analyticsMetricControls('events'))}
function analyticsPageViewsMetric(){const rows=analyticsMetricEventsFor('pageViews').filter(function(e){return e.type==='page_view'});return analyticsMetricShell('pageViews','Page views',rows.length,analyticsMetricRangeLabel(analyticsMetricRange('pageViews')),analyticsMetricControls('pageViews'))}
function analyticsFormSubmitsMetric(){const rows=analyticsMetricEventsFor('forms').filter(function(e){return e.type==='form_submission'});return analyticsMetricShell('forms','Form submits',rows.length,analyticsMetricRangeLabel(analyticsMetricRange('forms')),analyticsMetricControls('forms'))}
function analyticsConversionRateMetric(){const rows=analyticsFilteredEvents();const views=rows.filter(function(e){return e.type==='page_view'}).length;const forms=rows.filter(function(e){return e.type==='form_submission'}).length;const rate=views?Math.round(forms/views*100):0;return analyticsMetricShell('conversion','Conversion rate',rate+'%','Forms / views','')}
function analyticsActivePagesMetric(){const rows=analyticsFilteredEvents();const pages=new Set(rows.map(function(e){return analyticsPath(e.sourceUrl)}).filter(Boolean));return analyticsMetricShell('activePages','Active pages',pages.size,'Current view','')}
function analyticsDedicatedMetrics(){return '<section class="analyticsDedicatedMetrics">'+analyticsUniqueSessionsMetric()+analyticsTotalEventsMetric()+analyticsPageViewsMetric()+analyticsFormSubmitsMetric()+analyticsConversionRateMetric()+analyticsActivePagesMetric()+'</section>'}`;
    if (!generated.includes("function analyticsDedicatedMetrics()")) {
      generated = generated.replace("function analyticsContent(){", dedicatedMetricsCode + "\nfunction analyticsContent(){");
    }

    generated = generated.replace("+analyticsPulseHeader(events,pages)+analyticsModeTabs()+'<div class=\"analyticsToolPanel\">", "+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">");
    generated = generated.replace("+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">", "+analyticsPulseHeader(events,pages)+analyticsDedicatedMetrics()+'<div class=\"analyticsToolPanel\">");

    generated = generated.replace(/body='<section class="analyticsKpis">'\+analyticsKpi\('Unique sessions'[\s\S]*?\+'<\/section>'\+analyticsSection\('Overview'/, "body=analyticsSection('Overview'");
    generated = generated.replace(/'<section class="analyticsKpis">'\+analyticsKpi\('Unique sessions'[\s\S]*?\+'<\/section>'\+analyticsSection\('Overview'/, "analyticsSection('Overview'");

    const analyticsTextStyles = `
      /* analytics-horizontal-metrics-v1 */
      .analyticsStickyCommandCenter {
        width:calc(100% + 48px) !important;
        max-width:none !important;
        box-sizing:border-box !important;
        margin:calc(-1 * var(--analytics-command-pull, 0px)) -24px 0 -24px !important;
        border-radius:0 !important;
        overflow:visible !important;
        padding:18px 14px 20px !important;
        min-height:auto !important;
      }
      .analyticsStickyCommandCenter h2 {
        font-size:clamp(34px,3vw,48px) !important;
        line-height:1 !important;
        margin:8px 0 0 !important;
      }
      .analyticsStickyCommandCenter .analyticsTop {
        gap:16px !important;
        align-items:flex-start !important;
      }
      .analyticsStickyCommandCenter .analyticsLooseModeTabs,
      .analyticsStickyCommandCenter .analyticsStatusLine {
        margin-top:10px !important;
      }
      .analyticsShell,
      .analyticsShell * {
        opacity:1 !important;
        visibility:visible !important;
        color:#071629 !important;
        -webkit-text-fill-color:#071629 !important;
        background-image:none !important;
        -webkit-background-clip:border-box !important;
        background-clip:border-box !important;
        text-shadow:none !important;
      }
      .analyticsShell p,
      .analyticsShell small,
      .analyticsShell .muted,
      .analyticsShell [class*="muted"],
      .analyticsShell [class*="label"],
      .analyticsShell [class*="caption"],
      .analyticsShell [class*="sub"] {
        color:#607089 !important;
        -webkit-text-fill-color:#607089 !important;
      }
      .analyticsShell h1,
      .analyticsShell h2,
      .analyticsShell h3,
      .analyticsShell h4,
      .analyticsShell strong,
      .analyticsShell b,
      .analyticsShell .metricValue,
      .analyticsShell [class*="value"],
      .analyticsShell [class*="number"] {
        color:#061a33 !important;
        -webkit-text-fill-color:#061a33 !important;
      }
      .analyticsShell button.primary,
      .analyticsShell button.primary * {
        color:#fff !important;
        -webkit-text-fill-color:#fff !important;
        background-image:none !important;
      }
      .analyticsDedicatedMetrics {
        display:flex !important;
        flex-wrap:nowrap !important;
        align-items:stretch !important;
        gap:10px !important;
        width:100% !important;
        max-width:100% !important;
        box-sizing:border-box !important;
        margin:16px 0 0 !important;
        overflow-x:auto !important;
        overflow-y:hidden !important;
        padding-bottom:4px !important;
        scrollbar-width:thin !important;
      }
      .analyticsMetricCard {
        flex:1 1 0 !important;
        min-width:150px !important;
        background:#fff !important;
        border:1px solid #d9e3f2 !important;
        border-radius:8px !important;
        box-shadow:0 10px 28px rgba(6,26,51,.07) !important;
        padding:12px !important;
        box-sizing:border-box !important;
        display:flex !important;
        flex-direction:column !important;
        justify-content:space-between !important;
      }
      .analyticsMetricCardTop {
        display:grid !important;
        gap:8px !important;
        align-items:start !important;
      }
      .analyticsMetricCard p {
        margin:0 !important;
        color:#061a33 !important;
        -webkit-text-fill-color:#061a33 !important;
        font-size:11px !important;
        font-weight:950 !important;
        letter-spacing:.06em !important;
        line-height:1.15 !important;
        text-transform:uppercase !important;
      }
      .analyticsMetricCard b {
        display:block !important;
        color:#061a33 !important;
        -webkit-text-fill-color:#061a33 !important;
        font-size:30px !important;
        line-height:1 !important;
        margin:12px 0 6px !important;
        font-weight:950 !important;
      }
      .analyticsMetricCard span {
        color:#607089 !important;
        -webkit-text-fill-color:#607089 !important;
        font-size:12px !important;
        font-weight:850 !important;
      }
      .analyticsMetricControls {
        display:flex !important;
        gap:6px !important;
        flex-wrap:wrap !important;
      }
      .analyticsMetricSelect,
      .analyticsMetricRefresh {
        min-height:30px !important;
        border-radius:7px !important;
        border:1px solid #cbd8ea !important;
        background:#f8fbff !important;
        color:#061a33 !important;
        -webkit-text-fill-color:#061a33 !important;
        font-size:12px !important;
        font-weight:850 !important;
        padding:5px 8px !important;
        box-shadow:none !important;
        max-width:100% !important;
      }
      @media (max-width:900px) {
        .analyticsMetricCard { flex:0 0 170px !important; }
      }
      @media (max-width:760px) {
        .analyticsStickyCommandCenter {
          width:calc(100% + 32px) !important;
          margin:calc(-1 * var(--analytics-command-pull, 0px)) -16px 0 -16px !important;
          border-radius:0 !important;
          padding:16px 12px 18px !important;
        }
        .analyticsMetricCard { flex:0 0 210px !important; }
      }
    `;

    if (!generated.includes("analytics-horizontal-metrics-v1")) {
      generated = generated.replace("</style>", analyticsTextStyles + "</style>");
    }

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
