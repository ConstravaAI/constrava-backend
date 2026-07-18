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
    const needle = "+'</div><div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-top:12px\">'+analyticsLiveControl()";
    const replacement = "+'</div>'+analyticsModeTabs()+'<div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-top:12px\">'+analyticsLiveControl()";
    if (generated.includes(needle)) {
      generated = generated.replace(needle, replacement);
    }

    const separatedModeTabsCode = String.raw`function analyticsModeTab(key,label){const active=S.analyticsView===key;return '<button onclick="S.analyticsView=&quot;'+key+'&quot;;render()" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:9px 13px;font-weight:950">'+label+'</button>'}
function analyticsOverviewTab(){return analyticsModeTab('overview','Overview')}
function analyticsTrafficTab(){return analyticsModeTab('traffic','Traffic')}
function analyticsSourcesTab(){return analyticsModeTab('sources','Sources')}
function analyticsPagesTab(){return analyticsModeTab('pages','Pages')}
function analyticsEventsTab(){return analyticsModeTab('events','Events')}
function analyticsAudienceTab(){return analyticsModeTab('audience','Audience')}
function analyticsModeTabs(){return '<div class="analyticsLooseModeTabs" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px">'+analyticsOverviewTab()+analyticsTrafficTab()+analyticsSourcesTab()+analyticsPagesTab()+analyticsEventsTab()+analyticsAudienceTab()+'</div>'}`;
    const modeTabsPattern = /function analyticsModeTabs\(\)\{[\s\S]*?\}function analyticsLiveControl\(\)/;
    if (modeTabsPattern.test(generated)) {
      generated = generated.replace(modeTabsPattern, separatedModeTabsCode + "\nfunction analyticsLiveControl()");
    }

    const separatedPulseHeaderCode = String.raw`function analyticsTopBarBottom(){try{const labels=['Analytics','CRM','Connected Resources'];const nodes=[...document.querySelectorAll('header,nav,[role="navigation"],body>div,body>section,body>main,div')];let best=null;nodes.forEach(function(el){const text=(el.innerText||'').replace(/\s+/g,' ');if(!labels.every(function(label){return text.includes(label)}))return;const r=el.getBoundingClientRect();if(r.width<window.innerWidth*.5||r.height<32||r.height>120||r.top>4)return;if(!best||r.height<best.height)best={bottom:Math.round(r.bottom),height:r.height}});return best?best.bottom:69}catch(error){return 69}}
function analyticsSyncStickyCommandCenter(){requestAnimationFrame(function(){try{const banner=document.querySelector('.analyticsStickyCommandCenter');if(!banner)return;const top=analyticsTopBarBottom();document.documentElement.style.setProperty('--analytics-sticky-top',top+'px');document.documentElement.style.setProperty('--analytics-command-pull','0px');requestAnimationFrame(function(){try{const currentTop=Math.round(banner.getBoundingClientRect().top);const pull=Math.max(0,currentTop-top);document.documentElement.style.setProperty('--analytics-command-pull',pull+'px')}catch(error){}})}catch(error){}});return ''}
function analyticsLiveControl(){return '<button class="'+(S.analyticsLive?'primary':'secondary')+'" type="button" onclick="analyticsToggleLive()" style="border-radius:8px;padding:7px 10px;font-weight:900;box-shadow:none">'+(S.analyticsLive?'Live updating':'Live paused')+'</button>'}
function analyticsStatusItem(text){return '<span class="analyticsStatusItem" style="color:#607089;font-size:13px;font-weight:850;line-height:1.4">'+text+'</span>'}
function analyticsPulseHeader(events,pages){analyticsSyncStickyCommandCenter();const last=events.length?[...events].sort(function(a,b){return analyticsTime(b)-analyticsTime(a)})[0]:null;return '<section class="analyticsHero analyticsStickyCommandCenter" style="position:sticky;top:var(--analytics-sticky-top,69px);z-index:20;width:calc(100% + 48px);max-width:none;box-sizing:border-box;margin:calc(-1 * var(--analytics-command-pull, 0px)) -24px 0 -24px;border-radius:0"><div class="analyticsTop"><div><div class="analyticsEyebrow">'+(S.analyticsLive?'Live analytics':'Manual refresh')+'</div><h2>Analytics command center</h2>'+analyticsModeTabs()+'</div>'+analyticsControls()+'</div><div class="analyticsStatusLine" style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-top:10px">'+analyticsLiveControl()+analyticsStatusItem('Last event: '+esc(last?(last.createdAt||'').slice(5,16).replace('T',' '):'none yet'))+analyticsStatusItem(pages.size+' active pages')+'</div></section>'}`;
    const pulseHeaderPattern = /function analyticsLiveControl\(\)\{[\s\S]*?\}function analyticsPulseHeader\(events,pages\)\{[\s\S]*?\}function analyticsContent\(\)/;
    if (pulseHeaderPattern.test(generated)) {
      generated = generated.replace(pulseHeaderPattern, separatedPulseHeaderCode + "\nfunction analyticsContent()");
    }

    const tabsAfterHeaderNeedle = "+analyticsPulseHeader(events,pages)+analyticsModeTabs()+'<div class=\"analyticsToolPanel\">";
    const tabsInsideHeaderReplacement = "+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">";
    if (generated.includes(tabsAfterHeaderNeedle)) {
      generated = generated.replace(tabsAfterHeaderNeedle, tabsInsideHeaderReplacement);
    }

    const dedicatedKpiLabelCode = String.raw`function analyticsKpiTextColor(){return '#061a33'}
function analyticsKpiCard(content){return '<div class="analyticsKpi" style="background:#fff;border:1px solid #d9e3f2;border-radius:16px;padding:14px">'+content+'</div>'}
function analyticsKpiLabel(label){const color=analyticsKpiTextColor();return '<p style="margin:0;color:'+color+';-webkit-text-fill-color:'+color+';font-size:12px;font-weight:950;text-transform:uppercase;letter-spacing:.07em">'+esc(label)+'</p>'}
function analyticsKpiValue(value){const color=analyticsKpiTextColor();return '<b style="display:block;color:'+color+';-webkit-text-fill-color:'+color+';font-size:30px;margin:5px 0;font-weight:950">'+esc(value)+'</b>'}
function analyticsKpiDelta(now,prev){const color=analyticsKpiTextColor();return '<span class="analyticsDelta '+(now>=prev?'up':'down')+'" style="display:inline-flex;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:950;color:'+color+';-webkit-text-fill-color:'+color+';background:#d9f8e8">'+analyticsPct(now,prev)+'</span>'}
function analyticsKpiNote(note){const color=analyticsKpiTextColor();return '<p style="margin:6px 0 0;color:'+color+';-webkit-text-fill-color:'+color+';font-size:12px;font-weight:850;text-transform:uppercase;letter-spacing:.07em">'+esc(note)+'</p>'}
function analyticsKpi(label,value,now,prev,note){return analyticsKpiCard(analyticsKpiLabel(label)+analyticsKpiValue(value)+analyticsKpiDelta(now,prev)+analyticsKpiNote(note||analyticsRangeLabel()))}`;
    const dedicatedKpiNameCode = String.raw`function analyticsKpiTextColor(){return '#061a33'}
function analyticsKpiCard(content){return '<div class="analyticsKpi" style="background:#fff;border:1px solid #d9e3f2;border-radius:16px;padding:14px">'+content+'</div>'}
function analyticsKpiLabel(name){const color=analyticsKpiTextColor();return '<p style="margin:0;color:'+color+';-webkit-text-fill-color:'+color+';font-size:12px;font-weight:950;text-transform:uppercase;letter-spacing:.07em">'+esc(name)+'</p>'}
function analyticsKpiValue(value){const color=analyticsKpiTextColor();return '<b style="display:block;color:'+color+';-webkit-text-fill-color:'+color+';font-size:30px;margin:5px 0;font-weight:950">'+esc(value)+'</b>'}
function analyticsKpiDelta(current,previous){const color=analyticsKpiTextColor();return '<span class="analyticsDelta '+analyticsDeltaClass(current,previous)+'" style="display:inline-flex;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:950;color:'+color+';-webkit-text-fill-color:'+color+';background:#d9f8e8">'+analyticsPct(current,previous)+'</span>'}
function analyticsKpiNote(note){const color=analyticsKpiTextColor();return '<p style="margin:6px 0 0;color:'+color+';-webkit-text-fill-color:'+color+';font-size:12px;font-weight:850;text-transform:uppercase;letter-spacing:.07em">'+esc(note)+'</p>'}
function analyticsKpi(name,value,current,previous,note){return analyticsKpiCard(analyticsKpiLabel(name)+analyticsKpiValue(value)+analyticsKpiDelta(current,previous)+analyticsKpiNote(note||analyticsRangeLabel()))}`;
    const kpiLabelNextFunctions = ["analyticsSection", "analyticsRows", "analyticsOptions", "analyticsSourceOptions"];
    for (const nextName of kpiLabelNextFunctions) {
      const originalLabelPattern = new RegExp("function analyticsKpi\\(label,value,now,prev,note\\)\\{[\\s\\S]*?\\}function " + nextName + "\\(");
      const splitLabelPattern = new RegExp("function analyticsKpiTextColor\\(\\)\\{[\\s\\S]*?function analyticsKpi\\(label,value,now,prev,note\\)\\{[\\s\\S]*?\\}function " + nextName + "\\(");
      const labelPattern = splitLabelPattern.test(generated) ? splitLabelPattern : originalLabelPattern;
      if (labelPattern.test(generated)) {
        generated = generated.replace(labelPattern, dedicatedKpiLabelCode + "\nfunction " + nextName + "(");
        break;
      }
    }
    const kpiNameNextFunctions = ["analyticsSourceOptions", "analyticsControls", "analyticsRows", "analyticsSection"];
    for (const nextName of kpiNameNextFunctions) {
      const originalNamePattern = new RegExp("function analyticsKpi\\(name,value,current,previous,note\\)\\{[\\s\\S]*?\\}function " + nextName + "\\(");
      const splitNamePattern = new RegExp("function analyticsKpiTextColor\\(\\)\\{[\\s\\S]*?function analyticsKpi\\(name,value,current,previous,note\\)\\{[\\s\\S]*?\\}function " + nextName + "\\(");
      const namePattern = splitNamePattern.test(generated) ? splitNamePattern : originalNamePattern;
      if (namePattern.test(generated)) {
        generated = generated.replace(namePattern, dedicatedKpiNameCode + "\nfunction " + nextName + "(");
        break;
      }
    }

    const analyticsTextStyles = `
      /* analytics-kpi-readable-text-v3 */
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
      .analyticsStickyCommandCenter .analyticsLooseModeTabs {
        margin-top:10px !important;
      }
      .analyticsStickyCommandCenter .analyticsStatusLine {
        margin-top:10px !important;
      }
      @media (max-width:760px) {
        .analyticsStickyCommandCenter {
          width:calc(100% + 32px) !important;
          margin:calc(-1 * var(--analytics-command-pull, 0px)) -16px 0 -16px !important;
          border-radius:0 !important;
          padding:16px 12px 18px !important;
        }
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
      .analyticsShell [class*="positive"],
      .analyticsShell [class*="success"],
      .analyticsShell [class*="trend"] {
        color:#168a52 !important;
        -webkit-text-fill-color:#168a52 !important;
      }
      .analyticsShell section.analyticsKpis,
      .analyticsShell section.analyticsKpis *,
      .analyticsShell .analyticsKpis,
      .analyticsShell .analyticsKpis *,
      .analyticsShell [class*="analyticsKpi"],
      .analyticsShell [class*="analyticsKpi"] *,
      .analyticsShell [class*="Kpi"],
      .analyticsShell [class*="Kpi"] * {
        color:#061a33 !important;
        -webkit-text-fill-color:#061a33 !important;
        opacity:1 !important;
        visibility:visible !important;
        text-shadow:none !important;
        background-image:none !important;
        -webkit-background-clip:border-box !important;
        background-clip:border-box !important;
      }
    `;

    if (!generated.includes("analytics-kpi-readable-text-v3")) {
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