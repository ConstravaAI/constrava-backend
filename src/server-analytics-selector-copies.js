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

    const separatedModeTabsCode = String.raw`function analyticsModeTab(key,label){const active=S.analyticsView===key;return '<button onclick="S.analyticsView=&quot;'+key+'&quot;;render()" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:10px 14px;font-weight:950">'+label+'</button>'}
function analyticsOverviewTab(){return analyticsModeTab('overview','Overview')}
function analyticsTrafficTab(){return analyticsModeTab('traffic','Traffic')}
function analyticsSourcesTab(){return analyticsModeTab('sources','Sources')}
function analyticsPagesTab(){return analyticsModeTab('pages','Pages')}
function analyticsEventsTab(){return analyticsModeTab('events','Events')}
function analyticsAudienceTab(){return analyticsModeTab('audience','Audience')}
function analyticsModeTabs(){return '<div class="analyticsLooseModeTabs" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px">'+analyticsOverviewTab()+analyticsTrafficTab()+analyticsSourcesTab()+analyticsPagesTab()+analyticsEventsTab()+analyticsAudienceTab()+'</div>'}`;
    const modeTabsPattern = /function analyticsModeTabs\(\)\{[\s\S]*?\}function analyticsLiveControl\(\)/;
    if (modeTabsPattern.test(generated)) {
      generated = generated.replace(modeTabsPattern, separatedModeTabsCode + "\nfunction analyticsLiveControl()");
    }

    const separatedPulseHeaderCode = String.raw`function analyticsLiveControl(){return '<button class="'+(S.analyticsLive?'primary':'secondary')+'" type="button" onclick="analyticsToggleLive()" style="border-radius:8px;padding:8px 10px;font-weight:900;box-shadow:none">'+(S.analyticsLive?'Live updating':'Live paused')+'</button>'}
function analyticsStatusItem(text){return '<span class="analyticsStatusItem" style="color:#607089;font-size:13px;font-weight:850;line-height:1.4">'+text+'</span>'}
function analyticsPulseHeader(events,pages){const last=events.length?[...events].sort(function(a,b){return analyticsTime(b)-analyticsTime(a)})[0]:null;return '<section class="analyticsHero analyticsStickyCommandCenter" style="position:sticky;top:84px;z-index:20;width:calc(100% + 48px);max-width:none;box-sizing:border-box;margin:-1px -24px 0 -24px;border-radius:0"><div class="analyticsTop"><div><div class="analyticsEyebrow">'+(S.analyticsLive?'Live analytics':'Manual refresh')+'</div><h2>Analytics command center</h2><p>Website tracker activity organized into traffic, sources, pages, events, and audience context.</p>'+analyticsModeTabs()+'</div>'+analyticsControls()+'</div><div class="analyticsStatusLine" style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-top:12px">'+analyticsLiveControl()+analyticsStatusItem('Last event: '+esc(last?(last.createdAt||'').slice(5,16).replace('T',' '):'none yet'))+analyticsStatusItem(pages.size+' active pages')+'</div></section>'}`;
    const pulseHeaderPattern = /function analyticsLiveControl\(\)\{[\s\S]*?\}function analyticsPulseHeader\(events,pages\)\{[\s\S]*?\}function analyticsContent\(\)/;
    if (pulseHeaderPattern.test(generated)) {
      generated = generated.replace(pulseHeaderPattern, separatedPulseHeaderCode + "\nfunction analyticsContent()");
    }

    const tabsAfterHeaderNeedle = "+analyticsPulseHeader(events,pages)+analyticsModeTabs()+'<div class=\"analyticsToolPanel\">";
    const tabsInsideHeaderReplacement = "+analyticsPulseHeader(events,pages)+'<div class=\"analyticsToolPanel\">";
    if (generated.includes(tabsAfterHeaderNeedle)) {
      generated = generated.replace(tabsAfterHeaderNeedle, tabsInsideHeaderReplacement);
    }

    const analyticsTextStyles = `
      /* analytics-overview-visible-text-v2 */
      .analyticsStickyCommandCenter {
        width:calc(100% + 48px) !important;
        max-width:none !important;
        box-sizing:border-box !important;
        margin:-1px -24px 0 -24px !important;
        border-radius:0 !important;
        overflow:visible !important;
      }
      @media (max-width:760px) {
        .analyticsStickyCommandCenter {
          width:calc(100% + 32px) !important;
          margin:-1px -16px 0 -16px !important;
          border-radius:0 !important;
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
    `;

    if (!generated.includes("analytics-overview-visible-text-v2")) {
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