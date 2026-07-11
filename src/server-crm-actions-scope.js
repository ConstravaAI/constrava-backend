import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const fontWrapperPath = path.join(here, "server-fonts.js");
const marker = "empty-analytics-tab-panels-v1";

const analyticsCommandCenterCode = String.raw`
function analyticsEnsureLive(){if(S.analyticsLive&&!S.analyticsTimer){S.analyticsTimer=setInterval(async function(){try{await load();if(S.tab==='analytics')render()}catch(err){}},12000)}if(!S.analyticsLive&&S.analyticsTimer){clearInterval(S.analyticsTimer);S.analyticsTimer=null}}
function analyticsToggleLive(){S.analyticsLive=!S.analyticsLive;analyticsEnsureLive();render()}
function analyticsModeTabs(){const items=[['overview','Overview'],['traffic','Traffic'],['sources','Sources'],['pages','Pages'],['events','Events'],['audience','Audience']];return '<div class="analyticsModeTabs" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:white;border:1px solid var(--line);border-radius:18px;padding:8px;box-shadow:0 12px 32px rgba(6,26,51,.07)">'+items.map(function(item){const active=S.analyticsView===item[0];return '<button onclick="S.analyticsView=\''+item[0]+'\';render()" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:10px 14px;font-weight:950">'+item[1]+'</button>'}).join('')+'</div>'}
function analyticsLiveControl(){return '<button class="'+(S.analyticsLive?'primary':'secondary')+'" type="button" onclick="analyticsToggleLive()" style="border-radius:999px;padding:10px 14px;font-weight:950">'+(S.analyticsLive?'Live updating':'Live paused')+'</button>'}
function analyticsPulseHeader(events,pages){const last=events.length?[...events].sort(function(a,b){return analyticsTime(b)-analyticsTime(a)})[0]:null;return '<section class="analyticsHero"><div class="analyticsTop"><div><div class="analyticsEyebrow">'+(S.analyticsLive?'Live analytics':'Manual refresh')+'</div><h2>Analytics command center</h2><p>Website tracker activity organized into traffic, sources, pages, events, and audience context.</p></div>'+analyticsControls()+'</div><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">'+analyticsLiveControl()+'<span class="pill">Last event: '+esc(last?(last.createdAt||'').slice(5,16).replace('T',' '):'none yet')+'</span><span class="pill">'+pages.size+' active pages</span></div></section>'}
function analyticsContent(){S.analyticsRange=S.analyticsRange||'30';S.analyticsSource=S.analyticsSource||'all';S.analyticsView=S.analyticsView||'overview';S.analyticsLive=S.analyticsLive!==false;analyticsEnsureLive();const events=analyticsFilteredEvents();const pages=new Set(events.map(function(e){return analyticsPath(e.sourceUrl)}));return '<div class="analyticsShell analyticsCommandCenter">'+analyticsPulseHeader(events,pages)+analyticsModeTabs()+'<div class="analyticsToolPanel"></div></div>'}
`;

let fontSource = await fs.readFile(fontWrapperPath, "utf8");
if (!fontSource.includes(marker)) {
  fontSource = fontSource.replace(
    "const fontLinks =",
    `const analyticsCommandCenterOverride = ${JSON.stringify(analyticsCommandCenterCode)};\n\nconst fontLinks =`
  );
  fontSource = fontSource.replace(
    "String.raw\\`${modernAnalyticsClientCode}\\`",
    "String.raw\\`${modernAnalyticsClientCode}${analyticsCommandCenterOverride}\\`"
  );
  if (!fontSource.includes("analyticsCommandCenterOverride")) {
    throw new Error("Could not patch analytics generator override.");
  }
  await fs.writeFile(fontWrapperPath, `${fontSource}\n// ${marker}\n`);
}

let source = await fs.readFile(runtimeWrapperPath, "utf8");
if (!source.includes(marker)) {
  const writeNeedle = "await fs.writeFile(runtimePath, source);";
  const patch = String.raw`
// empty-analytics-tab-panels-v1
source = source.replace(${JSON.stringify('<p class="muted">${esc(workspaceLabel)}</p><h1 id="pageTitle">')}, ${JSON.stringify('<h1 id="pageTitle">')});

const crmActionVisibilityCode = "function syncCrmActionButtons(){var show=S.tab==='crm';['priorityCheck','aiAdd'].forEach(function(id){var el=document.getElementById(id);if(el)el.style.display=show?'':'none'})}";
if (!source.includes("function syncCrmActionButtons()")) {
  source = source.replace("function render(){", crmActionVisibilityCode + "\nfunction render(){");
  source = source.replace("app.innerHTML=h;bind();syncNotifications()", "app.innerHTML=h;bind();syncNotifications();syncCrmActionButtons()");
  source = source.replace("document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};", "document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};syncCrmActionButtons();");
}
`;

  if (!source.includes(writeNeedle)) throw new Error("Could not find runtime write target in src/server-runtime.js");
  source = source.replace(writeNeedle, `${patch}\n${writeNeedle}`);
  await fs.writeFile(runtimeWrapperPath, `${source}\n// ${marker}\n`);
}

await import("./server-account-persistence.js");
