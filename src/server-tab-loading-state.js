import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const selectorPath = path.join(here, "server-analytics-selector-copies.js");
const generatedSelectorPath = path.join(here, ".server-analytics-selector-loading.js");
const marker = "tab-loading-state-v1";

const loadingClientCode = String.raw`function constravaTabLabel(name){return name==='crm'?'CRM':name==='resources'?'Connected Resources':name==='settings'?'Settings':name==='notifications'?'Notifications':'Analytics'}
function constravaTabLoadingMarkup(name){const label=constravaTabLabel(name);return '<style>@keyframes constravaTabSpin{to{transform:rotate(360deg)}}</style><section class="card tabLoadingState" style="min-height:260px;display:grid;place-items:center;text-align:center;border-radius:14px"><div><span aria-hidden="true" style="display:inline-block;width:34px;height:34px;border:3px solid #d9e3f2;border-top-color:#061a33;border-radius:999px;animation:constravaTabSpin .8s linear infinite;margin-bottom:12px"></span><h2 style="margin:0;color:#061a33">Loading '+esc(label)+'</h2><p class="muted" style="margin:6px 0 0">Refreshing the latest page data.</p></div></section>'}
function constravaShowTabLoading(name){const target=document.getElementById('app');if(target)target.innerHTML=constravaTabLoadingMarkup(name)}`;

const loadingTabFunction = String.raw`function tab(name){S.tab=name;document.querySelectorAll('.tab').forEach(function(b){b.classList.toggle('active',b.dataset.tab===name)});document.getElementById('settingsButton').classList.toggle('active',name==='settings');const dd=document.getElementById('notificationDropdown');if(dd)dd.classList.remove('open');const nb=document.getElementById('notificationButton');if(nb)nb.setAttribute('aria-expanded','false');pageTitle.textContent=constravaTabLabel(name);constravaShowTabLoading(name);const token=(S.tabLoadingToken||0)+1;S.tabLoadingToken=token;if(S.tabLoadingTimer)clearTimeout(S.tabLoadingTimer);S.tabLoadingTimer=setTimeout(async function(){try{await load();if(S.tabLoadingToken===token)render()}catch(error){if(S.tabLoadingToken===token){const target=document.getElementById('app');if(target)target.innerHTML='<section class="card"><div class="in"><h2>Could not refresh this page</h2><p class="muted">Please try the tab again.</p></div></section>'}}},120)}`;

const runtimePatch = `// ${marker}\nconst constravaTabLoadingClientCode = ${JSON.stringify(loadingClientCode)};\nconst constravaTabLoadingTabFunction = ${JSON.stringify(loadingTabFunction)};\nsource = source.replace(/function tab\\(name\\)\\{S\\.tab=name;document\\.querySelectorAll\\('\\.tab'\\)[\\s\\S]*?;render\\(\\)\\}/, constravaTabLoadingClientCode + "\\n" + constravaTabLoadingTabFunction);\nif (!source.includes("function constravaTabLoadingMarkup")) throw new Error("Could not install tab loading state.");\n`;

const selectorInjection = `
    const tabLoadingRuntimePatch = ${JSON.stringify(runtimePatch)};
    const tabLoadingNeedle = "const patch = String.raw` + "`" + `\\n// live-analytics-display-v2";
    const tabLoadingReplacement = "const patch = String.raw` + "`" + `\\n" + tabLoadingRuntimePatch + "\\n// live-analytics-display-v2";
    if (!generated.includes(tabLoadingNeedle)) throw new Error("Could not find analytics selector patch marker for tab loading.");
    generated = generated.replace(tabLoadingNeedle, tabLoadingReplacement);
`;

let selectorSource = await fs.readFile(selectorPath, "utf8");
if (!selectorSource.includes(marker)) {
  const writeNeedle = "    await fs.writeFile(generatedPath, generated);";
  if (!selectorSource.includes(writeNeedle)) {
    throw new Error("Could not find analytics selector generated write target.");
  }
  selectorSource = selectorSource.replace(writeNeedle, `${selectorInjection}\n${writeNeedle}`);
}

await fs.writeFile(generatedSelectorPath, selectorSource);
await import(`${pathToFileURL(generatedSelectorPath).href}?v=${Date.now()}`);
