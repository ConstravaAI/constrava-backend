import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "connect-resources-white-v2";

const resourcesClientCode = String.raw`function syncConnectedResourcesBlank(){const isResources=S.tab==='resources';const workspace=document.querySelector('.workspace');if(workspace)workspace.style.display=isResources?'none':'';if(isResources){const app=document.getElementById('app');if(app)app.innerHTML=''}}function resourcesContent(){setTimeout(syncConnectedResourcesBlank,0);return ''}`;

const oldTab = '<button class="tab" data-tab="resources">Connected Resources</button>';
const newTab = '<button class="tab" data-tab="resources">Connect Resources</button>';

const runtimeInjection = [
  `// ${marker}`,
  `const connectedResourcesClientCode = ${JSON.stringify(resourcesClientCode)};`,
  `source = source.replace(${JSON.stringify(oldTab)}, ${JSON.stringify(newTab)});`,
  `source = source.replace(${JSON.stringify("function render(){")}, connectedResourcesClientCode + ${JSON.stringify("\nfunction render(){")});`,
  `source = source.replace(/if\(S\.tab==='resources'\)\{h=[\s\S]*?\}if\(S\.tab==='settings'\)/, ${JSON.stringify("if(S.tab==='resources')h=resourcesContent();if(S.tab==='settings')")});`,
  `source = source.replace(${JSON.stringify("app.innerHTML=h;bind();syncNotifications()")}, ${JSON.stringify("app.innerHTML=h;bind();syncNotifications();syncConnectedResourcesBlank()")});`,
  `if (!source.includes(${JSON.stringify(newTab)})) throw new Error("Connect Resources tab button was not installed.");`,
  `if (!source.includes(${JSON.stringify("syncNotifications();syncConnectedResourcesBlank()")})) throw new Error("Connect Resources blank render hook was not installed.");`
].join("\n");

let wrapperSource = await fs.readFile(runtimeWrapperPath, "utf8");
if (!wrapperSource.includes(marker)) {
  const target = "await fs.writeFile(runtimePath, source);";
  if (!wrapperSource.includes(target)) throw new Error("Runtime wrapper write target was not found.");
  wrapperSource = wrapperSource.replace(target, `${runtimeInjection}\n${target}`);
  await fs.writeFile(runtimeWrapperPath, wrapperSource);
}

await import("./server-fonts.js");
