import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "connected-resources-removed-v1";

const resourcesClientCode = String.raw`function syncConnectedResourcesBlank(){const workspace=document.querySelector('.workspace');if(workspace)workspace.style.display=S.tab==='resources'?'none':''}function resourcesContent(){syncConnectedResourcesBlank();setTimeout(syncConnectedResourcesBlank,0);return ''}`;

const runtimeInjection = [
  `// ${marker}`,
  `const connectedResourcesClientCode = ${JSON.stringify(resourcesClientCode)};`,
  `source = source.replace(${JSON.stringify("<button class=\"tab\" data-tab=\"resources\">Connected Resources</button>")}, "");`,
  `source = source.replace(${JSON.stringify("function render(){")}, connectedResourcesClientCode + ${JSON.stringify("\nfunction render(){syncConnectedResourcesBlank();")});`,
  `source = source.replace(/if\(S\.tab==='resources'\)\{h=[\s\S]*?\}if\(S\.tab==='settings'\)/, ${JSON.stringify("if(S.tab==='resources')h=resourcesContent();if(S.tab==='settings')")});`,
  `if (source.includes(${JSON.stringify("Connected Resources</button>")})) throw new Error("Connected resources tab button was not removed.");`
].join("\n");

let wrapperSource = await fs.readFile(runtimeWrapperPath, "utf8");
if (!wrapperSource.includes(marker)) {
  const target = "await fs.writeFile(runtimePath, source);";
  if (!wrapperSource.includes(target)) throw new Error("Runtime wrapper write target was not found.");
  wrapperSource = wrapperSource.replace(target, `${runtimeInjection}\n${target}`);
  await fs.writeFile(runtimeWrapperPath, wrapperSource);
}

await import("./server-fonts.js");
