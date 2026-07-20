import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "connect-resources-direct-blank-v1";

const oldTab = '<button class="tab" data-tab="resources">Connected Resources</button>';
const newTab = '<button class="tab" data-tab="resources">Connect Resources</button>';

const renderReset = "function render(){document.body.style.background='';const workspace=document.querySelector('.workspace');if(workspace)workspace.style.display='';";
const resourcesBranch = "if(S.tab==='resources'){h='';document.body.style.background='#fff';const workspace=document.querySelector('.workspace');if(workspace)workspace.style.display='none'}if(S.tab==='settings')";

const runtimeInjection = [
  `// ${marker}`,
  `source = source.replace(${JSON.stringify(oldTab)}, ${JSON.stringify(newTab)});`,
  `source = source.replace(${JSON.stringify("name==='resources'?'Connected Resources'")}, ${JSON.stringify("name==='resources'?'Connect Resources'")});`,
  `source = source.replace(${JSON.stringify("function render(){")}, ${JSON.stringify(renderReset)});`,
  `source = source.replace(/if\(S\.tab==='resources'\)\{h=[\s\S]*?\}if\(S\.tab==='settings'\)/, ${JSON.stringify(resourcesBranch)});`,
  `if (!source.includes(${JSON.stringify(newTab)})) throw new Error("Connect Resources tab button was not installed.");`,
  `if (source.includes("Outside resources") || source.includes("Website tracker") || source.includes("Recent plans")) throw new Error("Hidden Connect Resources content was not removed.");`
].join("\n");

let wrapperSource = await fs.readFile(runtimeWrapperPath, "utf8");
if (!wrapperSource.includes(marker)) {
  const target = "await fs.writeFile(runtimePath, source);";
  if (!wrapperSource.includes(target)) throw new Error("Runtime wrapper write target was not found.");
  wrapperSource = wrapperSource.replace(target, `${runtimeInjection}\n${target}`);
  await fs.writeFile(runtimeWrapperPath, wrapperSource);
}

await import("./server-fonts.js");
