import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const visualSourcePath = path.join(here, "server-analytics-selector-copies.js");
const marker = "colorful-workspaces-runtime-v1";

const visualSource = await fs.readFile(visualSourcePath, "utf8");
const colorfulStyles = visualSource.match(
  /const colorfulWorkspaceStyles = `([\s\S]*?)`;\r?\n    generated = generated\.replace/
)?.[1];

if (!colorfulStyles?.includes("colorful-workspaces-v1")) {
  throw new Error("Could not load the colorful CRM and resources visual system.");
}

const runtimeInjection = [
  `// ${marker}`,
  `const constravaColorfulWorkspaceStyles = ${JSON.stringify(colorfulStyles)};`,
  'const constravaDashboardTitleIndex = source.indexOf("<title>Constrava Dashboard</title>");',
  'const constravaDashboardStyleEndIndex = source.indexOf("</style>", constravaDashboardTitleIndex);',
  'if (constravaDashboardTitleIndex < 0 || constravaDashboardStyleEndIndex < 0) throw new Error("Could not find the dashboard stylesheet.");',
  'source = source.slice(0, constravaDashboardStyleEndIndex) + constravaColorfulWorkspaceStyles + source.slice(constravaDashboardStyleEndIndex);',
  'if (!source.slice(constravaDashboardTitleIndex).includes("colorful-workspaces-v1")) throw new Error("Could not install the colorful workspace styles.");'
].join("\n");

let wrapperSource = await fs.readFile(runtimeWrapperPath, "utf8");
const target = "await fs.writeFile(runtimePath, source);";
const targetIndex = wrapperSource.indexOf(target);
const markerIndex = wrapperSource.indexOf(`// ${marker}`);

if (targetIndex < 0) throw new Error("Runtime wrapper write target was not found.");
if (markerIndex >= 0 && markerIndex < targetIndex) {
  wrapperSource = `${wrapperSource.slice(0, markerIndex)}${runtimeInjection}\n${wrapperSource.slice(targetIndex)}`;
} else {
  wrapperSource = wrapperSource.replace(target, `${runtimeInjection}\n${target}`);
}

await fs.writeFile(runtimeWrapperPath, wrapperSource);
await import("./server-fonts.js");
