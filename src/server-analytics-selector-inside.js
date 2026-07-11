import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const scopeWrapperPath = path.join(here, "server-crm-actions-scope.js");
const generatedPath = path.join(here, ".server-crm-actions-scope.generated.js");

const wrapper = await fs.readFile(scopeWrapperPath, "utf8");
const encoded = wrapper.match(/const encoded = "([\s\S]*?)";/)?.[1];
if (!encoded) throw new Error("Could not find encoded dashboard wrapper.");

let generated = Buffer.from(encoded, "base64").toString("utf8");

const integratedAnalyticsTabs = `function analyticsModeTabs(){const items=[['overview','Overview'],['traffic','Traffic'],['sources','Sources'],['pages','Pages'],['events','Events'],['audience','Audience']];return items.map(function(item){const active=S.analyticsView===item[0];return '<button onclick="S.analyticsView=\\''+item[0]+'\\';render()" class="'+(active?'primary':'secondary')+'" style="border-radius:999px;padding:10px 14px;font-weight:950">'+item[1]+'</button>'}).join('')}function analyticsLiveControl`;

generated = generated.replace(/function analyticsModeTabs\(\)\{[\s\S]*?\}function analyticsLiveControl/, integratedAnalyticsTabs);

generated = generated.replace(
  "+'</div><div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-top:12px\">'+analyticsLiveControl()",
  "+'</div><div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-top:12px\">'+analyticsLiveControl()+analyticsModeTabs()"
);

generated = generated
  .replaceAll("analyticsPulseHeader(events,pages)+analyticsModeTabs()+body", "analyticsPulseHeader(events,pages)+body")
  .replaceAll("analyticsPulseHeader(events,pages)+analyticsModeTabs()+", "analyticsPulseHeader(events,pages)+");

await fs.writeFile(generatedPath, generated);
await import(`${pathToFileURL(generatedPath).href}?v=${Date.now()}`);
