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
      await fs.writeFile(generatedPath, generated);
      patched = true;
    }
  }
} catch (error) {
  patched = false;
}

if (patched) {
  await import(`${pathToFileURL(generatedPath).href}?v=${Date.now()}`);
} else {
  await import("./server-crm-actions-scope.js");
}
