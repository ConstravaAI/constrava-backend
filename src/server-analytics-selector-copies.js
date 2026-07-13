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

    const analyticsTextStyles = `
      /* analytics-overview-visible-text-v2 */
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
