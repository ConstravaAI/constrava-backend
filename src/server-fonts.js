import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const analyticsSourcePath = path.join(here, "server-analytics.js");
const fontRuntimePath = path.join(here, ".server-analytics-fonts.js");

const fontCss = String.raw`
/* Constrava premium typography layer */
:root{
  --font-sans:"Manrope","Inter","Aptos","Segoe UI",system-ui,-apple-system,BlinkMacSystemFont,sans-serif;
  --font-display:"Playfair Display",Georgia,"Times New Roman",serif;
}
body,input,select,textarea,button{
  font-family:var(--font-sans)!important;
  letter-spacing:-0.01em;
}
h1,h2,.workspace h1,.analyticsTop h2,.hero h1,.bannerTitle{
  font-family:var(--font-display)!important;
  letter-spacing:-0.035em!important;
  font-weight:800!important;
}
.brand,.metricValue,.analyticsKpi b,.funnelStep b{
  font-family:var(--font-sans)!important;
  letter-spacing:-0.045em!important;
}
h3,h4,.card h3,.analyticsCard h3,.crmListHead h2,.modalHead h2{
  font-family:var(--font-sans)!important;
  letter-spacing:-0.025em!important;
  font-weight:900!important;
}
.tab,.btn,.primary,.secondary,.pill,.crmTab,label,.role,.small,.muted{
  font-family:var(--font-sans)!important;
}
`;

const fontLinks = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800;900&family=Playfair+Display:wght@700;800;900&display=swap" rel="stylesheet">';

const generatedFontHeadPatch = `sourcePatches.push(
  ['<title>Constrava Dashboard</title>\\n<style>', '<title>Constrava Dashboard</title>\\n${fontLinks}\\n<style>'],
  ['<title>Constrava</title><style>', '<title>Constrava</title>${fontLinks}<style>'],
  ['<title>Sign in | Constrava</title><style>', '<title>Sign in | Constrava</title>${fontLinks}<style>']
);\n`;

let source = await fs.readFile(analyticsSourcePath, "utf8");

const analyticsCssNeedle = "const analyticsCss = String.raw`";
if (!source.includes(analyticsCssNeedle)) throw new Error("Could not find analytics CSS declaration.");
source = source.replace(analyticsCssNeedle, `const fontCss = String.raw\`\n${fontCss}\n\`;\n\n${analyticsCssNeedle}`);

const styleReplacementNeedle = 'responsive = responsive.replace(styleMarker, "\\n" + wideCss + "\\n" + analyticsCss + "\\n`;\\n\\nconst crmContentNeedle");';
if (!source.includes(styleReplacementNeedle)) throw new Error("Could not find analytics style replacement.");
source = source.replace(styleReplacementNeedle, 'responsive = responsive.replace(styleMarker, "\\n" + fontCss + "\\n" + wideCss + "\\n" + analyticsCss + "\\n`;\\n\\nconst crmContentNeedle");');

const injectionNeedle = 'const injectionNeedle = "const injection = wizardInjection + crmInjection + ";';
if (!source.includes(injectionNeedle)) throw new Error("Could not find responsive injection marker.");
source = source.replace(injectionNeedle, `const generatedFontHeadPatch = ${JSON.stringify(generatedFontHeadPatch)};\n${injectionNeedle}`);

const injectionReplacementNeedle = 'responsive = responsive.replace(injectionNeedle, "const analyticsInjection = " + JSON.stringify(generatedAnalyticsPatch) + ";\\n" + injectionNeedle + "analyticsInjection + ");';
if (!source.includes(injectionReplacementNeedle)) throw new Error("Could not find analytics injection replacement.");
source = source.replace(injectionReplacementNeedle, 'responsive = responsive.replace(injectionNeedle, generatedFontHeadPatch + "const analyticsInjection = " + JSON.stringify(generatedAnalyticsPatch) + ";\\n" + injectionNeedle + "analyticsInjection + ");');

await fs.writeFile(fontRuntimePath, source);
await import(`${pathToFileURL(fontRuntimePath).href}?v=${Date.now()}`);
