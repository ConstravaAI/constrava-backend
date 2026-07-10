import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const responsiveSourcePath = path.join(here, "server-responsive.js");
const wideRuntimePath = path.join(here, ".server-responsive-wide.js");

const wideCss = String.raw`
/* Wide app layout layer: reduce dead space and make the dashboard feel full-screen */
html,body{min-height:100%}.shell{width:calc(100% - 18px)!important;max-width:none!important;margin:10px auto!important}.topbar{padding:10px 14px!important}.workspace{margin-bottom:10px!important;gap:10px!important;align-items:center!important}.workspace h1{font-size:36px!important}.workspace p{margin:0 0 3px!important}.grid{gap:12px!important}.card{border-radius:14px!important}.in{padding:14px!important}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))!important}.two{grid-template-columns:minmax(0,1fr) minmax(0,1fr)!important}.metricValue{font-size:29px!important}.item{padding:10px 0!important}.crmShell{grid-template-columns:210px minmax(0,1fr)!important;gap:12px!important}.crmSide{top:72px!important;border-radius:14px!important;padding:8px!important}.crmTab{padding:9px 10px!important;border-radius:10px!important}.crmListHead{margin-bottom:6px!important}.crmToolbar{padding:9px 0!important;margin:4px 0 0!important}.crmToolbar input{min-width:min(360px,100%)!important}.recordCard{gap:8px!important}.fieldLine{margin-top:3px!important}.empty,.crmEmpty{min-height:120px!important;padding:20px!important}.resource{gap:10px!important}.resourceIcon{width:38px!important;height:38px!important;border-radius:12px!important}pre{padding:12px!important}.modalHead,.modalBody,.modalFoot{padding:14px!important}
@media(min-width:1500px){.shell{width:calc(100% - 22px)!important}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))!important}.crmShell{grid-template-columns:220px minmax(0,1fr)!important}.workspace h1{font-size:38px!important}.in{padding:15px!important}}
@media(max-width:1100px){.shell{width:calc(100% - 14px)!important;margin:8px auto!important}.crmShell{grid-template-columns:1fr!important}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))!important}.two{grid-template-columns:1fr!important}}
@media(max-width:760px){.shell{width:calc(100% - 10px)!important;margin:8px auto!important}.topbar{padding:9px!important}.workspace{margin-bottom:8px!important}.workspace h1{font-size:30px!important}.in{padding:12px!important}.card{border-radius:12px!important}.metrics{grid-template-columns:1fr!important}.crmSide{padding:7px!important}.crmToolbar{padding:8px 0!important}.item{padding:9px 0!important}}
`;

let responsive = await fs.readFile(responsiveSourcePath, "utf8");
const marker = "`;\n\nconst crmContentNeedle";

if (!responsive.includes(marker)) {
  throw new Error("Could not find responsiveCss closing marker in src/server-responsive.js");
}

responsive = responsive.replace(marker, "\n" + wideCss + "\n`;\n\nconst crmContentNeedle");
await fs.writeFile(wideRuntimePath, responsive);
await import(`${pathToFileURL(wideRuntimePath).href}?v=${Date.now()}`);
