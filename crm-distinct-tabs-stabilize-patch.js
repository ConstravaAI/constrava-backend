import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-distinct-tabs-stabilize-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldLine = 'top.innerHTML = `<div class="cx-titlebox"><strong>${esc(t.label)}</strong><span>${esc(t.desc)} • One unified CRM list</span></div><div class="cx-pill dark">Side tabs only</div>`;';
const newLine = 'top.innerHTML = `<div class="cx-titlebox"><strong>${esc(t.label)}</strong><span>${esc(t.desc)} • One unified CRM list</span></div><div id="cxTopAiTools" class="cx-top-ai"><input id="cxTopAiInput" placeholder="AI add/update: type what happened…"><button id="cxTopAiRun" type="button">AI Add</button><button id="cxTopAiOpen" class="secondary" type="button">Expand</button><span id="cxTopAiStatus" class="cx-top-ai-status">Ready</span></div>`;';

if (source.includes(oldLine) && !source.includes('id="cxTopAiTools"')) {
  source = source.replace(oldLine, newLine);
  changed = true;
}

const oldCss = '.cx-titlebox strong{display:block;font-size:19px;color:#fff}.cx-titlebox span{display:block;color:rgba(226,232,240,.82);font-size:12px;margin-top:4px}.cx-empty{';
const newCss = '.cx-titlebox strong{display:block;font-size:19px;color:#fff}.cx-titlebox span{display:block;color:rgba(226,232,240,.82);font-size:12px;margin-top:4px}.cx-top-ai{display:flex;gap:8px;align-items:center;min-width:min(620px,48vw);max-width:720px;margin-left:auto}.cx-top-ai input{flex:1;min-width:230px;border:1px solid rgba(209,250,229,.22);border-radius:12px;background:rgba(15,23,42,.28);color:#fff;padding:10px 12px;font:inherit;outline:0}.cx-top-ai input::placeholder{color:rgba(226,232,240,.68)}.cx-top-ai input:focus{border-color:rgba(16,185,129,.82);box-shadow:0 0 0 4px rgba(16,185,129,.16)}.cx-top-ai button{display:inline-flex!important;border:1px solid rgba(16,185,129,.75)!important;border-radius:12px!important;background:#10b981!important;color:#022c22!important;font-weight:950!important;padding:10px 12px!important;white-space:nowrap!important;cursor:pointer!important;min-height:auto!important;height:auto!important}.cx-top-ai button.secondary{background:rgba(255,255,255,.08)!important;color:#d1fae5!important;border-color:rgba(209,250,229,.25)!important}.cx-top-ai-status{font-size:11px;color:rgba(226,232,240,.78);max-width:190px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.cx-empty{';
if (source.includes(oldCss) && !source.includes('.cx-top-ai input')) {
  source = source.replace(oldCss, newCss);
  changed = true;
}

const oldMedia = '@media(max-width:1100px){.cx-dcrm-grid,.cx-three,.cx-two,.cx-form-grid{grid-template-columns:1fr}.cx-kanban{grid-template-columns:1fr}.cx-wide{grid-column:auto}.cx-settings-row{grid-template-columns:1fr}}`';
const newMedia = '@media(max-width:1100px){.cx-dcrm-grid,.cx-three,.cx-two,.cx-form-grid{grid-template-columns:1fr}.cx-kanban{grid-template-columns:1fr}.cx-wide{grid-column:auto}.cx-settings-row{grid-template-columns:1fr}.crm-top.cx-dcrm-titlebar{display:block!important}.cx-top-ai{margin:12px 0 0;min-width:0;max-width:none;width:100%}}@media(max-width:560px){.cx-top-ai{display:grid;grid-template-columns:1fr auto}.cx-top-ai input{min-width:0}.cx-top-ai button.secondary{display:none!important}.cx-top-ai-status{display:none}}`';
if (source.includes(oldMedia) && !source.includes('@media(max-width:560px){.cx-top-ai')) {
  source = source.replace(oldMedia, newMedia);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Distinct CRM tabs now own stable top-bar AI controls.");
} else {
  console.log("Distinct CRM tabs top-bar controls already stable or anchor not found.");
}
