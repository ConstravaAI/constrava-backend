import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "crm-actions-visibility-v2";

let source = await fs.readFile(runtimeWrapperPath, "utf8");

if (!source.includes(marker)) {
  const writeNeedle = "await fs.writeFile(runtimePath, source);";
  const patch = String.raw`
// crm-actions-visibility-v2
const crmActionVisibilityCode = "function syncCrmActionButtons(){var show=S.tab==='crm';['priorityCheck','aiAdd'].forEach(function(id){var el=document.getElementById(id);if(el)el.style.display=show?'':'none'})}";
if (!source.includes("function syncCrmActionButtons()")) {
  source = source.replace("function render(){", crmActionVisibilityCode + "\nfunction render(){");
  source = source.replace("app.innerHTML=h;bind();syncNotifications()", "app.innerHTML=h;bind();syncNotifications();syncCrmActionButtons()");
  source = source.replace("document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};", "document.getElementById('aiAdd').onclick=function(){S.crmView='edit';tab('crm')};syncCrmActionButtons();");
}
`;

  if (!source.includes(writeNeedle)) throw new Error("Could not find runtime write target in src/server-runtime.js");
  source = source.replace(writeNeedle, `${patch}\n${writeNeedle}`);
  await fs.writeFile(runtimeWrapperPath, `${source}\n// ${marker}\n`);
}

await import("./server-account-persistence.js");
