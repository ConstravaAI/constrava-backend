import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-hide-legacy-workflow-panels-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const marker = "window.__constravaHideLegacyWorkflowPanels";

if (!source.includes(marker)) {
  source += `

(function(){
  if (window.__constravaHideLegacyWorkflowPanels) return;
  window.__constravaHideLegacyWorkflowPanels = true;

  function hideLegacyPanels(){
    var panel = document.getElementById('cxSimpleCrmRoot');
    if (!panel || !panel.parentElement) return;
    var parent = panel.parentElement;
    Array.prototype.forEach.call(parent.children, function(child){
      if (child === panel) return;
      child.setAttribute('data-cx-legacy-hidden', 'true');
      child.style.setProperty('display', 'none', 'important');
    });
  }

  window.addEventListener('load', hideLegacyPanels);
  window.addEventListener('cx-crm-ai-updated', hideLegacyPanels);
  setInterval(hideLegacyPanels, 600);
})();
`;
  fs.writeFileSync(file, source);
  console.log("Legacy CRM workflow/deal panels hidden outside simple CRM tabs.");
} else {
  console.log("Legacy CRM workflow panel hider already installed.");
}
