import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-distinct-tabs-nojump-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldBoot = `  function boot(){
    if(!document.querySelector('.crm-shell')) return;
    rebuildSide(); updateTitle(); ensureRoot(); render(); loadEntries();
  }
  setInterval(boot, 1200);
  document.addEventListener('click', () => setTimeout(boot, 80), true);
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();`;

const newBoot = `  let cxBooted = false;
  let cxLoadedEntries = false;

  function boot(){
    if(!document.querySelector('.crm-shell')) return false;
    if(cxBooted) return true;
    cxBooted = true;
    rebuildSide();
    updateTitle();
    ensureRoot();
    render();
    if(!cxLoadedEntries){
      cxLoadedEntries = true;
      loadEntries();
    }
    return true;
  }

  function tryBoot(){
    if(boot()) return;
    setTimeout(tryBoot, 300);
  }

  document.addEventListener('click', function(e){
    const tab = e.target && e.target.closest && e.target.closest('[data-cx-tab]');
    if(tab) setTimeout(function(){ updateTitle(); }, 40);
  }, true);

  window.addEventListener('cx-crm-ai-updated', function(){
    cxLoadedEntries = false;
    loadEntries();
  });

  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', tryBoot); else tryBoot();`;

if (source.includes(oldBoot)) {
  source = source.replace(oldBoot, newBoot);
  changed = true;
}

// Guard render so it does not destroy the active input while the user is typing in the top bar.
const oldUpdateTitleCall = `    rebuildSide(); updateTitle();
    const panel = ensureRoot(); if(!panel) return;`;
const newUpdateTitleCall = `    rebuildSide();
    if(document.activeElement && document.activeElement.id !== 'cxTopAiInput') updateTitle();
    else if(!document.getElementById('cxTopAiTools')) updateTitle();
    const panel = ensureRoot(); if(!panel) return;`;
if (source.includes(oldUpdateTitleCall)) {
  source = source.replace(oldUpdateTitleCall, newUpdateTitleCall);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM distinct tabs no-jump behavior applied.");
} else {
  console.log("CRM distinct tabs no-jump patch already applied or anchor not found.");
}
