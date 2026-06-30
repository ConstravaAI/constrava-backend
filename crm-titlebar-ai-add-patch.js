import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-titlebar-ai-add-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const marker = "window.__constravaCrmTitlebarAiAdd";

if (!source.includes(marker)) {
  source += `

(function(){
  if (window.__constravaCrmTitlebarAiAdd) return;
  window.__constravaCrmTitlebarAiAdd = true;

  var token = new URLSearchParams(location.search).get('token') || 'demo';

  function ensureStyles(){
    if (document.getElementById('cxTitlebarAiAddStyle')) return;
    var style = document.createElement('style');
    style.id = 'cxTitlebarAiAddStyle';
    style.textContent = '.crm-top.cx-simple-titlebar{display:grid!important;grid-template-columns:minmax(220px,1fr) minmax(360px,650px)!important;gap:14px!important;align-items:center!important}.cx-simple-title-pill{display:none!important}.cx-titlebar-ai-add{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center}.cx-titlebar-ai-input{width:100%;border:1px solid rgba(255,255,255,.22);border-radius:13px;background:rgba(255,255,255,.12);color:#fff;padding:11px 12px;font:inherit;outline:none}.cx-titlebar-ai-input::placeholder{color:rgba(255,255,255,.68)}.cx-titlebar-ai-btn{border:0;border-radius:13px;background:#10b981;color:#022c22;font-weight:950;padding:11px 15px;cursor:pointer;white-space:nowrap}.cx-titlebar-ai-status{grid-column:1/-1;color:rgba(226,232,240,.78);font-size:11px;min-height:14px}@media(max-width:950px){.crm-top.cx-simple-titlebar{grid-template-columns:1fr!important}.cx-titlebar-ai-add{grid-template-columns:1fr}.cx-titlebar-ai-btn{width:100%}}';
    document.head.appendChild(style);
  }

  async function submitTitlebarAi(){
    var input = document.getElementById('cxTitlebarAiInput');
    var status = document.getElementById('cxTitlebarAiStatus');
    var text = input ? input.value.trim() : '';
    if (!text) return;
    if (status) status.textContent = 'Saving with AI...';
    try {
      var r = await fetch('/api/crm/ai-entry?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, text: text })
      });
      var j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Could not save.');
      if (input) input.value = '';
      if (status) status.textContent = 'Saved. Reloading records...';
      window.dispatchEvent(new CustomEvent('cx-crm-ai-updated', { detail: j }));
      setTimeout(function(){ var s = document.getElementById('cxTitlebarAiStatus'); if (s) s.textContent = ''; }, 1800);
    } catch (err) {
      if (status) status.textContent = err && err.message ? err.message : 'Could not save.';
    }
  }

  function installTitlebarAi(){
    ensureStyles();
    var top = document.querySelector('.crm-top.cx-simple-titlebar') || document.querySelector('.crm-top');
    if (!top) return;
    if (!top.querySelector('.cx-simple-title')) return;
    if (document.getElementById('cxTitlebarAiAdd')) return;

    var oldPill = top.querySelector('.cx-simple-title-pill');
    if (oldPill) oldPill.style.display = 'none';

    var box = document.createElement('div');
    box.id = 'cxTitlebarAiAdd';
    box.className = 'cx-titlebar-ai-add';
    box.innerHTML = '<input id="cxTitlebarAiInput" class="cx-titlebar-ai-input" placeholder="AI add/update: type what happened anywhere in the CRM..."><button id="cxTitlebarAiBtn" class="cx-titlebar-ai-btn" type="button">AI Add</button><div id="cxTitlebarAiStatus" class="cx-titlebar-ai-status"></div>';
    top.appendChild(box);

    var btn = document.getElementById('cxTitlebarAiBtn');
    var input = document.getElementById('cxTitlebarAiInput');
    if (btn) btn.onclick = submitTitlebarAi;
    if (input) input.onkeydown = function(event){ if (event.key === 'Enter') { event.preventDefault(); submitTitlebarAi(); } };
  }

  var observer = new MutationObserver(installTitlebarAi);
  observer.observe(document.documentElement, { childList:true, subtree:true });
  window.addEventListener('load', installTitlebarAi);
  window.addEventListener('cx-crm-ai-updated', installTitlebarAi);
  setInterval(installTitlebarAi, 500);
  installTitlebarAi();
})();
`;
  fs.writeFileSync(file, source);
  console.log("CRM title bar AI Add input restored.");
} else {
  console.log("CRM title bar AI Add input already restored.");
}
