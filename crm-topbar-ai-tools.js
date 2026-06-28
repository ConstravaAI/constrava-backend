(function(){
  if (window.__constravaCrmTopbarAiToolsLoaded) return;
  window.__constravaCrmTopbarAiToolsLoaded = true;

  const params = new URLSearchParams(location.search);
  const token = params.get('token') || 'demo';

  const style = document.createElement('style');
  style.textContent = `
    .cx-top-ai{display:flex;gap:8px;align-items:center;min-width:min(620px,48vw);max-width:720px;margin-left:auto}
    .cx-top-ai input{flex:1;min-width:230px;border:1px solid rgba(209,250,229,.22);border-radius:12px;background:rgba(15,23,42,.28);color:#fff;padding:10px 12px;font:inherit;outline:0}
    .cx-top-ai input::placeholder{color:rgba(226,232,240,.68)}
    .cx-top-ai input:focus{border-color:rgba(16,185,129,.82);box-shadow:0 0 0 4px rgba(16,185,129,.16)}
    .cx-top-ai button{display:inline-flex!important;border:1px solid rgba(16,185,129,.75)!important;border-radius:12px!important;background:#10b981!important;color:#022c22!important;font-weight:950!important;padding:10px 12px!important;white-space:nowrap!important;cursor:pointer!important;min-height:auto!important;height:auto!important}
    .cx-top-ai button.secondary{background:rgba(255,255,255,.08)!important;color:#d1fae5!important;border-color:rgba(209,250,229,.25)!important}
    .cx-top-ai-status{font-size:11px;color:rgba(226,232,240,.78);max-width:190px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .cx-top-ai-modal{position:fixed;inset:0;z-index:2000;display:none;place-items:center;background:rgba(2,18,14,.64);backdrop-filter:blur(9px);padding:20px}
    .cx-top-ai-modal.open{display:grid}
    .cx-top-ai-box{width:min(760px,100%);background:#fff;border:1px solid rgba(16,185,129,.22);border-radius:24px;box-shadow:0 36px 120px rgba(0,0,0,.35);overflow:hidden}
    .cx-top-ai-head{padding:20px 22px;background:linear-gradient(135deg,#f8fffc,#ecfdf5);border-bottom:1px solid #dbe8e4}.cx-top-ai-head h2{margin:0;color:#022c22}.cx-top-ai-head p{margin:7px 0 0;color:#64748b;line-height:1.45}
    .cx-top-ai-body{padding:20px 22px}.cx-top-ai-body textarea{width:100%;min-height:160px;border:1px solid #d8e0e7;border-radius:14px;background:#f8fafc;padding:13px;color:#0f172a;font:inherit;resize:vertical}.cx-top-ai-body textarea:focus{outline:0;border-color:#10b981;box-shadow:0 0 0 4px rgba(16,185,129,.12)}
    .cx-top-ai-foot{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:16px 22px;border-top:1px solid #dbe8e4;background:#f8fffc}.cx-top-ai-foot button{border:1px solid #d8e0e7;border-radius:12px;background:#fff;color:#073d32;font-weight:900;padding:10px 12px;cursor:pointer}.cx-top-ai-foot button.primary{background:#10b981;border-color:#10b981;color:#022c22}.cx-top-ai-result{margin-top:12px;border:1px solid #dbe8e4;border-radius:12px;background:#f8fafc;padding:11px 12px;color:#334155;font-size:13px;line-height:1.45}.cx-top-ai-result.ok{background:#ecfdf5;color:#047857;border-color:rgba(16,185,129,.35)}.cx-top-ai-result.warn{background:#fffbeb;color:#92400e;border-color:rgba(245,158,11,.35)}
    @media(max-width:1050px){.crm-top.cx-dcrm-titlebar{display:block!important}.cx-top-ai{margin:12px 0 0;min-width:0;max-width:none;width:100%}.cx-top-ai-status{display:none}}
    @media(max-width:560px){.cx-top-ai{display:grid;grid-template-columns:1fr auto}.cx-top-ai input{min-width:0}.cx-top-ai button.secondary{display:none!important}}
  `;
  document.head.appendChild(style);

  function topbar(){ return document.querySelector('.crm-top.cx-dcrm-titlebar') || document.querySelector('.crm-top'); }
  function toast(msg){ const t=document.getElementById('toast'); if(t){t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);} }
  function setStatus(msg){ const s=document.getElementById('cxTopAiStatus'); if(s) s.textContent = msg; }
  function aiText(){ const input=document.getElementById('cxTopAiInput'); return input ? input.value.trim() : ''; }
  function clearInput(){ const input=document.getElementById('cxTopAiInput'); if(input) input.value=''; }

  async function runAi(text, resultEl){
    const content = String(text || '').trim();
    if(!content){
      if(resultEl){ resultEl.className='cx-top-ai-result warn'; resultEl.textContent='Type what happened first.'; }
      else setStatus('Type an update first');
      return;
    }
    setStatus('Interpreting…');
    if(resultEl){ resultEl.className='cx-top-ai-result'; resultEl.textContent='Interpreting and updating CRM…'; }
    try{
      const r = await fetch('/api/crm/ai-entry?token=' + encodeURIComponent(token), {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ token, text:content })
      });
      const j = await r.json();
      if(!j.ok) throw new Error(j.error || 'AI CRM update failed.');
      const count = (j.actions && j.actions.length) || 1;
      setStatus('Saved ' + count + ' action' + (count === 1 ? '' : 's'));
      if(resultEl){ resultEl.className='cx-top-ai-result ok'; resultEl.textContent='Saved ' + count + ' CRM action' + (count === 1 ? '' : 's') + ' into the unified list.'; }
      clearInput();
      toast('CRM updated by AI.');
      window.dispatchEvent(new CustomEvent('cx-crm-ai-updated', { detail:j }));
    }catch(err){
      const msg = err.message || 'AI CRM update failed.';
      setStatus('Failed');
      if(resultEl){ resultEl.className='cx-top-ai-result warn'; resultEl.textContent=msg; }
      else toast(msg);
    }
  }

  function modal(){
    let m = document.getElementById('cxTopAiModal');
    if(m) return m;
    m = document.createElement('div');
    m.id = 'cxTopAiModal';
    m.className = 'cx-top-ai-modal';
    m.innerHTML = `<div class="cx-top-ai-box"><div class="cx-top-ai-head"><h2>AI Add / Update CRM</h2><p>Type what happened in plain English. The AI can create a new entry, update matching entries, or add follow-up tasks to the unified CRM list.</p></div><div class="cx-top-ai-body"><textarea id="cxTopAiModalText" placeholder="Example: John Henry from Henry Construction called. Phone 123-754-3808, email HenryJ@email.com. He wants a website quote and is ready for a proposal. Create or update the entry and make the next step send a proposal."></textarea><div id="cxTopAiModalResult" class="cx-top-ai-result">No command run yet.</div></div><div class="cx-top-ai-foot"><button id="cxTopAiClose" type="button">Close</button><div><button id="cxTopAiExample" type="button">Load example</button> <button id="cxTopAiModalRun" class="primary" type="button">Run AI Update</button></div></div></div>`;
    document.body.appendChild(m);
    m.addEventListener('click', e => { if(e.target === m) m.classList.remove('open'); });
    document.getElementById('cxTopAiClose').onclick = () => m.classList.remove('open');
    document.getElementById('cxTopAiExample').onclick = () => { document.getElementById('cxTopAiModalText').value = 'John Henry from Henry Construction called. Phone 123-754-3808, email HenryJ@email.com. He wants a website quote and is ready for a proposal. Create or update the CRM entry and make the next step send a proposal.'; };
    document.getElementById('cxTopAiModalRun').onclick = () => runAi(document.getElementById('cxTopAiModalText').value, document.getElementById('cxTopAiModalResult'));
    return m;
  }

  function openModal(){
    const m = modal();
    const quick = aiText();
    if(quick) document.getElementById('cxTopAiModalText').value = quick;
    m.classList.add('open');
    setTimeout(() => document.getElementById('cxTopAiModalText')?.focus(), 50);
  }

  function ensure(){
    const top = topbar();
    if(!top) return;
    if(document.getElementById('cxTopAiTools')) return;
    const tool = document.createElement('div');
    tool.id = 'cxTopAiTools';
    tool.className = 'cx-top-ai';
    tool.innerHTML = `<input id="cxTopAiInput" placeholder="AI add/update: type what happened…"><button id="cxTopAiRun" type="button">AI Add</button><button id="cxTopAiOpen" class="secondary" type="button">Expand</button><span id="cxTopAiStatus" class="cx-top-ai-status">Ready</span>`;
    top.appendChild(tool);
    document.getElementById('cxTopAiRun').onclick = () => runAi(aiText(), null);
    document.getElementById('cxTopAiOpen').onclick = openModal;
    document.getElementById('cxTopAiInput').addEventListener('keydown', e => { if(e.key === 'Enter' && (e.ctrlKey || e.metaKey)){ runAi(aiText(), null); } });
    modal();
  }

  setInterval(ensure, 500);
  document.addEventListener('click', () => setTimeout(ensure, 40), true);
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensure); else ensure();
})();
