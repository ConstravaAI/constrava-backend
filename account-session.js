(function(){
  if (window.ConstravaAccountSessionLoaded) return;
  window.ConstravaAccountSessionLoaded = true;

  function esc(value){return String(value == null ? '' : value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');}
  function ready(fn){if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn); else fn();}

  ready(async function(){
    try {
      const response = await fetch('/auth/me', { credentials: 'same-origin' });
      if (!response.ok) return;
      const data = await response.json();
      if (!data.ok || !data.account) return;
      const hero = document.querySelector('.hero') || document.querySelector('header');
      if (!hero || document.getElementById('accountPill')) return;
      const pill = document.createElement('div');
      pill.id = 'accountPill';
      pill.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;border:1px solid rgba(16,185,129,.25);border-radius:16px;padding:10px 12px;background:rgba(255,255,255,.86);box-shadow:0 12px 28px rgba(15,23,42,.07);color:#064e3b;font-weight:900';
      pill.innerHTML = '<span>🔐 '+esc(data.account.display_name || data.account.email)+'</span><button id="accountLogout" style="border:1px solid #dbe8e4;border-radius:12px;background:#fff;color:#047857;font-weight:900;padding:8px 11px;cursor:pointer">Log out</button>';
      hero.appendChild(pill);
      const logout = document.getElementById('accountLogout');
      if (logout) logout.addEventListener('click', async function(){
        logout.disabled = true;
        await fetch('/auth/logout', { method:'POST', credentials:'same-origin' }).catch(function(){});
        location.href = '/signin';
      });
    } catch {}
  });
})();
