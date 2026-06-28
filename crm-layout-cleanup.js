(function(){
  if (window.__constravaCrmSideNavOnlyLoaded) return;
  window.__constravaCrmSideNavOnlyLoaded = true;

  const titles = {
    leads: ['Leads', 'Unified CRM entries sorted as leads. Use the left sidebar to change CRM sections.'],
    contacts: ['Contacts', 'People and contact records from the same unified CRM list.'],
    accounts: ['Accounts', 'Companies and organizations from the same unified CRM list.'],
    deals: ['Deals', 'Opportunities, values, status, and next steps from the same unified CRM list.'],
    tasks: ['Tasks', 'Follow-ups and next steps from the same unified CRM list.'],
    reports: ['Reports', 'CRM reporting based on the unified entry list.'],
    analytics: ['CRM Analytics', 'Pipeline and form-intake activity from the unified CRM system.'],
    all: ['Full CRM List', 'Every record in the unified CRM list.']
  };

  const style = document.createElement('style');
  style.textContent = `
    .crm-top.cx-titlebar{height:auto!important;min-height:62px!important;padding:14px 18px!important;display:flex!important;align-items:center!important;justify-content:space-between!important;gap:14px!important;background:linear-gradient(135deg,#26394d,#1d2f41)!important;color:#fff!important;overflow:visible!important}
    .crm-top.cx-titlebar button{display:none!important}
    .cx-crm-title-wrap{display:flex;flex-direction:column;gap:4px;min-width:0}
    .cx-crm-title-wrap strong{font-size:18px;letter-spacing:-.02em;color:#fff}
    .cx-crm-title-wrap span{font-size:12px;line-height:1.35;color:rgba(226,232,240,.82)}
    .cx-crm-title-badge{border:1px solid rgba(209,250,229,.28);background:rgba(16,185,129,.16);color:#d1fae5;border-radius:999px;padding:7px 10px;font-size:11px;font-weight:950;white-space:nowrap}
    .crm-left [data-crm], .crm-left button{cursor:pointer}
    .crm-left [data-crm].active, .crm-left button.active{background:#eaf6fd!important;color:#0b85be!important;font-weight:950!important}
    @media(max-width:800px){.crm-top.cx-titlebar{display:block!important}.cx-crm-title-badge{display:inline-flex;margin-top:8px}}
  `;
  document.head.appendChild(style);

  function activeSection(){
    const side = document.querySelector('.crm-left [data-crm].active, .crm-left button.active[data-crm]');
    const value = side && (side.getAttribute('data-crm') || side.textContent || '').trim().toLowerCase();
    if (value) return value;
    const any = document.querySelector('[data-crm].active');
    return any ? String(any.getAttribute('data-crm') || any.textContent || 'all').trim().toLowerCase() : 'all';
  }

  function niceTitle(key){
    const clean = String(key || 'all').toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return titles[clean] || [clean.replace(/-/g, ' ').replace(/\b\w/g, m => m.toUpperCase()), 'CRM section from the unified entry list.'];
  }

  function ensureSideNavClicks(){
    document.querySelectorAll('.crm-left [data-crm], .crm-left button[data-crm]').forEach(btn => {
      if (btn.__cxSideNavBound) return;
      btn.__cxSideNavBound = true;
      btn.addEventListener('click', () => setTimeout(updateTitle, 40), true);
    });
  }

  function updateTitle(){
    const top = document.querySelector('.crm-top');
    if (!top) return;
    top.classList.add('cx-titlebar');
    let wrap = top.querySelector('.cx-crm-title-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.className = 'cx-crm-title-wrap';
      wrap.innerHTML = '<strong></strong><span></span>';
      top.insertBefore(wrap, top.firstChild || null);
    }
    let badge = top.querySelector('.cx-crm-title-badge');
    if (!badge) {
      badge = document.createElement('div');
      badge.className = 'cx-crm-title-badge';
      badge.textContent = 'Side navigation only';
      top.appendChild(badge);
    }
    const [title, desc] = niceTitle(activeSection());
    wrap.querySelector('strong').textContent = title;
    wrap.querySelector('span').textContent = desc;
  }

  function cleanTopNav(){
    ensureSideNavClicks();
    updateTitle();
  }

  setInterval(cleanTopNav, 800);
  document.addEventListener('click', () => setTimeout(cleanTopNav, 60), true);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', cleanTopNav);
  else cleanTopNav();
})();
