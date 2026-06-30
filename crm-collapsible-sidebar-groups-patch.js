import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-collapsible-sidebar-groups-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const marker = "window.__constravaCollapsibleSidebarGroups";

if (!source.includes(marker)) {
  source += `

(function(){
  if (window.__constravaCollapsibleSidebarGroups) return;
  window.__constravaCollapsibleSidebarGroups = true;

  var GROUPS = ['CRM', 'Analytics'];
  var storagePrefix = 'constravaSidebarSectionCollapsed:';

  function norm(text){ return String(text || '').replace(/\\s+/g, ' ').trim(); }
  function keyFor(label){ return storagePrefix + label.toLowerCase(); }
  function isCollapsed(label){ return localStorage.getItem(keyFor(label)) === '1'; }
  function setCollapsed(label, collapsed){ localStorage.setItem(keyFor(label), collapsed ? '1' : '0'); }
  function labelFromText(text){
    text = norm(text);
    for (var i = 0; i < GROUPS.length; i++) if (text === GROUPS[i]) return GROUPS[i];
    return '';
  }
  function labelFor(el){ return labelFromText(el && el.textContent); }
  function sidebarRoots(){
    var roots = [];
    ['.crm-left', '.sidebar', '.side-bar', '.app-sidebar', '.cx-sidebar', 'aside', 'nav'].forEach(function(sel){
      Array.prototype.forEach.call(document.querySelectorAll(sel), function(el){
        if (roots.indexOf(el) === -1) roots.push(el);
      });
    });
    return roots;
  }
  function directInteractiveCount(el){
    return el ? el.querySelectorAll('a,button,[role="button"],.nav-item,.menu-item,.sidebar-item,.cx-side-btn,.cx-simple-side-btn').length : 0;
  }
  function looksLikeSection(el){
    if (!el || !el.parentElement) return false;
    var cls = String(el.className || '').toLowerCase();
    var role = String(el.getAttribute && el.getAttribute('role') || '').toLowerCase();
    if (/section|group|card|panel|menu|nav|sidebar|cluster/.test(cls)) return true;
    if (/group|navigation|menu/.test(role)) return true;
    if (directInteractiveCount(el) >= 2) return true;
    return false;
  }
  function findWholeSection(header, root){
    var current = header;
    var best = null;
    for (var i = 0; current && current !== root && i < 6; i++, current = current.parentElement) {
      if (!current.parentElement || current === document.body || current === document.documentElement) break;
      var text = norm(current.textContent || '');
      if (!text) continue;
      var containsThisLabel = text.indexOf(norm(header.textContent || '')) !== -1;
      var containsOtherGroup = GROUPS.some(function(g){ return g !== labelFor(header) && text.indexOf(g) !== -1; });
      if (containsThisLabel && !containsOtherGroup && looksLikeSection(current)) best = current;
    }
    return best || header.parentElement || header;
  }
  function findHeaders(root){
    var headers = [];
    Array.prototype.forEach.call(root.querySelectorAll('*'), function(el){
      if (el.closest('[data-cx-generated-section-control]')) return;
      var label = labelFor(el);
      if (!label) return;
      if (el.children.length > 2 && directInteractiveCount(el) > 1) return;
      headers.push({ el: el, label: label });
    });
    return headers;
  }
  function makeHeaderClickable(header, section, label){
    if (header.getAttribute('data-cx-collapse-control') !== '1') {
      header.setAttribute('data-cx-collapse-control', '1');
      header.setAttribute('role', 'button');
      header.setAttribute('tabindex', '0');
      header.style.cursor = 'pointer';
      header.style.userSelect = 'none';
      header.style.display = header.style.display || 'flex';
      header.style.alignItems = 'center';
      header.style.justifyContent = 'space-between';
      header.dataset.cxGroupLabel = label;
      if (!header.querySelector('.cx-collapse-chevron')) {
        var chev = document.createElement('span');
        chev.className = 'cx-collapse-chevron';
        chev.style.marginLeft = '8px';
        chev.style.fontSize = '11px';
        chev.style.opacity = '.75';
        header.appendChild(chev);
      }
      function toggle(event){
        if (event) event.stopPropagation();
        setCollapsed(label, !isCollapsed(label));
        applyAll();
      }
      header.addEventListener('click', toggle);
      header.addEventListener('keydown', function(event){
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggle(event);
        }
      });
    }
    section.setAttribute('data-cx-collapsible-section', label);
  }
  function childContains(child, node){ return child === node || child.contains(node); }
  function applySection(header, section, label){
    makeHeaderClickable(header, section, label);
    var collapsed = isCollapsed(label);
    Array.prototype.forEach.call(section.children, function(child){
      if (childContains(child, header)) {
        child.style.removeProperty('display');
        return;
      }
      child.setAttribute('data-cx-collapse-member', label);
      if (collapsed) child.style.setProperty('display', 'none', 'important');
      else child.style.removeProperty('display');
    });

    if (section === header || section.children.length <= 1) {
      Array.prototype.forEach.call(header.parentElement ? header.parentElement.children : [], function(child){
        if (childContains(child, header)) return;
        if (collapsed) child.style.setProperty('display', 'none', 'important');
        else child.style.removeProperty('display');
      });
    }

    section.classList.toggle('cx-section-collapsed', collapsed);
    var chev = header.querySelector('.cx-collapse-chevron');
    if (chev) chev.textContent = collapsed ? '▸' : '▾';
    header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  }
  function applyAll(){
    sidebarRoots().forEach(function(root){
      findHeaders(root).forEach(function(pair){
        var section = findWholeSection(pair.el, root);
        applySection(pair.el, section, pair.label);
      });
    });
  }

  var style = document.createElement('style');
  style.textContent = '[data-cx-collapse-control="1"]{border-radius:10px;padding:8px}[data-cx-collapse-control="1"]:hover{background:rgba(16,185,129,.10)}[data-cx-collapsible-section].cx-section-collapsed{padding-bottom:8px!important;min-height:0!important}.cx-collapse-chevron{font-weight:900}';
  document.head.appendChild(style);

  var observer = new MutationObserver(function(){ applyAll(); });
  observer.observe(document.documentElement, { childList:true, subtree:true });
  window.addEventListener('load', applyAll);
  setInterval(applyAll, 1000);
  applyAll();
})();
`;
  fs.writeFileSync(file, source);
  console.log("CRM and Analytics whole sidebar sections are now collapsible.");
} else {
  console.log("CRM and Analytics whole sidebar collapsible sections already installed.");
}
