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
  var storagePrefix = 'constravaSidebarGroupCollapsed:';

  function norm(text){ return String(text || '').replace(/\\s+/g, ' ').trim(); }
  function keyFor(label){ return storagePrefix + label.toLowerCase(); }
  function isCollapsed(label){ return localStorage.getItem(keyFor(label)) === '1'; }
  function setCollapsed(label, collapsed){ localStorage.setItem(keyFor(label), collapsed ? '1' : '0'); }
  function groupLabelFor(el){
    var text = norm(el && el.textContent);
    for (var i = 0; i < GROUPS.length; i++) if (text === GROUPS[i]) return GROUPS[i];
    return '';
  }
  function looksLikeGroupHeader(el){
    if (!el || !el.textContent) return false;
    var label = groupLabelFor(el);
    if (!label) return false;
    if (el.closest('[data-cx-collapse-control]')) return false;
    return true;
  }
  function isHeaderish(el){
    if (!el || !el.textContent) return false;
    if (groupLabelFor(el)) return true;
    var tag = String(el.tagName || '').toLowerCase();
    var cls = String(el.className || '').toLowerCase();
    return /h1|h2|h3|h4|h5|h6/.test(tag) || /title|section|heading|label|nav-title|group/.test(cls);
  }
  function sidebarRoots(){
    var roots = [];
    var selectors = ['.crm-left', '.sidebar', '.side-bar', '.app-sidebar', '.cx-sidebar', 'aside', 'nav'];
    selectors.forEach(function(sel){
      Array.prototype.forEach.call(document.querySelectorAll(sel), function(el){
        if (roots.indexOf(el) === -1) roots.push(el);
      });
    });
    return roots;
  }
  function collectItems(header){
    var items = [];
    var next = header.nextElementSibling;
    while (next) {
      if (isHeaderish(next)) break;
      items.push(next);
      next = next.nextElementSibling;
    }
    if (!items.length) {
      var parent = header.parentElement;
      if (parent) {
        next = parent.nextElementSibling;
        while (next) {
          if (isHeaderish(next)) break;
          items.push(next);
          next = next.nextElementSibling;
        }
      }
    }
    return items;
  }
  function makeControl(header, label){
    if (header.getAttribute('data-cx-collapse-control') === '1') return;
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

    function toggle(){
      var nextState = !isCollapsed(label);
      setCollapsed(label, nextState);
      applyAll();
    }
    header.addEventListener('click', toggle);
    header.addEventListener('keydown', function(event){
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        toggle();
      }
    });
  }
  function applyHeader(header, label){
    makeControl(header, label);
    var collapsed = isCollapsed(label);
    var items = collectItems(header);
    items.forEach(function(item){
      item.style.setProperty('display', collapsed ? 'none' : '', collapsed ? 'important' : '');
      item.setAttribute('data-cx-collapse-member', label);
    });
    var chev = header.querySelector('.cx-collapse-chevron');
    if (chev) chev.textContent = collapsed ? '▸' : '▾';
    header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  }
  function applyAll(){
    sidebarRoots().forEach(function(root){
      Array.prototype.forEach.call(root.querySelectorAll('*'), function(el){
        if (!looksLikeGroupHeader(el)) return;
        var label = groupLabelFor(el);
        if (label) applyHeader(el, label);
      });
    });
  }

  var style = document.createElement('style');
  style.textContent = '[data-cx-collapse-control="1"]{border-radius:10px;padding-right:8px}[data-cx-collapse-control="1"]:hover{background:rgba(16,185,129,.08)}';
  document.head.appendChild(style);

  var observer = new MutationObserver(function(){ applyAll(); });
  observer.observe(document.documentElement, { childList:true, subtree:true });
  window.addEventListener('load', applyAll);
  setInterval(applyAll, 1000);
  applyAll();
})();
`;
  fs.writeFileSync(file, source);
  console.log("CRM and Analytics sidebar groups are now collapsible.");
} else {
  console.log("CRM and Analytics sidebar collapsible groups already installed.");
}
