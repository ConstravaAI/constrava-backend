import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-topbar-ai-tools-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function addAfterOnce(search, addition) {
  if (source.includes(addition)) return;
  if (source.includes(search)) {
    source = source.replace(search, search + addition);
    changed = true;
  }
}

addAfterOnce('<script src="/crm-distinct-tabs.js"></script>', '<script src="/crm-topbar-ai-tools.js"></script>');
addAfterOnce('<script src="/crm-layout-cleanup.js"></script>', '<script src="/crm-topbar-ai-tools.js"></script>');
addAfterOnce('<script src="/crm-form-integrations.js"></script>', '<script src="/crm-topbar-ai-tools.js"></script>');

if (!source.includes('app.get("/crm-topbar-ai-tools.js"')) {
  const anchor = 'app.get("/crm-distinct-tabs.js"';
  const fallback = 'app.get("/crm-layout-cleanup.js"';
  const route = 'app.get("/crm-topbar-ai-tools.js", (req, res) => { res.type("application/javascript").sendFile(path.join(__dirname, "crm-topbar-ai-tools.js")); });\n';
  if (source.includes(anchor)) {
    source = source.replace(anchor, route + anchor);
    changed = true;
  } else if (source.includes(fallback)) {
    source = source.replace(fallback, route + fallback);
    changed = true;
  } else {
    console.warn("[crm-topbar-ai-tools-patch] Could not find route anchor.");
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM top bar AI tools injected.");
} else {
  console.log("CRM top bar AI tools already injected or anchor missing.");
}
