import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-distinct-tabs-patch] server.js not found.");
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

addAfterOnce('<script src="/crm-layout-cleanup.js"></script>', '<script src="/crm-distinct-tabs.js"></script>');
addAfterOnce('<script src="/crm-form-integrations.js"></script>', '<script src="/crm-distinct-tabs.js"></script>');
addAfterOnce('<script src="/crm-unified-entry-ui.js"></script>', '<script src="/crm-distinct-tabs.js"></script>');

if (!source.includes('app.get("/crm-distinct-tabs.js"')) {
  const anchor = 'app.get("/crm-layout-cleanup.js"';
  const fallback = 'app.get("/crm",';
  const route = 'app.get("/crm-distinct-tabs.js", (req, res) => { res.type("application/javascript").sendFile(path.join(__dirname, "crm-distinct-tabs.js")); });\n';
  if (source.includes(anchor)) {
    source = source.replace(anchor, route + anchor);
    changed = true;
  } else if (source.includes(fallback)) {
    source = source.replace(fallback, route + fallback);
    changed = true;
  } else {
    console.warn("[crm-distinct-tabs-patch] Could not find CRM route anchor.");
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Distinct CRM tabs workspace injected.");
} else {
  console.log("Distinct CRM tabs workspace already injected or anchor missing.");
}
