import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-layout-cleanup-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function addAfterOnce(search, replacement) {
  if (source.includes(replacement)) return;
  if (source.includes(search)) {
    source = source.replace(search, search + replacement);
    changed = true;
  }
}

addAfterOnce('<script src="/crm-unified-entry-ui.js"></script>', '<script src="/crm-layout-cleanup.js"></script>');
addAfterOnce('<script src="/crm-form-integrations.js"></script>', '<script src="/crm-layout-cleanup.js"></script>');

if (!source.includes('app.get("/crm-layout-cleanup.js"')) {
  const anchor = 'app.get("/crm",';
  const route = 'app.get("/crm-layout-cleanup.js", (req, res) => { res.type("application/javascript").sendFile(path.join(__dirname, "crm-layout-cleanup.js")); });\n';
  if (source.includes(anchor)) {
    source = source.replace(anchor, route + anchor);
    changed = true;
  } else {
    console.warn("[crm-layout-cleanup-patch] Could not find /crm route anchor.");
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM layout cleanup script injected.");
} else {
  console.log("CRM layout cleanup script already injected or anchor not found.");
}
