import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-return-syntax-repair-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const marker = "function mergeEntryUpdate";
const wrapped = "return ensureCrmEntityLinkId(ensureCrmRecordId({";
const single = "return ensureCrmRecordId({";

function repairBeforeMerge(startText, closeText) {
  let searchFrom = 0;
  while (true) {
    const start = source.indexOf(startText, searchFrom);
    if (start === -1) break;
    const merge = source.indexOf(marker, start);
    if (merge === -1) break;
    const section = source.slice(start, merge);
    const badEnd = section.lastIndexOf("\n  };\n}\n");
    if (badEnd !== -1) {
      const absolute = start + badEnd;
      source = source.slice(0, absolute) + "\n  " + closeText + "\n}\n" + source.slice(merge);
      changed = true;
      searchFrom = absolute + closeText.length;
    } else {
      searchFrom = merge + marker.length;
    }
  }
}

repairBeforeMerge(wrapped, "}));");
repairBeforeMerge(single, "});");

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM return wrapper syntax repaired.");
} else {
  console.log("CRM return wrapper syntax already valid or no target found.");
}
