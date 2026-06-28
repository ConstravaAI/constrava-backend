import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-entry-type-field-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function replaceAllSafe(find, replacement) {
  if (source.includes(find)) {
    source = source.replaceAll(find, replacement);
    changed = true;
  }
}

// Add a normalized `type` variable inside completeCrmEntry.
replaceAllSafe(
  'const now = new Date().toISOString();\n  return {',
  'const now = new Date().toISOString();\n  const entryType = entryCleanText(src.type || src.record_type || src.category || (String(src.module || "").toLowerCase().includes("client") ? "client" : "lead"));\n  return {'
);

// Store type beside record_type/module on complete entries.
replaceAllSafe(
  'record_type: entryCleanText(src.record_type || src.type || "crm_entry"),\n    module: entryCleanText(src.module || "leads"),',
  'type: entryType,\n    record_type: entryCleanText(src.record_type || src.type || entryType || "crm_entry"),\n    module: entryCleanText(src.module || (entryType === "client" ? "clients" : "leads")),'
);

// Make fallback/plain-text entries explicitly typed as leads.
replaceAllSafe(
  'record_type: "lead",\n      module: "leads",',
  'type: "lead",\n      record_type: "lead",\n      module: "leads",'
);

replaceAllSafe(
  'record_type: "crm_entry", module: "leads"',
  'type: "lead", record_type: "lead", module: "leads"'
);

// Update OpenAI prompt field list and lead defaults.
replaceAllSafe(
  'Complete CRM fields include name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type.',
  'Complete CRM fields include type,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type.'
);
replaceAllSafe(
  "use module:'leads', record_type:'lead', status:'New'",
  "use type:'lead', module:'leads', record_type:'lead', status:'New'"
);
replaceAllSafe(
  "For inferred potential leads use module:'leads', record_type:'lead', status:'New'",
  "For inferred potential leads use type:'lead', module:'leads', record_type:'lead', status:'New'"
);

// Make the leads filter respect the new type field.
replaceAllSafe(
  'if (t === "leads") list = list.filter((e) => !/task|note/i.test(String(e.record_type || e.module || "")));',
  'if (t === "leads") list = list.filter((e) => String(e.type || e.record_type || e.module || "").toLowerCase().includes("lead") || !/task|note|client/i.test(String(e.type || e.record_type || e.module || "")));'
);

if (changed) {
  fs.writeFileSync(file, source);
  console.log("CRM entries now include a first-class type field.");
} else {
  console.log("CRM type field patch already applied or anchors not found.");
}
