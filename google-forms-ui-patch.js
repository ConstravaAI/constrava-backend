import fs from "fs";

const file = "crm-form-integrations.js";
if (!fs.existsSync(file)) {
  console.warn("[google-forms-ui-patch] crm-form-integrations.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
if (source.includes("/api/google/forms/select")) {
  console.log("Google Forms UI select patch already applied.");
  process.exit(0);
}

const find = `document.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>{$('gfFormId').value=b.dataset.id;$('gfForm').value=b.dataset.name;showScript();toast('Selected '+b.dataset.name);});`;
const replace = `document.querySelectorAll('[data-id]').forEach(b=>b.onclick=async()=>{$('gfFormId').value=b.dataset.id;$('gfForm').value=b.dataset.name;showScript();try{const r=await fetch('/api/google/forms/select?private=1',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({connectionId:conn(),formId:b.dataset.id,formName:b.dataset.name})});const j=await r.json();if(!j.ok)throw new Error(j.error||'Could not save selected form.');toast('Selected and saved '+b.dataset.name);}catch(e){toast('Selected '+b.dataset.name+', but save failed: '+e.message);}});`;

if (!source.includes(find)) {
  console.warn("[google-forms-ui-patch] Could not find Google Forms selection handler; leaving UI file unchanged.");
  process.exit(0);
}

source = source.replace(find, replace);
fs.writeFileSync(file, source);
console.log("Google Forms UI select patch applied.");
