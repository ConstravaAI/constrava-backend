import fs from "fs";

const file = "crm-distinct-tabs.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-workflow-tools-cards-patch] crm-distinct-tabs.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const marker = "window.__constravaWorkflowToolsCards";

if (!source.includes(marker)) {
  source += `

(function(){
  if (window.__constravaWorkflowToolsCards) return;
  window.__constravaWorkflowToolsCards = true;

  function workflowVisible(){
    var root = document.getElementById('cxSimpleCrmRoot');
    return !!(root && /CRM Workflow Center/.test(root.textContent || ''));
  }

  function setWorkflowText(text){
    var input = document.getElementById('cxWorkflowAiInput');
    if (!input) return;
    input.value = text;
    input.focus();
  }

  function readCsvFile(file){
    var reader = new FileReader();
    reader.onload = function(){
      var text = String(reader.result || '').slice(0, 12000);
      setWorkflowText('Import this CSV into the CRM. Create or update records using the correct types and entity IDs.\\n\\n' + text);
    };
    reader.readAsText(file);
  }

  function chooseCsv(){
    var picker = document.createElement('input');
    picker.type = 'file';
    picker.accept = '.csv,text/csv';
    picker.onchange = function(){
      var file = picker.files && picker.files[0];
      if (file) readCsvFile(file);
    };
    picker.click();
  }

  function addTools(){
    if (!workflowVisible()) return;
    var root = document.getElementById('cxSimpleCrmRoot');
    if (!root || document.getElementById('cxWorkflowToolsCard')) return;

    var card = document.createElement('div');
    card.id = 'cxWorkflowToolsCard';
    card.className = 'cx-simple-card';
    card.innerHTML = '<div class="cx-simple-toolbar"><div><h3>CRM Tools</h3><p>Use these shortcuts to bring common CRM workflows into the AI workflow box.</p></div><span class="cx-simple-pill">Workflow tools</span></div><div class="cx-workflow-tool-grid"><button type="button" data-tool="csv"><b>📥 Import CSV</b><span>Pick a CSV and prepare it for CRM import.</span></button><button type="button" data-tool="form"><b>🌐 Connect Website Form</b><span>Create form capture instructions or embed workflow.</span></button><button type="button" data-tool="email"><b>✉️ Sync Email</b><span>Paste email details and log CRM activity.</span></button><button type="button" data-tool="call"><b>☎️ Log Call</b><span>Record call outcome, notes, and follow-up.</span></button><button type="button" data-tool="task"><b>✅ Create Task</b><span>Create follow-up tasks tied to CRM records.</span></button><button type="button" data-tool="api"><b>🔌 Connect API</b><span>Draft webhook/API payload instructions.</span></button><button type="button" data-tool="auto"><b>⚙️ Run Automation</b><span>Score, classify, and advance CRM records.</span></button></div>';

    var firstGrid = root.querySelector('.cx-workflow-grid');
    if (firstGrid && firstGrid.nextSibling) root.insertBefore(card, firstGrid.nextSibling);
    else root.appendChild(card);

    var style = document.getElementById('cxWorkflowToolsStyle');
    if (!style) {
      style = document.createElement('style');
      style.id = 'cxWorkflowToolsStyle';
      style.textContent = '.cx-workflow-tool-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:14px}.cx-workflow-tool-grid button{border:1px solid #dbe8e4;border-radius:14px;background:#fff;text-align:left;padding:13px;cursor:pointer;box-shadow:0 8px 18px rgba(15,23,42,.04)}.cx-workflow-tool-grid button:hover{border-color:#10b981;background:#f0fdf4}.cx-workflow-tool-grid b{display:block;color:#022c22;font-size:14px}.cx-workflow-tool-grid span{display:block;color:#64748b;font-size:12px;line-height:1.4;margin-top:5px}@media(max-width:850px){.cx-workflow-tool-grid{grid-template-columns:1fr}}';
      document.head.appendChild(style);
    }

    card.addEventListener('click', function(event){
      var btn = event.target.closest('button[data-tool]');
      if (!btn) return;
      var tool = btn.getAttribute('data-tool');
      if (tool === 'csv') return chooseCsv();
      if (tool === 'form') return setWorkflowText('Connect a website form to the CRM. Generate the fields, capture flow, and record types needed for new submissions.');
      if (tool === 'email') return setWorkflowText('Log this email as CRM activity. Extract sender, company, request, next step, and update the matching record:\\n\\n');
      if (tool === 'call') return setWorkflowText('Log this call in the CRM. Include who called, outcome, notes, next step, and any deal/task updates:\\n\\n');
      if (tool === 'task') return setWorkflowText('Create a CRM task. Include owner, related person/company/deal, due date, priority, and task notes:\\n\\n');
      if (tool === 'api') return setWorkflowText('Create or test a CRM API/webhook workflow. Define the payload fields, record types, and expected CRM update behavior:\\n\\n');
      if (tool === 'auto') return setWorkflowText('Run CRM automation: classify records, assign types, identify missing fields, create follow-up tasks, and suggest stage changes.');
    });
  }

  setInterval(addTools, 500);
  window.addEventListener('load', addTools);
  window.addEventListener('cx-crm-ai-updated', addTools);
})();
`;
  fs.writeFileSync(file, source);
  console.log("CRM workflow tools restored inside Workflow Center tab.");
} else {
  console.log("CRM workflow tools are already installed in Workflow Center tab.");
}
