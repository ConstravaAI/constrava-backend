import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "crm-actions-scoped-v1";

let source = await fs.readFile(runtimeWrapperPath, "utf8");

if (!source.includes(marker)) {
  const sharedHeaderInjection = `.replaceAll('<input id="search" placeholder="Search records, tasks, leads..."> <button class="primary" id="aiAdd">AI Add</button>', '<input id="search" placeholder="Search records, tasks, leads..."> <button class="secondary" id="priorityCheck">AI Priority Check</button> <button class="primary" id="aiAdd">Edit Records</button>')`;
  const scopedHeaderInjection = `.replaceAll('<input id="search" placeholder="Search records, tasks, leads..."> <button class="primary" id="aiAdd">AI Add</button>', '<input id="search" placeholder="Search records, tasks, leads...">')`;

  if (source.includes(sharedHeaderInjection)) {
    source = source.replace(sharedHeaderInjection, scopedHeaderInjection);
  }

  const crmShellNeedle = `function crmShell(content){const items=[['overview','Overview'],['all','All Records'],['Person','Contacts'],['Company','Companies'],['Deal','Deals'],['Task','Tasks'],['Intake','Intakes'],['Note','Notes'],['edit','Edit Records']];return '<div class="crmShell"><aside class="crmSide"><div class="crmSideTitle">CRM sections</div>'+items.map(function(item){const id=item[0],label=item[1];return '<button class="crmTab '+(S.crmView===id?'active':'')+'" data-crm="'+id+'"><span>'+label+'</span><span>'+crmCount(id)+'</span></button>'}).join('')+'</aside><div>'+content+'</div></div>'}`;
  const scopedCrmShell = `function crmActions(){return '<div class="crmToolbar" style="justify-content:flex-end;margin-bottom:12px"><button class="secondary" id="priorityCheck">AI Priority Check</button><button class="primary" id="aiAdd">Edit Records</button></div>'}
function crmShell(content){const items=[['overview','Overview'],['all','All Records'],['Person','Contacts'],['Company','Companies'],['Deal','Deals'],['Task','Tasks'],['Intake','Intakes'],['Note','Notes'],['edit','Edit Records']];return '<div class="crmShell"><aside class="crmSide"><div class="crmSideTitle">CRM sections</div>'+items.map(function(item){const id=item[0],label=item[1];return '<button class="crmTab '+(S.crmView===id?'active':'')+'" data-crm="'+id+'"><span>'+label+'</span><span>'+crmCount(id)+'</span></button>'}).join('')+'</aside><div>'+crmActions()+content+'</div></div>'}`;

  if (!source.includes(crmShellNeedle) && !source.includes("function crmActions(){return '<div class=\"crmToolbar\"")) {
    throw new Error("Could not find CRM shell injection target in src/server-runtime.js");
  }
  source = source.replace(crmShellNeedle, scopedCrmShell);

  const editBindNeedle = `document.querySelectorAll('[data-edit-record]').forEach(function(b){b.onclick=function(){openRecordEditor(b.dataset.editRecord)}});`;
  const editBindReplacement = `${editBindNeedle}let aiAdd=document.getElementById('aiAdd');if(aiAdd)aiAdd.onclick=function(){S.tab='crm';S.crmView='edit';render()};`;

  if (source.includes(editBindNeedle) && !source.includes("let aiAdd=document.getElementById('aiAdd')")) {
    source = source.replace(editBindNeedle, editBindReplacement);
  }

  await fs.writeFile(runtimeWrapperPath, `${source}\n// ${marker}\n`);
}

await import("./server-account-persistence.js");
