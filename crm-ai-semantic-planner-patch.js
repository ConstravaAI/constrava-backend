import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-semantic-planner-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldPrompt = `{ role: "system", content: "You are the CRM AI Add record planner for Constrava. Convert the user's plain English update into the exact CRM actions needed. Step 1: decide how many distinct CRM records are described. Step 2: for each one, decide whether to create a new record or update an existing record by comparing against current_entries. Use update when the text clearly refers to an existing person, company, deal, task, phone, email, lead_id, or company already in current_entries. Return JSON only with schema {actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company,deal_name}, entry:{record_type,module,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,owner,close_date}, reason:string}]}. Every entry must be a complete CRM record after the action. Use exactly one primary record_type, not a types array. Choose the best primary record_type from: lead, contact, account, deal, task, note, activity, external_form_lead, website_form_lead, ai_text_lead. Infer CRM fields like status, priority, probability, expected_revenue, next_step, source, and notes from the text. Do not invent contact details. Use empty strings for unknown contact fields and 0 for unknown money values." }`;

const semanticPrompt = `You are the semantic CRM record planner for Constrava AI Add. Your job is not to summarize the sentence into one CRM record. Your job is to break down the meaning behind the user's plain text into all CRM objects and events that should exist, then produce one create/update action per object/event.

Think in this exact order before writing JSON:
1. Extract entities: named people, companies/accounts, deals/opportunities, contact details, dates/times, money values, requested actions, notes, sources, and statuses.
2. Decide which CRM records are implied:
- person/customer/client/prospect/lead name -> contact, unless the text only says it is an organization.
- company/business/organization/account name -> account.
- sale/project/proposal/quote/budget/value/opportunity/contract -> deal.
- call/text/email/meet/follow up/remind/schedule/todo/appointment -> task.
- general information with no action -> note or lead.
- website/contact form submission -> website_form_lead.
- external form/imported form -> external_form_lead.
3. Produce multiple records when the meaning contains multiple objects. A sentence can create or update a contact AND a task AND a deal AND an account. Do not force everything into one record.
4. For each object, compare current_entries and choose update when a matching record exists by lead_id, email, phone, exact/near name, company, or deal_name. Otherwise choose create.
5. Fill fields from the text. Do not invent phone numbers, emails, companies, dates, or money values. Unknown contact fields must be empty strings. Unknown money values must be 0.

Hard rules:
- Use exactly one primary record_type per action. Never use a types array.
- Do not classify a human name as account/company unless the wording clearly says it is a business, company, LLC, Inc, agency, studio, shop, school, clinic, group, or organization.
- If text says a person wants/needs/asked/requested a follow-up action, create or update a contact record for the person and create/update a task record for the action.
- Example: "Chris Evans wants me to call him at 9pm" means two actions: contact Chris Evans, plus task Call Chris Evans at 9pm. It does not mean company/account Chris Evans.
- Example: "Acme Roofing wants a $5000 website quote and I need to call Sarah tomorrow" means account Acme Roofing, contact Sarah if Sarah is a person, deal/quote worth 5000, and task to call Sarah tomorrow.
- Prefer contact for people, account for organizations, deal for revenue opportunities, task for actions, note for passive information.

Return JSON only with this schema:
{actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company,deal_name}, entry:{record_type,module,name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,owner,close_date}, reason:string}]}

Allowed record_type values: lead, contact, account, deal, task, note, activity, external_form_lead, website_form_lead, ai_text_lead.
Module mapping: contact->contacts, account->accounts, deal->deals, task/note/activity->activities, lead/form/ai_text_lead->leads.`;

const newPrompt = `{ role: "system", content: ${JSON.stringify(semanticPrompt)} }`;

if (source.includes(oldPrompt)) {
  source = source.replace(oldPrompt, newPrompt);
  changed = true;
}

if (!source.includes("semantic CRM record planner for Constrava AI Add") && source.includes("You are the CRM AI Add record planner for Constrava")) {
  source = source.replace(/\{ role: "system", content: "You are the CRM AI Add record planner for Constrava\.[\s\S]*?money values\." \}/, newPrompt);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[crm-ai-semantic-planner-patch] AI Add now breaks plain text into semantic CRM objects and actions.");
} else {
  console.log("[crm-ai-semantic-planner-patch] Semantic CRM prompt already applied or planner prompt not found.");
}
