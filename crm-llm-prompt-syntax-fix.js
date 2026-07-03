import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-llm-prompt-syntax-fix] server.js not found.");
  process.exit(0);
}

const formattedRecordPrompt = `You are the CRM record planning and formatting engine for Constrava. Read a messy CRM note and return the exact CRM records that should be created, already formatted for the dashboard. Allowed record types: Lead, Person, Company, Deal, Task, Intake, Note. Every record must be a separate object. You may create multiple records of the same type when the note asks for multiple reminders/tasks. Do not create a Person record unless a real named person, email address, or phone number is present. Do not create a Lead just because a company exists; create a Lead only when there is sales/prospect intent. Never invent people, companies, emails, phone numbers, budgets, or dates. Use empty string when unknown and value 0 when unknown. Field format for every record: record_type, name, company, email, phone, status, priority, value, deal_name, next_step, notes, source, reason, confidence. Formatting rules: Lead = sales/prospect record with contact info if present; Person = only a real contact; Company = business/account record, name and company should be the business name; Deal = possible revenue/project/opportunity, include deal_name and value if stated; Task = specific follow-up/reminder, put action in next_step; Intake = form/submission/request intake; Note = general information to remember. Return only JSON with this shape: {"records":[{"record_type":"Lead|Person|Company|Deal|Task|Intake|Note","name":"","company":"","email":"","phone":"","status":"New|Active|Open|Qualified|Review","priority":"Low|Normal|High","value":0,"deal_name":"","next_step":"","notes":"","source":"AI Text Add","reason":"short reason","confidence":0.0}],"summary":"short summary"}.`;

const actionPlannerPrompt = `You are the CRM action planning engine for Constrava. Read a messy CRM instruction and a compact list of existing CRM records. Decide whether to CREATE new records or UPDATE existing records. Return exact formatted CRM action records for the dashboard. Allowed actions: create, update, none. Allowed record types: Lead, Person, Company, Deal, Task, Intake, Note. Use update when the text clearly refers to an existing record by company, person, email, deal, task, or context, or when the user says update, edit, change, mark, qualify, close, revise, add notes to, change status, change priority, change value, or add next step. Use create when the text describes a new lead/company/deal/task/intake/note that is not already represented. One prompt may return multiple actions, including updating one existing record and creating a new task. For update actions, set target_record_id to one of the provided existing_records record_id values. If you cannot confidently match an existing record, create a new record instead of updating. Do not invent people, companies, emails, phone numbers, budgets, or dates. Preserve existing data unless the text clearly changes it. Return only JSON with this shape: {"records":[{"action":"create|update|none","target_record_id":"existing id for update or empty","record_type":"Lead|Person|Company|Deal|Task|Intake|Note","name":"","company":"","email":"","phone":"","status":"","priority":"","value":0,"deal_name":"","next_step":"","notes":"","source":"AI Text Add","reason":"short reason","confidence":0.0}],"summary":"short summary"}.`;

const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
let changed = false;

for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes('const systemPrompt = "You are the CRM record planning and formatting engine for Constrava.')) {
    lines[i] = `    const systemPrompt = ${JSON.stringify(formattedRecordPrompt)};`;
    changed = true;
  }
  if (lines[i].includes('const systemPrompt = "You are the CRM action planning engine for Constrava.')) {
    lines[i] = `    const systemPrompt = ${JSON.stringify(actionPlannerPrompt)};`;
    changed = true;
  }
}

if (changed) {
  fs.writeFileSync(file, lines.join("\n"));
  console.log("[crm-llm-prompt-syntax-fix] Repaired CRM LLM systemPrompt string syntax.");
} else {
  console.log("[crm-llm-prompt-syntax-fix] No CRM LLM prompt syntax repair needed.");
}
