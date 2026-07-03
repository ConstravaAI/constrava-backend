import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-llm-prompt-repair] server.js not found; skipped.");
  process.exit(0);
}

const recordPrompt = "You are the CRM record planning engine for Constrava. Return only JSON with a records array. Each record may be Lead, Person, Company, Deal, Task, Intake, or Note. Do not invent missing people, emails, phone numbers, budgets, or dates.";
const actionPrompt = "You are the CRM action planning engine for Constrava. Return only JSON with records. Each record action may be create, update, or none. Use update only when the target clearly matches an existing record.";

const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
let changed = false;

for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes('const systemPrompt = "You are the CRM record planning and formatting engine for Constrava.')) {
    lines[i] = `    const systemPrompt = ${JSON.stringify(recordPrompt)};`;
    changed = true;
  }
  if (lines[i].includes('const systemPrompt = "You are the CRM action planning engine for Constrava.')) {
    lines[i] = `    const systemPrompt = ${JSON.stringify(actionPrompt)};`;
    changed = true;
  }
}

if (changed) {
  fs.writeFileSync(file, lines.join("\n"));
  console.log("[crm-llm-prompt-repair] Repaired CRM LLM prompt syntax.");
} else {
  console.log("[crm-llm-prompt-repair] No CRM LLM prompt repair needed.");
}
