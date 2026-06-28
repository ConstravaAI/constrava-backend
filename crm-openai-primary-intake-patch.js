import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-openai-primary-intake-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const primaryPlan = `if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ ok: false, error: "OpenAI API key is required for CRM AI sorting." });
    }
    const plan = await llmPlanCrmEntry(text, current);
    if (!plan || !Array.isArray(plan.actions) || plan.actions.length === 0) {
      return res.status(502).json({ ok: false, error: "OpenAI could not interpret this CRM update." });
    }`;

const beforePlan = source;
source = source.replace(
  /const plan = await llmPlanCrmEntry\(text, current\) \|\| fallbackPlanCrmEntry\(text\);/g,
  primaryPlan
);
if (source !== beforePlan) changed = true;

const prompt = "You are the primary AI interpreter for a CRM. Treat the user's input like a messy real sales/admin note, not a structured form. People often omit labels such as lead, deal, status, company, or next step. If a note says someone called, emailed, texted, asked, wants, needs, requested, submitted a form, reached out, or left contact information, infer a potential lead unless the note clearly says otherwise. Output JSON only: {actions:[{action:'create'|'update', match:{lead_id,email,phone,name,company}, entry:{complete CRM fields}, reason:string}]}. Complete CRM fields include name,email,phone,mobile,company,title,industry,source,status,priority,deal_name,value,probability,expected_revenue,next_step,notes,tags,module,record_type. For inferred potential leads, use module:'leads', record_type:'lead', status:'New', source:'AI Plain Text Note', priority:'Medium', probability:10, value:0 when no value is stated, next_step:'Follow up with this potential lead.', and a useful deal_name based on the company or name. Extract names, companies, phones, emails, service needs, budgets, and follow-up instructions when present. Use existing entries to update the right record. Do not invent contact details not present or implied.";
const promptLiteral = JSON.stringify(prompt);

const beforePrompt = source;
source = source.replace(
  /content:\s*"You are (?:the AI operator|the primary AI interpreter)[^\n"]*Do not invent contact details not present or implied\."/g,
  "content: " + promptLiteral
);
if (source !== beforePrompt) changed = true;

if (changed) {
  fs.writeFileSync(file, source);
  console.log("OpenAI is now the primary CRM intake interpreter.");
} else {
  console.log("OpenAI primary CRM intake patch already applied or anchor not found.");
}
