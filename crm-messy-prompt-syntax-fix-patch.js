import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-messy-prompt-syntax-fix-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
const before = source;

const safePromptLine = `  const prompt = [
    "You are a CRM intake interpreter. The user will type messy normal notes, not a form.",
    "They may omit labels, punctuation, exact field names, names, companies, statuses, or next steps.",
    "Always turn the note into CRM actions that can be saved. Return JSON only.",
    "Return an object with an actions array. Each action must include action, match, entry, and reason.",
    "Required entry fields: type, types, name, email, phone, mobile, company, title, industry, source, status, priority, deal_name, value, probability, expected_revenue, next_step, notes, tags, module, record_type.",
    "type is the primary category. types is an array of all matching CRM tabs using singular canonical values: lead, person, company, deal, task, intake, note, client, purchase, entry.",
    "If someone called, texted, emailed, messaged, submitted a form, asked, wants, needs, is interested, or has contact info, infer lead.",
    "If a person name/email/phone appears, include person. If a business/company appears, include company.",
    "If there is a project, budget, quote, proposal, website, landing page, chatbot, booking, form, or service need, include deal.",
    "If there is follow-up, call back, email, tomorrow, weekday, appointment, or next step, include task.",
    "If it came from a form/submission, include intake.",
    "For vague business notes, still create one useful record with notes equal to the original text.",
    "Do not require a specific format. Do not invent email or phone if missing. Prefer update only when the text clearly refers to an existing record."
  ].join(" ");`;

source = source.replace(
  /  const prompt = "You are a CRM intake interpreter[\s\S]*?Prefer update only when the text clearly refers to an existing record\.";/,
  safePromptLine
);

if (source !== before) {
  fs.writeFileSync(file, source);
  console.log("Messy CRM prompt string syntax repaired.");
} else {
  console.log("Messy CRM prompt string syntax already safe or anchor not found.");
}

await import("./crm-messy-regex-syntax-fix-patch.js");
