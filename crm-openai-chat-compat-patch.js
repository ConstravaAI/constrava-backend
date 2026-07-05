import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-openai-chat-compat-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

if (source.includes("temperature: 0,")) {
  source = source.replaceAll("temperature: 0,\n", "");
  source = source.replaceAll("        temperature: 0,\n", "");
  source = source.replaceAll("      temperature: 0,\n", "");
  changed = true;
}

if (source.includes("max_tokens: 40,")) {
  source = source.replaceAll("max_tokens: 40,", "max_completion_tokens: 40,");
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[crm-openai-chat-compat-patch] Removed unsupported chat parameters for newer OpenAI models.");
} else {
  console.log("[crm-openai-chat-compat-patch] No OpenAI chat compatibility changes needed.");
}
