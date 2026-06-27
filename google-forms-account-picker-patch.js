import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[google-forms-account-picker-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const oldPrompt = 'url.searchParams.set("prompt", "consent");';
const newPrompt = 'url.searchParams.set("prompt", "select_account consent");';
if (source.includes(oldPrompt)) {
  source = source.replace(oldPrompt, newPrompt);
  changed = true;
}

const accessType = 'url.searchParams.set("access_type", "offline");';
const includeGranted = 'url.searchParams.set("include_granted_scopes", "true");';
if (source.includes(accessType) && !source.includes(includeGranted)) {
  source = source.replace(accessType, `${accessType}\n  ${includeGranted}`);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Google Forms OAuth now forces account picker.");
} else {
  console.log("Google Forms account picker patch already applied or OAuth start route not found.");
}
