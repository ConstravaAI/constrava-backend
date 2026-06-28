import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-entry-normalizer-hotfix-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const fragileCreateBlock = `      } else {
        const normalized = await normalizeFormLeadSmart({ ...patch, plain_text: text, notes: patch.notes || patch.message || text, provider: "AI CRM Entry", source: patch.source || "AI CRM Entry", dashboard_token: token }, siteId, "ai-entry", req);
        finalEntry = completeCrmEntry({ ...normalized, ...patch, source: patch.source || normalized.source || "AI CRM Entry" }, siteId, text);
      }`;

const safeCreateBlock = `      } else {
        const baseEntry = {
          ...patch,
          plain_text: text,
          notes: patch.notes || patch.message || text,
          provider: "AI CRM Entry",
          source: patch.source || "AI CRM Entry",
          dashboard_token: token
        };
        finalEntry = completeCrmEntry(baseEntry, siteId, text);
      }`;

if (source.includes(fragileCreateBlock)) {
  source = source.replace(fragileCreateBlock, safeCreateBlock);
  changed = true;
}

// Safety net for any slightly different generated copy.
source = source.replace(
  /const normalized = await normalizeFormLeadSmart\(\{ \.\.\.patch, plain_text: text, notes: patch\.notes \|\| patch\.message \|\| text, provider: "AI CRM Entry", source: patch\.source \|\| "AI CRM Entry", dashboard_token: token \}, siteId, "ai-entry", req\);\s*finalEntry = completeCrmEntry\(\{ \.\.\.normalized, \.\.\.patch, source: patch\.source \|\| normalized\.source \|\| "AI CRM Entry" \}, siteId, text\);/g,
  `const baseEntry = { ...patch, plain_text: text, notes: patch.notes || patch.message || text, provider: "AI CRM Entry", source: patch.source || "AI CRM Entry", dashboard_token: token };
        finalEntry = completeCrmEntry(baseEntry, siteId, text);`
);

if (source !== fs.readFileSync(file, "utf8")) changed = true;

if (changed) {
  fs.writeFileSync(file, source);
  console.log("AI CRM entry route no longer depends on normalizeFormLeadSmart.");
} else {
  console.log("AI CRM entry normalizer dependency already removed or anchor not found.");
}
