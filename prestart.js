import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

function replaceOnce(search, replacement) {
  if (text.includes(replacement)) return;
  if (!text.includes(search)) return;
  text = text.replace(search, replacement);
}

// Keep only the safe database compatibility fixes.
// The previous plan-preview patch introduced frontend JavaScript issues, so it has been removed.
replaceOnce(
  'const dateCol = firstExisting(c, ["created_at", "report_date", "date", "generated_at"]);',
  'const dateCol = firstExisting(c, ["report_date", "date", "created_at", "generated_at", "timestamp"]);'
);

replaceOnce(
  '  add(siteCol, String(siteId));\n  add(textCol, text);\n  add(dateCol, new Date());',
  '  const now = new Date();\n  const today = now.toISOString().slice(0, 10);\n\n  add(siteCol, String(siteId));\n  add(textCol, text);\n  if (c.includes("report_date")) add("report_date", today);\n  if (c.includes("date")) add("date", today);\n  if (c.includes("created_at")) add("created_at", now);\n  if (c.includes("generated_at")) add("generated_at", now);\n  if (c.includes("timestamp")) add("timestamp", now);\n  if (dateCol && !insertCols.includes(dateCol)) add(dateCol, now);'
);

fs.writeFileSync(target, text);
console.log("Prepared server.js for current Neon schema.");
