import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[dashboard-private-url-canonical-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

function replaceAllSafe(search, replacement) {
  if (!source.includes(search)) return false;
  source = source.split(search).join(replacement);
  return true;
}

const oldDashboardUrl = 'dashboard_url: `/dashboard?token=${encodeURIComponent(dashboardToken)}`';
const newDashboardUrl = 'dashboard_url: `${CANONICAL_ORIGIN}/dashboard/?token=${encodeURIComponent(dashboardToken)}&mode=private`';
if (replaceAllSafe(oldDashboardUrl, newDashboardUrl)) changed = true;

const oldRootLink = "<h1>Constrava</h1><p><a href='/dashboard?token=demo'>Open dashboard demo</a></p>";
const newRootLink = "<h1>Constrava</h1><p><a href='/dashboard/?token=demo&mode=private'>Open dashboard demo</a></p>";
if (replaceAllSafe(oldRootLink, newRootLink)) changed = true;

// Keep the real route as /dashboard. Express handles /dashboard/ too unless strict routing is enabled.
// This patch only changes generated URLs so old Render-style dashboard links stop being produced.

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[dashboard-private-url-canonical-patch] Generated dashboard URLs now point to /dashboard/?token=...&mode=private on the canonical origin.");
} else {
  console.log("[dashboard-private-url-canonical-patch] Dashboard URLs already canonical or target strings not found.");
}
