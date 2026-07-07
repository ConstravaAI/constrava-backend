import fs from "fs";

const serverFile = "server.js";
if (fs.existsSync(serverFile)) {
  let source = fs.readFileSync(serverFile, "utf8");
  let changed = false;
  function replaceAllSafe(search, replacement) {
    if (!source.includes(search)) return false;
    source = source.split(search).join(replacement);
    return true;
  }

  if (replaceAllSafe('app.use(express.static(__dirname));', 'app.use(express.static(__dirname, { redirect: false }));')) changed = true;

  const oldDashboardUrl = 'dashboard_url: `/dashboard?token=${encodeURIComponent(dashboardToken)}`';
  const newDashboardUrl = 'dashboard_url: `${CANONICAL_ORIGIN}/dashboard`';
  if (replaceAllSafe(oldDashboardUrl, newDashboardUrl)) changed = true;

  const olderDashboardUrl = 'dashboard_url: `${CANONICAL_ORIGIN}/dashboard/?token=${encodeURIComponent(dashboardToken)}&mode=private`';
  if (replaceAllSafe(olderDashboardUrl, newDashboardUrl)) changed = true;

  if (changed) fs.writeFileSync(serverFile, source);
}

const dashboardFile = "dashboard.html";
if (fs.existsSync(dashboardFile)) {
  let html = fs.readFileSync(dashboardFile, "utf8");
  const search = "loadCrmData();\n  </script>";
  const replacement = "loadCrmData();\n    switchMain('crm');\n  </script>";
  if (!html.includes(replacement) && html.includes(search)) {
    html = html.replace(search, replacement);
    fs.writeFileSync(dashboardFile, html);
  }
}
