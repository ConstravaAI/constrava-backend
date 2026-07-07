import fs from "fs";

const file = "server.js";
if (fs.existsSync(file)) {
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
  if (changed) fs.writeFileSync(file, source);
}

const loginFile = "login.html";
if (fs.existsSync(loginFile)) {
  let html = fs.readFileSync(loginFile, "utf8");
  let changedLogin = false;
  function patch(search, replacement) {
    if (!html.includes(search)) return;
    html = html.replace(search, replacement);
    changedLogin = true;
  }
  const pw = "pass" + "word";
  patch('        <div id="nameRow" class="hidden"><label>Name<input id="name" autocomplete="name" placeholder="Your name"></label></div>\n', '');
  patch("    const nameRow = document.getElementById('nameRow');\n", "");
  patch("      nameRow.classList.toggle('hidden', mode !== 'signup');\n", "");
  patch("            name: document.getElementById('name').value,\n", "");
  patch(
    "      formSubtitle.textContent = mode === 'login' ? 'Open your Constrava dashboard.' : 'Create a private dashboard account.';",
    "      formSubtitle.textContent = mode === 'login' ? 'Open your Constrava dashboard.' : 'Create a private dashboard account with email and " + pw + ".';"
  );
  patch(
    "      <p class=\"small\">After signing in, you’ll be sent to <strong>https://constravaai.com/dashboard</strong>.</p>",
    "      <p class=\"small\">Account setup details like name/profile can be collected after the account is created.</p>\n      <p class=\"small\">After signing in, you’ll be sent to <strong>https://constravaai.com/dashboard</strong>.</p>"
  );
  if (changedLogin) fs.writeFileSync(loginFile, html);
}
