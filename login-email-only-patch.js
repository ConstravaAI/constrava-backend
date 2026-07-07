import fs from "fs";

const file = "./login.html";
let html = fs.readFileSync(file, "utf8");
let changed = false;

function replace(search, value) {
  if (html.includes(search)) {
    html = html.replace(search, value);
    changed = true;
  }
}

replace('        <div id="nameRow" class="hidden"><label>Name<input id="name" autocomplete="name" placeholder="Your name"></label></div>\n', '');
replace("    const nameRow = document.getElementById('nameRow');\n", "");
replace("      nameRow.classList.toggle('hidden', mode !== 'signup');\n", "");
replace("            name: document.getElementById('name').value,\n", "");
replace(
  "      <p class=\"small\">After signing in, you’ll be sent to <strong>https://constravaai.com/dashboard</strong>.</p>",
  "      <p class=\"small\">Account setup details like name/profile can be collected after the account is created.</p>\n      <p class=\"small\">After signing in, you’ll be sent to <strong>https://constravaai.com/dashboard</strong>.</p>"
);
replace(
  "      formSubtitle.textContent = mode === 'login' ? 'Open your Constrava dashboard.' : 'Create a private dashboard account.';",
  "      formSubtitle.textContent = mode === 'login' ? 'Open your Constrava dashboard.' : 'Create a private dashboard account with email and password.';"
);

if (changed) {
  fs.writeFileSync(file, html);
  console.log("Login form patched to email/password only.");
} else {
  console.log("Login form patch skipped: already patched or matching text not found.");
}
