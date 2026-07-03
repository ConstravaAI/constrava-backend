import fs from "fs";

const files = ["index.html", "services.html", "process.html", "work.html", "contact.html"];
const signinLink = '        <a href="/signin">Sign in</a>';
let changed = 0;

for (const file of files) {
  if (!fs.existsSync(file)) continue;
  let html = fs.readFileSync(file, "utf8");
  if (html.includes('href="/signin"')) {
    console.log(`[public-signin-link-patch] ${file} already has sign in link.`);
    continue;
  }
  const target = '        <a href="/contact">Contact</a>\n      </nav>';
  const activeTarget = '        <a class="active" href="/contact">Contact</a>\n      </nav>';
  if (html.includes(target)) {
    html = html.replace(target, '        <a href="/contact">Contact</a>\n' + signinLink + '\n      </nav>');
  } else if (html.includes(activeTarget)) {
    html = html.replace(activeTarget, '        <a class="active" href="/contact">Contact</a>\n' + signinLink + '\n      </nav>');
  } else {
    console.warn(`[public-signin-link-patch] Could not find nav target in ${file}.`);
    continue;
  }
  fs.writeFileSync(file, html);
  changed++;
  console.log(`[public-signin-link-patch] Added sign in link to ${file}.`);
}

console.log(`[public-signin-link-patch] Complete. Updated ${changed} file(s).`);
