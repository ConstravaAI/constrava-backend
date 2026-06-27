import fs from "fs";

const file = "crm-form-integrations.js";
if (!fs.existsSync(file)) {
  console.warn("[google-forms-remove-old-signin-patch] crm-form-integrations.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;
function replaceAll(find, replace) {
  if (source.includes(find)) {
    source = source.split(find).join(replace);
    changed = true;
  }
}

replaceAll("<h3>1. Sign in with Google</h3>", "<h3>1. Connect Google Account</h3>");
replaceAll(">Sign in with Google</button>", ">Connect Google Account</button>");
replaceAll("Not connected yet. Click Sign in with Google to begin.", "Not connected yet. Connect a Google account to load available forms.");
replaceAll("Sign in first, then load forms.", "Connect your Google account, then load forms.");
replaceAll("Sign in with Google first.", "Connect your Google account first.");
replaceAll("Sign in again.", "Reconnect Google.");
replaceAll("Google sign-in is blocked on the public demo.", "Google account connection is blocked on the public demo.");

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Old Google sign-in wording removed from connector UI.");
} else {
  console.log("Old Google sign-in wording was already removed or not found.");
}
