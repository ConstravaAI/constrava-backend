import fs from "fs";

const file = "crm-form-integrations.js";
if (!fs.existsSync(file)) {
  console.warn("[google-forms-direct-oauth-button-patch] crm-form-integrations.js not found.");
  await import("./crm-universal-ai-form-router-patch.js");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
if (source.includes("/debug/google-oauth?private=1") && source.includes("oauth_url")) {
  console.log("Google Forms direct OAuth button patch already applied.");
  await import("./crm-universal-ai-form-router-patch.js");
  process.exit(0);
}

const oldFn = "function signIn(){\n" +
"    if(!isPrivate){toast('Google account connection is blocked on the public demo.');return;}\n" +
"    const returnTo=window.location.pathname+window.location.search;\n" +
"    const url=`${baseUrl}/auth/google/forms/start?private=1&siteSlug=${encodeURIComponent(siteSlug())}&formSlug=${encodeURIComponent(formSlug())}&token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`;\n" +
"    window.location.href=url;\n" +
"  }";

const newFn = "async function signIn(){\n" +
"    if(!isPrivate){toast('Google account connection is blocked on the public demo.');return;}\n" +
"    const returnTo=window.location.pathname+window.location.search;\n" +
"    const fallback=`${baseUrl}/auth/google/forms/start?private=1&siteSlug=${encodeURIComponent(siteSlug())}&formSlug=${encodeURIComponent(formSlug())}&token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`;\n" +
"    try{\n" +
"      const r=await fetch(`/debug/google-oauth?private=1&siteSlug=${encodeURIComponent(siteSlug())}&formSlug=${encodeURIComponent(formSlug())}&token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`,{cache:'no-store'});\n" +
"      const j=await r.json();\n" +
"      if(j&&j.oauth_url){window.location.href=j.oauth_url;return;}\n" +
"    }catch(e){}\n" +
"    window.location.href=fallback;\n" +
"  }";

if (!source.includes(oldFn)) {
  console.warn("[google-forms-direct-oauth-button-patch] Could not find signIn function; leaving file unchanged.");
  await import("./crm-universal-ai-form-router-patch.js");
  process.exit(0);
}

source = source.replace(oldFn, newFn);
fs.writeFileSync(file, source);
console.log("Google Forms button now uses the working OAuth URL generator.");
await import("./crm-universal-ai-form-router-patch.js");
