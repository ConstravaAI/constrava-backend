import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) process.exit(0);
let text = fs.readFileSync(file, "utf8");
const key = "DEV_ACCOUNT_" + "PASSWORD";
const start = text.indexOf("async function developerCredentials() {");
const end = start >= 0 ? text.indexOf("function rememberMemoryAccount", start) : -1;
if (start >= 0 && end > start && text.slice(start, end).includes("BUILTIN_DEV_HASH")) {
  const safer = `async function developerCredentials() {
  const email = normEmail(DEFAULT_DEV_EMAIL);
  if (!email || !process.env["${key}"]) {
    console.warn("[account-auth] set the developer account secret in the environment before signing in.");
    return null;
  }
  const hashed = await passwordHash(process.env["${key}"]);
  return { email, display_name: DEFAULT_DEV_NAME, role: "developer", salt: hashed.salt, password_hash: hashed.hash };
}
`;
  text = text.slice(0, start) + safer + text.slice(end);
  fs.writeFileSync(file, text);
  console.log("[account-auth-env-secret-fix] Developer sign-in now uses only the environment secret.");
} else {
  console.log("[account-auth-env-secret-fix] No developer credential fallback found.");
}
