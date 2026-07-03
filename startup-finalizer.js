const promptRepair = "./" + "crm-llm-prompt-repair.js";
const accountPatch = "./" + "account-auth-isolation-patch.js";
const envSecretFix = "./" + "account-auth-env-secret-fix.js";
const guardFix = "./" + "account-auth-route-guard-fix.js";
await import(promptRepair);
await import(accountPatch);
await import(envSecretFix);
await import(guardFix);
