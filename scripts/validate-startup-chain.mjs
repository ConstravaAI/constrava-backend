import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(root, "src");
const failures = [];

async function readProjectFile(relativePath) {
  try {
    return await fs.readFile(path.join(root, relativePath), "utf8");
  } catch (error) {
    failures.push(`Missing required file: ${relativePath}`);
    return "";
  }
}

function fail(message) {
  failures.push(message);
}

async function assertContains(relativePath, needle, label) {
  const source = await readProjectFile(relativePath);
  if (source && !source.includes(needle)) {
    fail(`${relativePath} is missing ${label || JSON.stringify(needle)}`);
  }
  return source;
}

function checkSyntax(relativePath) {
  const result = spawnSync(process.execPath, ["--check", path.join(root, relativePath)], {
    encoding: "utf8"
  });
  if (result.status !== 0) {
    fail(`${relativePath} failed syntax check:\n${result.stderr || result.stdout}`.trim());
  }
}

function localImportTargets(relativePath, source) {
  const dir = path.dirname(path.join(root, relativePath));
  const targets = [];
  const patterns = [
    /\bimport\s+(?:[^'"]+\s+from\s+)?["'](\.\/[^"']+)["']/g,
    /\bawait\s+import\(["'](\.\/[^"']+)["']\)/g
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const target = match[1].endsWith(".js") ? match[1] : `${match[1]}.js`;
      targets.push(path.relative(root, path.resolve(dir, target)).replaceAll("\\", "/"));
    }
  }
  return targets;
}

async function validateLocalImports(relativePath, seen = new Set()) {
  if (seen.has(relativePath)) return;
  seen.add(relativePath);
  const source = await readProjectFile(relativePath);
  if (!source) return;
  for (const target of localImportTargets(relativePath, source)) {
    if (path.basename(target).startsWith(".")) continue;
    try {
      await fs.access(path.join(root, target));
    } catch {
      fail(`${relativePath} imports missing file ${target}`);
      continue;
    }
    await validateLocalImports(target, seen);
  }
}

async function validateEncodedScopeWrapper() {
  const source = await readProjectFile("src/server-crm-actions-scope.js");
  if (!source) return;
  const encoded = source.match(/const encoded = "([\s\S]*?)";/)?.[1];
  if (!encoded) {
    fail("src/server-crm-actions-scope.js is missing its encoded generated wrapper.");
    return;
  }
  let decoded = "";
  try {
    decoded = Buffer.from(encoded, "base64").toString("utf8");
  } catch (error) {
    fail(`src/server-crm-actions-scope.js has an invalid encoded wrapper: ${error.message}`);
    return;
  }
  if (!decoded.includes('await import("./server-account-persistence.js");')) {
    fail("Encoded CRM scope wrapper no longer hands off to server-account-persistence.js.");
  }
  if (!decoded.includes("live-analytics-display-v2")) {
    fail("Encoded CRM scope wrapper is missing the live analytics display marker.");
  }
}

const packageJson = JSON.parse(await readProjectFile("package.json") || "{}");
if (packageJson.scripts?.start !== "node src/server-tracker-analytics.js") {
  fail("package.json start script must stay pointed at src/server-tracker-analytics.js.");
}

for (const fileName of (await fs.readdir(srcDir)).filter((name) => name.endsWith(".js") && !name.startsWith(".")).sort()) {
  checkSyntax(`src/${fileName}`);
}

await assertContains("src/server-tracker-analytics.js", 'import "./server-remove-analytics-title.js";', "the analytics title wrapper handoff");
await assertContains("src/server-remove-analytics-title.js", 'await import("./server-notification-icon.js");', "the notification wrapper handoff");
await assertContains("src/server-notification-icon.js", 'await import("./server-tab-loading-state.js");', "the tab loading wrapper handoff");
await assertContains("src/server.js", 'aria-label="Notifications"', "the encoding-safe notification control");
await assertContains("src/server.js", 'aria-label="Settings"', "the encoding-safe settings control");
await assertContains("src/server.js", '.settingsIcon svg{', "the shared SVG icon styling");
await assertContains("src/server-tab-loading-state.js", 'await import(`${pathToFileURL(generatedSelectorPath).href}?v=${Date.now()}`);', "the analytics selector loading handoff");
await assertContains("src/server-analytics-selector-copies.js", 'await import("./server-crm-actions-scope.js");', "the CRM scope fallback handoff");
await assertContains("src/server-runtime.js", "await fs.writeFile(runtimePath, source);", "the generated runtime write target");
await assertContains("src/server-responsive.js", "await import(`${pathToFileURL(responsiveRuntimePath).href}?v=${Date.now()}`);", "the responsive runtime handoff");
await assertContains("src/server-responsive.js", "function aiDraftRow\\\\(", "the AI record renderer preservation boundary");
await assertContains("src/server-runtime.js", "function aiRecordsContent()", "the AI record queue renderer");
await assertContains("src/server-analytics.js", "await import(`${pathToFileURL(analyticsRuntimePath).href}?v=${Date.now()}`);", "the analytics runtime handoff");
await assertContains("src/server-fonts.js", "await import(`${pathToFileURL(fontRuntimePath).href}?v=${Date.now()}`);", "the font runtime handoff");
await assertContains("src/server-connected-resources.js", 'await import("./server-fonts.js");', "the font wrapper handoff");
await assertContains("src/server-account-persistence.js", 'await import("./server-connected-resources.js");', "the connected resources wrapper handoff");

await validateLocalImports("src/server-tracker-analytics.js");
await validateEncodedScopeWrapper();

if (failures.length) {
  console.error("Startup chain validation failed:");
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log("Startup chain validation passed.");
