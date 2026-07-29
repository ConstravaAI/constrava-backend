import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(projectRoot, "src");
const failures = [];
const requiredStartScript = "node src/server-tracker-analytics.js";

async function readProjectFile(relativePath) {
  try {
    return await fs.readFile(path.join(projectRoot, relativePath), "utf8");
  } catch {
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
  const result = spawnSync(
    process.execPath,
    ["--check", path.join(projectRoot, relativePath)],
    { encoding: "utf8" }
  );
  if (result.status !== 0) {
    fail(`${relativePath} failed syntax check:\n${result.stderr || result.stdout}`.trim());
  }
}

function localImportTargets(relativePath, source) {
  const dir = path.dirname(path.join(projectRoot, relativePath));
  const targets = [];
  const patterns = [
    /\bimport\s+(?:[^'"]+\s+from\s+)?["'](\.\/[^"']+)["']/g,
    /\bawait\s+import\(["'](\.\/[^"']+)["']\)/g
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const target = match[1].endsWith(".js") ? match[1] : `${match[1]}.js`;
      targets.push(
        path.relative(projectRoot, path.resolve(dir, target)).replaceAll("\\", "/")
      );
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
      await fs.access(path.join(projectRoot, target));
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
if (packageJson.scripts?.start !== requiredStartScript) {
  fail("package.json start script must stay pointed at src/server-tracker-analytics.js.");
}

const sourceFileNames = (await fs.readdir(srcDir))
  .filter((name) => name.endsWith(".js") && !name.startsWith("."))
  .sort();

for (const fileName of sourceFileNames) {
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
await assertContains("src/server-analytics-selector-copies.js", "await fs.writeFile(generatedPath, generated);", "the analytics selector generated write target");
await assertContains("src/server-runtime.js", "await fs.writeFile(runtimePath, source);", "the generated runtime write target");
await assertContains("src/server-responsive.js", "await import(`${pathToFileURL(responsiveRuntimePath).href}?v=${Date.now()}`);", "the responsive runtime handoff");
await assertContains("src/server-responsive.js", "function aiDraftText\\\\(", "the AI record renderer preservation boundary");
await assertContains("src/server-runtime.js", "function aiRecordsContent()", "the AI record queue renderer");
await assertContains("src/server-analytics.js", "await import(`${pathToFileURL(analyticsRuntimePath).href}?v=${Date.now()}`);", "the analytics runtime handoff");
await assertContains("src/server-analytics.js", 'responsive = responsive.replace(/\\r\\n/g, "\\n");', "cross-platform analytics wrapper line endings");
await assertContains("src/server-runtime.js", 'source = source.replace(/\\r\\n/g, "\\n");', "cross-platform runtime wrapper line endings");
await assertContains("src/server-fonts.js", "await import(`${pathToFileURL(fontRuntimePath).href}?v=${Date.now()}`);", "the font runtime handoff");
await assertContains("src/server-connected-resources.js", 'await import("./server-fonts.js");', "the font wrapper handoff");
await assertContains("src/server-account-persistence.js", 'await import("./server-connected-resources.js");', "the connected resources wrapper handoff");
await assertContains("src/server-connected-resources.js", "function constravaEmailConnect(state)", "the provider-aware email connection step");
await assertContains("src/server.js", "async function fetchImapMessages(connection)", "the universal IMAP inbox adapter");
await assertContains("src/server.js", "/imap$/", "the IMAP verification route");
await assertContains("src/server.js", 'connection.status = "reauthorization_required";', "the Gmail permission recovery state");
await assertContains("src/server.js", "connection.syncCursor = connection.authorizedAt;", "the new-email-only OAuth sync cursor");
await assertContains("src/server-connected-resources.js", "Reconnect Google", "the Gmail reconnect action");
await assertContains("src/server.js", "function upsertHiddenIdentity(", "the hidden identity upsert layer");
await assertContains("src/server.js", "function reconcilePublishedRecordIdentity(", "published CRM identity reconciliation");
await assertContains("src/server.js", 'route === "/api/identity/reconcile"', "the incremental identity reconciliation endpoint");
await assertContains("src/server-runtime.js", "reconcilePublishedRecordIdentity(storeData, record);", "manual CRM identity reconciliation");
await assertContains("src/server-connected-resources.js", "function constravaHydrateEmailConnection(", "email connection refresh restoration");
await assertContains("src/server-connected-resources.js", "function constravaPreferredEmailConnection(", "active email connection selection");
await assertContains("src/server-runtime.js", "api('/api/email-connections')", "email connection dashboard preload");
await assertContains("src/server.js", "sourcePreview", "draft source preview response");
await assertContains("src/server-runtime.js", "function aiDraftText(", "simplified AI draft text renderer");
await assertContains("src/server.js", "durableStoreConfigured", "durable production store configuration");
await assertContains("src/server.js", "storeWriteQueue", "serialized atomic store writes");
await assertContains("src/server.js", "CREATE SCHEMA IF NOT EXISTS constrava_v2", "the isolated Neon workspace schema");
await assertContains("src/server.js", "postgresStoreConfigured", "the Postgres health and durability state");
await assertContains("src/server.js", 'route === "/api/website-connections"', "persistent Website Tracker connections");
await assertContains("src/server-connected-resources.js", "function constravaSaveWebsiteState(", "Website Tracker server persistence");
await assertContains("src/server-account-persistence.js", "replacement.satisfiedBy", "forward-compatible account persistence patches");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsModernDonut(", "the analytics distribution chart system");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewTrend(", "the interactive Overview trend chart");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewComposition(", "the interactive Overview composition chart");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewJourney(", "the Overview visitor journey");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewBlock(", "the reusable expandable Overview data block");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewToggleExpand(", "the Overview block expansion interaction");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsOverviewGrid{display:grid", "the responsive Overview data grid");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsOverviewModalBackdrop{position:fixed", "the non-dismissing Overview modal backdrop");
await assertContains("src/server-analytics-selector-copies.js", "aria-modal=\"true\"", "the accessible expanded Overview dialog");
await assertContains("src/server-analytics-selector-copies.js", "Collapse view", "the explicit Overview modal collapse control");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsOverviewSwitch button[aria-pressed=\"true\"]", "the accessible Overview chart controls");
await assertContains("src/server-analytics-selector-copies.js", "analytics-visual-system-v1", "the colorful analytics visual system");
await assertContains("src/server-analytics-selector-copies.js", "analyticsDedicatedMetrics()+(body?'<div", "conditional analytics detail panel rendering");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsToolbarControlsWrap select{color:#061a33!important}", "dark analytics dropdown selected values");
await assertContains("src/server-fonts.js", '<select id="analyticsRange" style="color:#061a33!important">', "explicit dark date-range selected value");
await assertContains("src/server-fonts.js", '<select id="analyticsSource" style="color:#061a33!important">', "explicit dark event-type selected value");
await assertContains("src/server-fonts.js", 'id="analyticsRefresh" style="color:#061a33!important"', "explicit dark Analytics refresh text");
await assertContains("src/server-fonts.js", 'id="analyticsReport" style="color:#061a33!important"', "explicit dark Analytics snapshot text");
await assertContains("src/server-fonts.js", "function analyticsAudienceTools(", "the audience analytics page");
await assertContains("src/server-fonts.js", "${analyticsCommandCenterFinal}", "the cleaned final analytics renderer injection");

await validateLocalImports("src/server-tracker-analytics.js");
await validateEncodedScopeWrapper();

if (failures.length) {
  console.error("Startup chain validation failed:");
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log("Startup chain validation passed.");
