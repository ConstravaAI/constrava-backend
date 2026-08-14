import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(projectRoot, "src");
const failures = [];
const requiredStartScript = "node scripts/start-runtime.mjs";

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

async function assertNotContains(relativePath, needle, label) {
  const source = await readProjectFile(relativePath);
  if (source && source.includes(needle)) {
    fail(`${relativePath} still contains ${label || JSON.stringify(needle)}`);
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
  fail("package.json start script must use the generated-runtime launcher.");
}
if (packageJson.scripts?.postinstall !== "npm run build:runtime") {
  fail("package.json postinstall script must generate the production runtime during the build phase.");
}

const sourceFileNames = (await fs.readdir(srcDir))
  .filter((name) => name.endsWith(".js") && !name.startsWith("."))
  .sort();

for (const fileName of sourceFileNames) {
  checkSyntax(`src/${fileName}`);
}

await assertContains("src/server-tracker-analytics.js", 'import "./server-remove-analytics-title.js";', "the analytics title wrapper handoff");
await assertContains("scripts/generate-runtime.mjs", 'process.env.CONSTRAVA_GENERATE_ONLY = "1";', "the build-only runtime flag");
await assertContains("scripts/start-runtime.mjs", 'path.join(root, "src", ".server.generated.js")', "the generated production server target");
await assertContains("src/server.js", 'process.env.CONSTRAVA_GENERATE_ONLY !== "1"', "the build-only listener guard");
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
await assertContains("src/server-runtime.js", "api('/api/records/drafts')", "the Review and Publish draft loader");
await assertContains("src/server.js", 'route === "/api/calendar-connections/sync"', "the calendar refresh review endpoint");
await assertContains("src/server.js", "google-calendar:${connection.id}:${event.id}", "calendar event duplicate protection");
await assertContains("src/server.js", "/calendar/v3/users/me/calendarList", "secondary Google Calendar discovery");
await assertContains("src/server.js", "connection.calendarSyncTokens[calendar.id]", "per-calendar incremental sync cursors");
await assertContains("src/server-runtime.js", "api('/api/calendar-connections/sync'", "the website-refresh calendar review trigger");
await assertContains("src/server-runtime.js", "S.aiRecords=(refreshed&&refreshed.records)", "the refreshed Review and Publish calendar drafts");
await assertContains("src/server-runtime.js", "S.emailConnections=out[3].connections", "the current dashboard load response shape");
await assertContains("src/server.js", 'recordType: { type: "string", enum: ["Person", "Company", "Deal", "Task", "Note"] }', "the specific AI record type schema");
await assertContains("src/server.js", "Never create a generic intake or placeholder record.", "the AI best-fit record instruction");
await assertContains("src/server.js", 'scan(/\\bnext\\s+week\\b/gi, () => 7, "relative_week")', "the next-week date resolver");
await assertContains("src/server.js", 'associatedDate: { type: "string" }', "the AI associated-date field");
await assertContains("src/server.js", 'fields.associatedDate = associatedMatch.date', "the validated associated-date assignment");
await assertContains("src/server.js", 'entry.recordType === "Task" ? associatedMatch : null', "the task due-date synchronization");
await assertNotContains("src/server.js", 'action("create", "Intake"', "an Intake fallback action");
await assertNotContains("src/server-runtime.js", '<option value="Intake">Intake</option>', "an Intake record-type option");
await assertContains("src/server-runtime.js", 'id="crmPriorityCheck">AI Priority Check</button>', "the CRM hero priority action");
await assertContains("src/server-runtime.js", 'id="crmEditRecords">Edit Records</button>', "the CRM hero edit action");
await assertContains("src/server-runtime.js", 'id="crmPlainTextRecord">Add record from plain text</button>', "the CRM hero plain-text action");
await assertContains("src/server-runtime.js", "function ensurePlainTextRecordDialog()", "the CRM plain-text record dialog");
await assertContains("src/server-runtime.js", "heroPlainText.onclick=openPlainTextRecordDialog", "the CRM plain-text action binding");
await assertContains("src/server-runtime.js", "kind:'manual_note',sourceId:'source_manual'", "the shared Manual Notes record-planning source");
await assertContains("src/server-runtime.js", "recordEditorBindCodeWithHeroActions", "the CRM hero action bindings");
await assertContains("src/server-runtime.js", "el.style.display='none'", "the hidden duplicate CRM workspace actions");
await assertContains("src/server-analytics.js", "await import(`${pathToFileURL(analyticsRuntimePath).href}?v=${Date.now()}`);", "the analytics runtime handoff");
await assertContains("src/server-analytics.js", 'responsive = responsive.replace(/\\r\\n/g, "\\n");', "cross-platform analytics wrapper line endings");
await assertContains("src/server-runtime.js", 'source = source.replace(/\\r\\n/g, "\\n");', "cross-platform runtime wrapper line endings");
await assertContains("src/server-fonts.js", "await import(`${pathToFileURL(fontRuntimePath).href}?v=${Date.now()}`);", "the font runtime handoff");
await assertContains("src/server-connected-resources.js", 'await import("./server-colorful-workspaces.js");', "the colorful workspace wrapper handoff");
await assertContains("src/server-connected-resources.js", "function constravaManualNotesDetail(resource)", "the Manual Notes AI record form");
await assertContains("src/server-connected-resources.js", "id=\"manualNotesForm\"", "the Manual Notes submission form");
await assertContains("src/server-connected-resources.js", "kind:'manual_note',sourceId:'source_manual'", "the Manual Notes AI plan source context");
await assertContains("src/server-connected-resources.js", "S.crmView='ai-records'", "the Manual Notes Review and Publish handoff");
await assertContains("src/server-colorful-workspaces.js", 'await import("./server-fonts.js");', "the font wrapper handoff");
await assertContains("src/server-colorful-workspaces.js", 'source.indexOf("<title>Constrava Dashboard</title>")', "dashboard-specific colorful stylesheet target");
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
await assertContains("src/server.js", "public.constrava_app_store_v2", "the Neon account storage table");
await assertContains("src/server.js", "normalizeDatabaseConnectionString", "common Neon connection string normalization");
await assertContains("src/server.js", "async function postgresQuery", "runtime Neon disconnect recovery");
await assertContains("src/server.js", "Account storage is temporarily unavailable.", "graceful database outage handling");
await assertContains("src/server.js", "const database = await databaseHealth();", "database-independent health reporting");
await assertContains("src/server.js", 'route === "/api/website-connections"', "persistent Website Tracker connections");
await assertContains("src/server-connected-resources.js", "function constravaSaveWebsiteState(", "Website Tracker server persistence");
await assertContains("src/server-connected-resources.js", ".join('\\\\n')", "escaped Website Tracker domain separators in the browser runtime");
await assertContains("src/server-account-persistence.js", "replacement.satisfiedBy", "forward-compatible account persistence patches");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsModernDonut(", "the analytics distribution chart system");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewTrend(", "the interactive Overview trend chart");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewComposition(", "the interactive Overview composition chart");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewJourney(", "the Overview visitor journey");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewBlock(", "the reusable Overview data block");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsTabGrid(", "the shared Analytics tab card grid");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsTabTimelineBlock(", "the shared Analytics tab timeline block");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsTabDonutBlock(", "the shared Analytics tab distribution block");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Traffic'", "the Traffic overview-style grid");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Sources'", "the Sources overview-style grid");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Pages'", "the Pages overview-style grid");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Events'", "the Events overview-style grid");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Audience'", "the Audience overview-style grid");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewPopup(", "the centered Overview detail pop-up");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewToggleExpand(", "the Overview pop-up open and collapse interaction");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsOverviewModalLayer{position:fixed", "the full-screen Overview pop-up layer");
await assertContains("src/server-analytics-selector-copies.js", "aria-modal=\"true\"", "the accessible Overview pop-up dialog");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsOverviewGrid{display:grid", "the responsive Overview data grid");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsOverviewSwitch button[aria-pressed=\"true\"]", "the accessible Overview chart controls");
await assertContains("src/server-analytics-selector-copies.js", "analytics-visual-system-v1", "the colorful analytics visual system");
await assertContains("src/server-analytics-selector-copies.js", "analyticsDedicatedMetrics()+(body?'<div", "conditional analytics detail panel rendering");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsToolbarControlsWrap select{color:#061a33!important}", "dark analytics dropdown selected values");
await assertContains("src/server-analytics-selector-copies.js", ".crmHeroActions{display:flex", "the CRM hero action layout");
await assertContains("src/server-fonts.js", 'source = source.replace(/\\r\\n/g, "\\n");', "cross-platform Analytics visual source line endings");
await assertContains("src/server-fonts.js", 'source.includes("function analyticsOverviewPopup(")', "the active Analytics visual installation check");
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
