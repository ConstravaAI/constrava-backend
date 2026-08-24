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

async function checkResourcesClientSyntax() {
  const source = await readProjectFile("src/server-connected-resources.js");
  const marker = "const resourcesClientCode = String.raw`";
  const start = source.indexOf(marker) + marker.length;
  const end = source.indexOf("`;", start);
  if (start < marker.length || end < start) {
    fail("src/server-connected-resources.js is missing its browser client bundle.");
    return;
  }
  try {
    new Function(source.slice(start, end));
  } catch (error) {
    fail(`Connected Resources browser code failed syntax check: ${error.message}`);
  }
}

async function checkPublicResourceCatalog() {
  const source = await readProjectFile("src/server-connected-resources.js");
  const start = source.indexOf("const CONSTRAVA_RESOURCES=[");
  const end = source.indexOf("\n];", start);
  if (start < 0 || end < start) {
    fail("src/server-connected-resources.js is missing its public resource catalog.");
    return;
  }
  const catalog = source.slice(start, end);
  const required = ["google-account", "google-adsense", "google-analytics", "website-tracker", "email-inbox", "manual-notes", "file-uploads", "crm-tools", "calendar"];
  const retired = ["microsoft-account", "website-forms", "messaging", "payments", "commerce", "phone-calls", "hubspot", "salesforce", "airtable", "notion"];
  for (const id of required) if (!catalog.includes(`id:'${id}'`)) fail(`The public resource catalog is missing ${id}.`);
  for (const id of retired) if (catalog.includes(`id:'${id}'`)) fail(`The public resource catalog still exposes retired resource ${id}.`);
  const ids = [...catalog.matchAll(/\{id:'([^']+)'/g)].map((match) => match[1]);
  if (ids.length !== required.length) fail(`The public resource catalog must contain exactly ${required.length} supported resources; found ${ids.length}.`);
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
await assertContains("scripts/generate-runtime.mjs", 'await import("../src/server-migration-safety-runtime.js");', "the migration safety runtime wrapper");
await assertContains("scripts/start-runtime.mjs", 'path.join(root, "src", ".server.generated.js")', "the generated production server target");
await assertContains("scripts/start-runtime.mjs", 'generatedSource.includes("migration-safety-runtime-v4")', "the migration-safe generated runtime check");
await assertContains("src/server.js", 'process.env.CONSTRAVA_GENERATE_ONLY !== "1"', "the build-only listener guard");
await assertContains("src/server-migration-safety-runtime.js", 'createMigrationSafety({ pool: postgresPool', "the migration safety integration");
await assertContains("src/server-migration-safety-runtime.js", 'await migrationSafety.ensure();', "the Postgres migration safety bootstrap");
await assertContains("src/server-migration-safety-runtime.js", 'createRelationalFoundation({ migrationSafety:', "the relational foundation integration");
await assertContains("src/server-migration-safety-runtime.js", 'await relationalFoundation.ensure();', "the relational foundation bootstrap");
await assertContains("src/server-migration-safety-runtime.js", 'createIdentityBackfill({ migrationSafety:', "the identity backfill integration");
await assertContains("src/server-migration-safety-runtime.js", 'await identityBackfill.ensure();', "the identity backfill bootstrap");
await assertContains("src/server-migration-safety-runtime.js", "createRelationalShadowSync({ pool: postgresPool", "the transactional relational shadow integration");
await assertContains("src/server-migration-safety-runtime.js", "RELATIONAL_DUAL_WRITE_ENABLED", "the explicit relational shadow off switch");
await assertContains("src/server-migration-safety-runtime.js", "await relationalShadowSync.ensure();", "the relational shadow startup reconciliation");
await assertContains("src/server-migration-safety-runtime.js", "relationalShadowSync.save({ serialized, storeData, expectedVersion })", "the atomic legacy and relational save boundary");
await assertContains("src/.server.generated.js", "migration-safety-runtime-v4", "the generated migration safety marker");
await assertContains("src/.server.generated.js", '...migrationSafety.health()', "the generated migration health response");
await assertContains("src/.server.generated.js", '...relationalFoundation.health()', "the generated relational schema health response");
await assertContains("src/.server.generated.js", '...identityBackfill.health()', "the generated relational backfill health response");
await assertContains("src/.server.generated.js", '...relationalShadowSync.health()', "the generated relational shadow health response");
await assertContains("src/postgres-migration-safety.js", 'const activeMode = "legacy";', "the Deployment 1 legacy-only storage mode");
await assertContains("src/postgres-migration-safety.js", "pg_advisory_lock", "the migration advisory lock");
await assertContains("src/postgres-migration-safety.js", "constrava_store_snapshots", "the pre-migration snapshot table");
await assertContains("src/postgres-migration-safety.js", "MIGRATION_CHECKSUM_MISMATCH", "migration checksum protection");
await assertContains("src/postgres-relational-foundation.js", 'RELATIONAL_FOUNDATION_MIGRATION_ID = "0002_relational_foundation"', "the versioned relational foundation migration");
await assertContains("src/postgres-relational-foundation.js", "credentials_ciphertext TEXT NOT NULL", "encrypted provider credential storage");
await assertContains("src/postgres-relational-foundation.js", "relationalBackfillEnabled: false", "the disabled relational backfill boundary");
await assertContains("src/postgres-identity-backfill.js", 'IDENTITY_BACKFILL_MIGRATION_ID = "0003_identity_project_backfill"', "the versioned identity and project backfill");
await assertContains("src/postgres-identity-backfill.js", "hashToken(rawId)", "hashed session-token migration");
await assertContains("src/postgres-identity-backfill.js", "credentialsCiphertext", "encrypted external-account credential migration");
await assertContains("src/postgres-identity-backfill.js", 'snapshotKey: IDENTITY_BACKFILL_SNAPSHOT_KEY', "the Deployment 3 pre-backfill snapshot");
await assertContains("src/postgres-identity-backfill.js", "relationalDualWriteEnabled: false", "the Deployment 3 no-dual-write boundary");
await assertContains("src/postgres-relational-shadow-sync.js", 'RELATIONAL_SHADOW_SYNC_MIGRATION_ID = "0004_relational_shadow_sync"', "the versioned relational shadow migration");
await assertContains("src/postgres-relational-shadow-sync.js", "RELATIONAL_SHADOW_SYNC_SNAPSHOT_KEY", "the Deployment 4 pre-shadow snapshot");
await assertContains("src/postgres-relational-shadow-sync.js", 'await client.query("BEGIN")', "transactional shadow writes");
await assertContains("src/postgres-relational-shadow-sync.js", 'await client.query("ROLLBACK")', "atomic shadow rollback");
await assertContains("src/postgres-relational-shadow-sync.js", "verifyIdentityShadow", "post-write relational drift verification");
await assertContains("src/postgres-relational-shadow-sync.js", "relationalReadsEnabled: false", "the Deployment 4 legacy-read boundary");
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
await assertContains("src/server-responsive.js", "const dashboardStyleInjection =", "the dashboard-specific style insertion");
await assertContains("src/server-responsive.js", "dashboardStyleEnd = source.indexOf", "the dashboard-scoped style lookup");
await assertNotContains("src/server-responsive.js", 'const styleNeedle = "</style>\\n</head>"', "the ambiguous first-page style marker");
await assertContains("src/server-runtime.js", "function aiRecordsContent()", "the AI record queue renderer");
await assertNotContains("src/server-runtime.js", "source.slice(0, start) + projectAwareSignInPage", "the obsolete production sign-in replacement");
await assertContains("src/.server.generated.js", "Standard account only", "the secure signup page in the generated production server");
await assertContains("src/server-runtime.js", "api('/api/records/drafts')", "the Review and Publish draft loader");
await assertContains("src/server.js", 'route === "/api/calendar-connections/sync"', "the calendar refresh review endpoint");
await assertContains("src/server.js", "google-calendar:${connection.id}:${event.id}", "calendar event duplicate protection");
await assertContains("src/server.js", "/calendar/v3/users/me/calendarList", "secondary Google Calendar discovery");
await assertContains("src/server.js", "calendarScanMatch", "the Google Calendar picker scan endpoint");
await assertContains("src/server.js", "calendarSelectionConfigured", "saved Google Calendar selection behavior");
await assertContains("src/server-connected-resources.js", "calendarPickerForm", "the Google Calendar selection interface");
await assertContains("src/server-connected-resources.js", "['Provider','Account details','Authorize','Choose calendars','CRM rules','Ready']", "the ordered calendar connection steps");
await assertContains("src/server-connected-resources.js", "function constravaCalendarCalendars", "the dedicated calendar-selection step");
await assertContains("src/server.js", 'route === "/api/google-accounts"', "the reusable Google account API");
await assertContains("src/server.js", "GOOGLE_SHARED_SCOPES", "combined read-only Google permissions");
await assertContains("src/server.js", "linkedGoogleAccount(storeData, connection)", "shared Google token resolution");
await assertContains("src/server.js", "saveGoogleAccountOAuth(storeData", "automatic Google account saving from resource OAuth");
await assertContains("src/server.js", 'connection.provider === "gmail" ? GOOGLE_SHARED_SCOPES.join(" ")', "combined Google permissions from the Gmail connection flow");
await assertContains("src/server.js", "GOOGLE_APP_CATALOG", "the supported Google app catalog");
await assertContains("src/server.js", "googleAppsAuthorizeMatch", "incremental Google app authorization");
await assertContains("src/server.js", "googleAppsScanMatch", "connected Google app scanning");
await assertContains("src/server-connected-resources.js", "function constravaGoogleAppsSetup", "the Google app selection interface");
await assertContains("src/server-connected-resources.js", "data-google-scan", "manual Google account scanning");
await assertContains("src/server.js", 'id: "adsense"', "the Google AdSense app catalog entry");
await assertContains("src/server.js", '"https://www.googleapis.com/auth/adsense.readonly"', "the read-only AdSense permission");
await assertContains("src/server.js", 'id: "analytics"', "the Google Analytics app catalog entry");
await assertContains("src/server.js", '"https://www.googleapis.com/auth/analytics.readonly"', "the read-only Google Analytics permission");
await assertContains("src/server.js", "async function syncAdsenseConnection", "AdSense report synchronization");
await assertContains("src/server.js", 'route === "/api/adsense-connections/discover"', "AdSense account discovery");
await assertContains("src/server-connected-resources.js", "function constravaAdsenseSetup", "the Google AdSense setup interface");
await assertContains("src/server-connected-resources.js", "function constravaAdsenseDashboard", "the Google AdSense performance dashboard");
await assertContains("src/server-connected-resources.js", "data-adsense-sync", "the AdSense report refresh control");
await assertContains("src/server.js", 'route === "/api/google-analytics-connections/discover"', "Google Analytics property discovery");
await assertContains("src/server.js", "syncGoogleAnalyticsConnection", "Google Analytics report synchronization");
await assertContains("src/server-connected-resources.js", "function constravaAnalyticsSetup", "the Google Analytics property picker");
await assertContains("src/server-connected-resources.js", "function constravaAnalyticsDashboard", "the Google Analytics performance dashboard");
await assertContains("src/server-connected-resources.js", "data-google-analytics-sync", "the Google Analytics report refresh control");
await assertContains("src/server.js", "/link-google", "Google account resource linking");
await assertContains("src/server-connected-resources.js", "function constravaGoogleSetup", "the reusable Google account interface");
await assertContains("src/server-connected-resources.js", "data-use-google-for-email", "Gmail reuse without another login");
await assertContains("src/server-connected-resources.js", "data-use-google-for-calendar", "Calendar reuse without another login");
await assertContains("src/server.js", "MICROSOFT_APP_CATALOG", "the supported Microsoft app catalog");
await assertContains("src/server.js", "microsoftAppsAuthorizeMatch", "incremental Microsoft app authorization");
await assertContains("src/server.js", "microsoftAppsScanMatch", "connected Microsoft app scanning");
await assertContains("src/server.js", "linkedMicrosoftAccount(storeData, connection)", "shared Microsoft token resolution");
await assertContains("src/server.js", "/link-microsoft", "Microsoft account resource linking");
await assertContains("src/server-connected-resources.js", "function constravaMicrosoftAppsSetup", "the Microsoft app selection interface");
await assertContains("src/server-connected-resources.js", "data-microsoft-scan", "manual Microsoft account scanning");
await assertContains("src/server-connected-resources.js", "data-use-microsoft-for-email", "Outlook reuse without another login");
await assertContains("src/server-connected-resources.js", "data-use-microsoft-for-calendar", "Microsoft Calendar reuse without another login");
await assertContains("src/server-connected-resources.js", "data-google-banner", "the Google account banner action");
await assertContains("src/server-connected-resources.js", ".resourcesGoogleCta{", "the Google banner action styling");
await assertContains("src/server-connected-resources.js", "if(name==='resources'){S.resourceView='';S.resourcesDirectoryView='all'}", "the Connect Resources tab directory reset");
await assertContains("src/server-connected-resources.js", "function constravaGooglePermissionDirectory", "the simplified Google permission directory");
await assertContains("src/server-connected-resources.js", "data-google-service", "direct Google service permission actions");
await assertContains("src/server-connected-resources.js", "function constravaOpenGoogleService", "Google permission-first resource routing");
await assertContains("src/server-connected-resources.js", "constravaReturnParams.delete('google_account_connected')", "the one-time Google OAuth return handling");
await assertNotContains("src/server-connected-resources.js", "{id:'microsoft-account'", "the visible Microsoft account directory option");
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
await assertNotContains("src/server-connected-resources.js", "api('/api/email-connections'),api('/api/google-accounts'),api('/api/microsoft-accounts')", "the retired Microsoft request in the Gmail flow");
await assertNotContains("src/server-connected-resources.js", "api('/api/calendar-connections'),api('/api/google-accounts'),api('/api/microsoft-accounts')", "the retired Microsoft request in the Google Calendar flow");
await assertContains("src/server.js", "function businessProviderReadiness(provider, storeData, workspaceId, accountUserId", "member-owned business-tool provider readiness reporting");
await assertContains("src/server.js", "process.env.GOOGLE_CALENDAR_CLIENT_ID || process.env.GMAIL_CLIENT_ID", "Google Sheets OAuth credential reuse");
await assertContains("src/server.js", "/link-google$/", "connected Google account reuse for Google Sheets");
await assertContains("src/server-connected-resources.js", "function constravaBusinessSetupNotice(status)", "clear business-provider administrator setup guidance");
await assertContains("src/server-connected-resources.js", "data-use-google-for-business", "Google Sheets connection without a second Google login");
await assertContains("src/server.js", "async function listGoogleSpreadsheets(storeData, connection)", "Google Sheets document discovery");
await assertContains("src/server.js", "/google-sheets\\/migrate$/", "selected Google Sheets migration route");
await assertContains("src/server.js", "https://www.googleapis.com/auth/drive.metadata.readonly https://www.googleapis.com/auth/spreadsheets.readonly", "Google Sheets file-list and read-only data scopes");
await assertContains("src/server-connected-resources.js", "function constravaBusinessDocuments(state)", "Google Sheets document picker");
await assertContains("src/server-connected-resources.js", "data-business-open-review", "Google Sheets Review and Publish handoff");
await assertContains("src/server-runtime.js", "function constravaBusinessDocuments(state)", "generated Google Sheets document picker");
await assertContains("src/server-runtime.js", "/google-sheets/migrate", "generated Google Sheets migration request");
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
await assertContains("src/server.js", "function freePublicPage()", "free public homepage renderer");
await assertContains("src/server.js", "Free business management + SEO tools", "free-service homepage positioning");
await assertContains("src/server.js", "Create your free account", "free account homepage call to action");
await assertContains("src/server.js", "SIGNUP_PASSWORD_MIN_LENGTH = 7", "the public password minimum");
await assertContains("src/server.js", "SIGNUP_SPECIAL_CHARACTER", "the public special-character requirement");
await assertContains("src/server.js", "el.mismatchDialog.showModal", "the password mismatch warning pop-up");
await assertContains("src/server.js", 'href="/signin">Log in', "the separate homepage login button");
await assertContains("src/server.js", 'href="/signup">Sign up', "the separate homepage signup button");
await assertContains("src/server.js", 'workspaceId: ""', "new accounts without an automatic CRM project");
await assertContains("src/server.js", '>Switch Project</a>', "the explicit project-switch navigation label");
await assertNotContains("src/server.js", '<section class="workspace">', "the obsolete shared dashboard spacer");
await assertNotContains("src/server.js", "document.getElementById('aiAdd')", "the removed spacer action binding");
await assertContains("src/server.js", "fluid-aspect-core-v1", "the production dashboard fluid aspect-ratio core");
await assertContains("src/server.js", 'role: "user", accountType: "standard", isDeveloper: false', "the standard-only public account boundary");
await assertContains("src/server.js", 'route === "/api/auth/developer-login"', "the separate developer authentication endpoint");
await assertContains("src/server.js", "function developerSignInPage()", "the isolated developer sign-in page");
await assertContains("src/server.js", 'route === "/api/auth/verify-email"', "one-time public email verification");
await assertContains("src/server.js", "createEmailVerification(user)", "hashed verification-token creation");
await assertContains("src/server.js", "emailVerificationTokenHash = hashToken(token)", "hashed verification-token storage");
await assertContains("src/server.js", "sendAccountVerificationEmail(user, verificationToken)", "verification email delivery before account activation");
await assertContains("src/server.js", 'code: "email_verification_required"', "unverified public login protection");
await assertContains("src/server.js", "function securityHeaders(", "shared HTTP security headers");
await assertContains("src/server.js", 'route === "/robots.txt"', "the search crawler rules");
await assertContains("src/server.js", 'route === "/sitemap.xml"', "the search sitemap");
await assertContains("src/server.js", '<link rel="canonical"', "the canonical homepage URL");
await assertContains("src/server.js", 'application/ld+json', "the homepage structured data");
await assertContains("src/server.js", "Free Business Management, CRM &amp; SEO Tools", "the search-focused homepage title");
await assertContains("src/server.js", "isRetiredResourceRoute(route)", "retired resource route enforcement");
await assertContains("src/server.js", 'const BUSINESS_PROVIDER_IDS = ["google_sheets"]', "the Google Sheets-only business migration catalog");
await assertNotContains("src/server.js", "â", "mojibake characters");
await assertNotContains("src/server.js", "Â", "mojibake characters");
await assertContains("src/server.js", 'route === "/api/website-connections"', "persistent Website Tracker connections");
await assertContains("src/server-connected-resources.js", "function constravaSaveWebsiteState(", "Website Tracker server persistence");
await assertContains("src/server.js", "/developer-handoff", "server-side Website Tracker developer handoff endpoint");
await assertContains("src/server.js", "https://api.resend.com/emails", "transactional developer handoff email delivery");
await assertContains("src/server.js", "developerHandoffs", "developer handoff delivery audit persistence");
await assertContains("src/server-connected-resources.js", "data-send-developer-handoff", "Website Tracker developer email send action");
await assertContains("src/server-connected-resources.js", ".join('\\\\n')", "escaped Website Tracker domain separators in the browser runtime");
await assertContains("src/server-account-persistence.js", "replacement.satisfiedBy", "forward-compatible account persistence patches");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsModernDonut(", "the analytics distribution chart system");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewTrend(", "the interactive Overview trend chart");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewComposition(", "the interactive Overview composition chart");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewJourney(", "the Overview visitor journey");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsOverviewBlock(", "the reusable Overview data block");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsTabGrid(", "the shared Analytics tab card grid");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Overview'", "the Overview shared Analytics tab layout");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsTabTimelineBlock(", "the shared Analytics tab timeline block");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsTabDonutBlock(", "the shared Analytics tab distribution block");
await assertContains("src/server-analytics-selector-copies.js", "analyticsTabGrid('Traffic'", "the Traffic overview-style grid");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsHourFormat()", "the 12-hour default and saved clock preference");
await assertContains("src/server-analytics-selector-copies.js", "function analyticsSetHourFormat(", "the Activity by hour clock-format control");
await assertContains("src/server-analytics-selector-copies.js", "12-hour", "the default 12-hour clock choice");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsTabStory-overview{background:", "the distinct Overview story color");
await assertContains("src/server-analytics-selector-copies.js", ".analyticsTabStoryCopy h3", "the high-contrast Overview heading style");
await assertContains("src/server-analytics-selector-copies.js", "fluid-aspect-layout-v1", "the fluid dashboard aspect-ratio layout");
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
await assertContains("src/server-runtime.js", "['Person','People']", "the dedicated People navigation label");
await assertContains("src/server-responsive.js", "function crmPeopleContent()", "the dedicated People CRM dashboard");
await assertContains("src/server-responsive.js", "if(S.crmView==='Person')return crmPeopleContent()", "the dedicated People tab route");
await assertContains("src/server-runtime.js", "function deleteRecordFromBody(", "workspace-scoped CRM record deletion");
await assertContains("src/server-runtime.js", "function synchronizeCompanyHierarchy(", "bidirectional company hierarchy persistence");
await assertContains("src/server-runtime.js", "A company cannot be part of itself.", "company self-link protection");
await assertContains("src/server-runtime.js", "That parent company would create a relationship loop.", "company relationship cycle protection");
await assertContains("src/server-runtime.js", "function ensureDeleteRecordDialog()", "the confirmed CRM record deletion dialog");
await assertContains("src/server-responsive.js", "function crmCompaniesContent()", "the dedicated company relationship dashboard");
await assertContains("src/server-responsive.js", ".companyRelationshipGrid", "the Company People and Companies sections");
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
await checkResourcesClientSyntax();
await checkPublicResourceCatalog();

if (failures.length) {
  console.error("Startup chain validation failed:");
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log("Startup chain validation passed.");
