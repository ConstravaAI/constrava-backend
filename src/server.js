import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import tls from "node:tls";
import dns from "node:dns/promises";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { PDFParse } from "pdf-parse";
import mammoth from "mammoth";
import readXlsxFile from "read-excel-file/node";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function normalizeDatabaseConnectionString(value) {
  const raw = String(value || "").trim();
  const extracted = raw.match(/postgres(?:ql)?:\/\/[^\s'"]+/i)?.[0];
  return extracted || raw.replace(/^(['"])(.*)\1$/, "$2").trim();
}

const databaseUrl = normalizeDatabaseConnectionString(process.env.DATABASE_URL);
const configuredDataFile = String(process.env.DATA_FILE || "").trim();
const configuredDataDir = String(process.env.DATA_DIR || "").trim();
const storeFile = configuredDataFile ? path.resolve(configuredDataFile) : path.join(configuredDataDir ? path.resolve(configuredDataDir) : path.join(root, "data"), "store.json");
const storeBackupFile = `${storeFile}.backup`;
const postgresStoreConfigured = Boolean(databaseUrl);
const durableStoreConfigured = Boolean(postgresStoreConfigured || configuredDataFile || configuredDataDir);
const dataStoreKind = postgresStoreConfigured ? "postgres" : durableStoreConfigured ? "persistent_file" : "local_file";
const configuredPoolSize = Number(process.env.DATABASE_POOL_SIZE || 5);
const postgresPool = postgresStoreConfigured
  ? new Pool({
      connectionString: databaseUrl,
      ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
      max: Number.isFinite(configuredPoolSize) ? Math.max(1, Math.min(20, configuredPoolSize)) : 5,
      connectionTimeoutMillis: 7_500,
      idleTimeoutMillis: 30_000,
      allowExitOnIdle: true
    })
  : null;
const POSTGRES_STORE_TABLE = "public.constrava_app_store_v2";
const STORE_VERSION = Symbol("constravaStoreVersion");
const PORT = Number(process.env.PORT || 3000);
const ORIGIN = process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`;
const COOKIE_NAME = "constrava_session";
const DEV_EMAIL = "constrava@constravaai.com";
const DEV_LOGIN_KEY_ENV = "DEV_LOGIN_KEY";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const OPENAI_API_KEY_ENV = "OPENAI_API_KEY";
const RELEVANCE_MODEL = process.env.CONSTRAVA_RELEVANCE_MODEL || "gpt-5.6-luna";
const RECORD_MODEL = process.env.CONSTRAVA_RECORD_MODEL || "gpt-5.6-terra";
const EMAIL_TOKEN_KEY_ENV = "EMAIL_TOKEN_ENCRYPTION_KEY";
const EMAIL_SYNC_INTERVAL_MS = Math.max(30_000, Number(process.env.EMAIL_SYNC_INTERVAL_MS || 60_000));
const AUTO_COMMIT_MIN_CONFIDENCE = 0.9;
const HIGH_CONFIDENCE_MIN_CONFIDENCE = 0.97;
const EMAIL_AUTOMATION_POLICIES = new Set(["off", "draft_90", "draft_97"]);
const DEFAULT_EMAIL_TIME_ZONE = process.env.CONSTRAVA_DEFAULT_TIME_ZONE || "UTC";
const MAX_JSON_BODY_BYTES = 2 * 1024 * 1024;
const MAX_FILE_UPLOAD_BYTES = 5 * 1024 * 1024;
const MAX_FILE_UPLOAD_BODY_BYTES = 7 * 1024 * 1024;
const MAX_EXTRACTED_FILE_CHARS = 60_000;
const FILE_UPLOAD_EXTENSIONS = new Set([".txt", ".md", ".csv", ".tsv", ".json", ".pdf", ".docx", ".xlsx"]);

function emailAutomationPolicy(value) {
  const normalized = clean(value).toLowerCase();
  if (normalized === "review") return "off";
  if (normalized === "auto" || normalized === "standard") return "draft_90";
  if (normalized === "high_confidence") return "draft_97";
  return EMAIL_AUTOMATION_POLICIES.has(normalized) ? normalized : "off";
}

const id = (prefix) => `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
const clean = (value) => String(value || "").replace(/\s+/g, " ").trim();
const clamp = (value) => Math.max(0, Math.min(100, Number(value) || 0));
const esc = (value) => String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[char]));

function isSecure(req) {
  return String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https" || ORIGIN.startsWith("https://");
}

function sessionCookie(req, sessionId, clear = false) {
  const secure = isSecure(req) ? "; Secure" : "";
  if (clear) return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=0`;
  return `${COOKIE_NAME}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${SESSION_MAX_AGE_SECONDS}`;
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const index = part.indexOf("=");
    return [decodeURIComponent(index >= 0 ? part.slice(0, index) : part), decodeURIComponent(index >= 0 ? part.slice(index + 1) : "")];
  }));
}

function baseRecord(type, title, fields = {}, priorityScore = 40, tags = [], workspaceId = "demo") {
  const now = new Date().toISOString();
  return {
    id: id(type.toLowerCase()),
    workspaceId,
    type,
    title,
    status: type === "Task" || type === "Deal" ? "open" : "active",
    priorityScore,
    priorityReasons: ["Seeded workspace context"],
    tags,
    fields,
    relationships: [],
    sourceIds: ["source_manual"],
    createdAt: now,
    updatedAt: now,
    metadata: {}
  };
}

function starterRecords(workspaceId = "demo") {
  return [
    baseRecord("Company", "Green Valley Roofing", { name: "Green Valley Roofing", industry: "Home services" }, 82, ["high intent"], workspaceId),
    baseRecord("Person", "John Parker", { email: "john@greenvalley.example", companyName: "Green Valley Roofing" }, 76, ["needs follow-up"], workspaceId),
    baseRecord("Deal", "Scheduling app quote", { value: 4000, stage: "qualified" }, 90, ["budget mentioned"], workspaceId),
    baseRecord("Task", "Follow up with Green Valley Roofing", { taskType: "email", dueDate: "" }, 88, ["needs follow-up"], workspaceId),
    baseRecord("Deal", "Scheduling app opportunity", { companyName: "Green Valley Roofing", value: 4000, stage: "new" }, 78, ["quote requested"], workspaceId),
    baseRecord("Note", "Original sales note", { body: "Customer needs a simple scheduling workflow and follow-up reminders." }, 52, ["context"], workspaceId)
  ];
}

function seed() {
  return {
    sources: [
      { id: "source_manual", workspaceId: "demo", name: "Manual Notes", type: "manual_note", status: "connected", metadata: {} },
      { id: "source_website", workspaceId: "demo", name: "Website Contact Form", type: "website_form", status: "connected", metadata: { siteId: "site_demo" } },
      { id: "source_email", workspaceId: "demo", name: "Email Inbox", type: "email", status: "ready_to_connect", metadata: {} },
      { id: "source_site", workspaceId: "demo", name: "External Website", type: "website", status: "ready_to_connect", metadata: {} }
    ],
    records: starterRecords("demo"),
    events: [{ id: id("event"), workspaceId: "demo", type: "page_view", siteId: "site_demo", sessionId: "sample", sourceUrl: "/", referrer: "direct", metadata: {}, createdAt: new Date().toISOString() }],
    plans: [],
    ingestionEvents: [],
    formConnections: [],
    emailConnections: [],
    googleAccounts: [],
    microsoftAccounts: [],
    calendarConnections: [],
    businessConnections: [],
    messagingConnections: [],
    websiteConnections: [],
    identityEntities: [],
    identityIdentifiers: [],
    identityMentions: [],
    identityRelationships: [],
    identityRecordLinks: [],
    identityReconciliation: {},
    reports: [],
    workspaces: [{ id: "demo", name: "Demo workspace", ownerUserId: "", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }],
    workspaceMembers: [],
    workspaceInvitations: [],
    users: [],
    sessions: []
  };
}

function defaultProjectName(user) {
  const name = clean(user?.name || user?.email?.split("@")[0] || "My");
  return name.toLowerCase().endsWith("s") ? `${name}' CRM` : `${name}'s CRM`;
}

function ensureWorkspaceProject(storeData, user) {
  storeData.workspaces ||= [];
  storeData.workspaceMembers ||= [];
  storeData.workspaceInvitations ||= [];
  if (!user.workspaceId) user.workspaceId = `workspace_${user.id}`;
  let workspace = storeData.workspaces.find((entry) => entry.id === user.workspaceId);
  if (!workspace) {
    const now = new Date().toISOString();
    workspace = { id: user.workspaceId, name: defaultProjectName(user), ownerUserId: user.id, createdAt: user.createdAt || now, updatedAt: now };
    storeData.workspaces.push(workspace);
  }
  if (!workspace.ownerUserId) workspace.ownerUserId = user.id;
  if (!storeData.workspaceMembers.some((entry) => entry.workspaceId === workspace.id && entry.userId === user.id)) {
    storeData.workspaceMembers.push({ id: id("member"), workspaceId: workspace.id, userId: user.id, role: workspace.ownerUserId === user.id ? "owner" : "member", status: "active", joinedAt: user.createdAt || new Date().toISOString(), lastOpenedAt: "" });
  }
  return workspace;
}

function ensureUserWorkspace(storeData, user) {
  ensureWorkspaceProject(storeData, user);
  acceptPendingInvitations(storeData, user);
  if (!storeData.records.some((record) => record.workspaceId === user.workspaceId)) storeData.records.push(...starterRecords(user.workspaceId));
}

function acceptPendingInvitations(storeData, user) {
  storeData.workspaceInvitations ||= [];
  const email = clean(user?.email).toLowerCase();
  if (!email) return [];
  const accepted = [];
  for (const invitation of storeData.workspaceInvitations.filter((entry) => entry.email === email && entry.status === "pending")) {
    const project = storeData.workspaces.find((entry) => entry.id === invitation.workspaceId);
    if (!project) continue;
    let membership = storeData.workspaceMembers.find((entry) => entry.workspaceId === project.id && entry.userId === user.id);
    const now = new Date().toISOString();
    if (membership) {
      membership.status = "active";
      if (membership.role !== "owner") membership.role = invitation.role || "member";
    } else {
      membership = { id: id("member"), workspaceId: project.id, userId: user.id, role: invitation.role || "member", status: "active", joinedAt: now, lastOpenedAt: "" };
      storeData.workspaceMembers.push(membership);
    }
    invitation.status = "accepted";
    invitation.userId = user.id;
    invitation.acceptedAt = now;
    invitation.updatedAt = now;
    project.updatedAt = now;
    accepted.push({ invitation, membership, project });
  }
  return accepted;
}

function ensureDeveloperAccount(storeData) {
  if (!process.env[DEV_LOGIN_KEY_ENV]) return null;
  let user = storeData.users.find((candidate) => candidate.email === DEV_EMAIL);
  if (!user) {
    user = { id: "user_developer", email: DEV_EMAIL, name: "Constrava Developer", role: "developer", workspaceId: "workspace_developer", createdAt: new Date().toISOString(), authProvider: DEV_LOGIN_KEY_ENV };
    storeData.users.push(user);
  }
  user.role = "developer";
  user.authProvider = DEV_LOGIN_KEY_ENV;
  user.workspaceId ||= "workspace_developer";
  ensureUserWorkspace(storeData, user);
  return user;
}

function normalize(storeData) {
  const fresh = seed();
  storeData.sources ||= fresh.sources;
  storeData.records ||= [];
  storeData.draftRecords ||= [];
  storeData.events ||= [];
  storeData.plans ||= [];
  storeData.ingestionEvents ||= [];
  storeData.formConnections ||= [];
  storeData.emailConnections ||= [];
  storeData.googleAccounts ||= [];
  storeData.microsoftAccounts ||= [];
  storeData.calendarConnections ||= [];
  storeData.businessConnections ||= [];
  storeData.messagingConnections ||= [];
  storeData.websiteConnections ||= [];
  storeData.identityEntities ||= [];
  storeData.identityIdentifiers ||= [];
  storeData.identityMentions ||= [];
  storeData.identityRelationships ||= [];
  storeData.identityRecordLinks ||= [];
  storeData.identityReconciliation ||= {};
  storeData.reports ||= [];
  storeData.workspaces ||= fresh.workspaces;
  storeData.workspaceMembers ||= [];
  storeData.workspaceInvitations ||= [];
  storeData.users ||= [];
  storeData.sessions ||= [];
  for (const connection of storeData.emailConnections) {
    connection.automationPolicy = emailAutomationPolicy(connection.automationPolicy);
    connection.timeZone = normalizeTimeZone(connection.timeZone || connection.scope?.timeZone || DEFAULT_EMAIL_TIME_ZONE);
    connection.scope = { ...(connection.scope || {}), timeZone: connection.timeZone };
    connection.accountUserId ||= storeData.users.find((user) => user.workspaceId === connection.workspaceId)?.id || "";
    connection.syncStats ||= { processed: 0, drafted: 0, committed: 0 };
    connection.syncStats.drafted ||= 0;
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId);
    if (source && connection.status === "active" && connection.authorizationStatus === "authorized") source.status = "connected";
  }
  for (const account of storeData.googleAccounts) {
    account.accountUserId ||= storeData.users.find((user) => user.workspaceId === account.workspaceId)?.id || "";
    account.status ||= account.oauthTokens ? "active" : "draft";
    account.authorizationStatus ||= account.oauthTokens ? "authorized" : "ready";
    account.enabledResources ||= { gmail: true, calendar: true };
    account.oauthClient ||= "calendar";
    account.selectedApps = Array.isArray(account.selectedApps) ? [...new Set(account.selectedApps.map(clean).filter((appId) => GOOGLE_APP_CATALOG.some((app) => app.id === appId)))] : googleAuthorizedApps(account);
    account.appScan ||= { status: "not_scanned", scannedAt: "", apps: [] };
  }
  for (const account of storeData.microsoftAccounts) {
    account.accountUserId ||= storeData.users.find((user) => user.workspaceId === account.workspaceId)?.id || "";
    account.status ||= account.oauthTokens ? "active" : "draft";
    account.authorizationStatus ||= account.oauthTokens ? "authorized" : "ready";
    account.oauthClient ||= "outlook";
    account.selectedApps = Array.isArray(account.selectedApps) ? [...new Set(account.selectedApps.map(clean).filter((appId) => MICROSOFT_APP_CATALOG.some((app) => app.id === appId)))] : microsoftAuthorizedApps(account);
    account.appScan ||= { status: "not_scanned", scannedAt: "", apps: [] };
  }
  for (const connection of storeData.calendarConnections) {
    connection.accountUserId ||= storeData.users.find((user) => user.workspaceId === connection.workspaceId)?.id || "";
    connection.sync ||= { direction: "read_only", window: "upcoming_90", createTasks: true, attachNotes: true, includeDeclined: false, includePrivate: false };
    connection.syncStats ||= { processed: 0, drafted: 0, ignored: 0 };
    connection.calendarSyncTokens ||= {};
    connection.availableCalendars = Array.isArray(connection.availableCalendars) ? connection.availableCalendars.map(calendarOptionSafe).filter((entry) => entry.id).slice(0, 50) : [];
    connection.selectedCalendarIds = Array.isArray(connection.selectedCalendarIds) ? [...new Set(connection.selectedCalendarIds.map(clean).filter(Boolean))].slice(0, 50) : [];
    connection.calendarSelectionConfigured = Boolean(connection.calendarSelectionConfigured);
    connection.authorizationStatus ||= "credentials_required";
    connection.oauthRedirectUri ||= "";
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId);
    if (source && connection.status === "active" && connection.authorizationStatus === "authorized") source.status = "connected";
  }
  for (const connection of storeData.businessConnections) {
    connection.accountUserId ||= storeData.users.find((user) => user.workspaceId === connection.workspaceId)?.id || "";
    connection.scope ||= { contacts: true, companies: true, deals: true, tasks: false, notes: false, includeArchived: false };
    connection.mapping ||= { personName: "name", personEmail: "email", companyName: "company", dealName: "deal" };
    connection.sync ||= { direction: "read_only", frequency: "manual", conflictStrategy: "review" };
    connection.authorizationStatus ||= "credentials_required";
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId);
    if (source && connection.status === "active" && connection.authorizationStatus === "authorized") source.status = "connected";
  }
  for (const connection of storeData.messagingConnections) {
    connection.accountUserId ||= storeData.users.find((user) => user.workspaceId === connection.workspaceId)?.id || "";
    connection.scope ||= { publicChannels: true, privateChannels: false, directMessages: false, supportConversations: true, smsInbound: true };
    connection.rules ||= { direction: "read_only", frequency: "manual", createContacts: true, createTasks: true, attachNotes: true, automationPolicy: "review" };
    connection.authorizationStatus ||= "credentials_required";
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId);
    if (source && connection.status === "active" && connection.authorizationStatus === "authorized") source.status = "connected";
  }
  for (const source of fresh.sources) if (!storeData.sources.some((entry) => entry.id === source.id)) storeData.sources.push(source);
  for (const collection of [storeData.records, storeData.draftRecords, storeData.events, storeData.plans, storeData.reports]) for (const item of collection) item.workspaceId ||= "demo";
  if (!storeData.records.some((record) => record.workspaceId === "demo")) storeData.records.push(...starterRecords("demo"));
  if (!storeData.workspaces.some((workspace) => workspace.id === "demo")) storeData.workspaces.push(fresh.workspaces[0]);
  for (const user of storeData.users) ensureWorkspaceProject(storeData, user);
  ensureDeveloperAccount(storeData);
  return storeData;
}

const IDENTITY_VERSION = 1;

function identityName(value) {
  return clean(value).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
}

function identityEmail(value) {
  const match = String(value || "").toLowerCase().match(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}/);
  return match?.[0] || "";
}

function identityPhone(value) {
  const digits = String(value || "").replace(/\D/g, "");
  return digits.length >= 7 ? digits.slice(-15) : "";
}

function identityDomain(value) {
  const email = identityEmail(value);
  if (email) return email.split("@")[1];
  try { return new URL(/^https?:\/\//i.test(clean(value)) ? clean(value) : `https://${clean(value)}`).hostname.replace(/^www\./, "").toLowerCase(); } catch { return ""; }
}

function identityFingerprint(record) {
  return crypto.createHash("sha256").update(JSON.stringify([IDENTITY_VERSION, record.type, record.title, record.fields || {}, record.updatedAt || ""])).digest("base64url");
}

function identityIdentifiersFor(type, details) {
  const identifiers = [];
  if (type === "Person") {
    const email = identityEmail(details.email);
    const phone = identityPhone(details.phone);
    if (email) identifiers.push({ type: "email", value: email });
    if (phone) identifiers.push({ type: "phone", value: phone });
  }
  if (type === "Company") {
    const domain = identityDomain(details.website || details.domain || details.contactEmail);
    if (domain) identifiers.push({ type: "domain", value: domain });
  }
  return identifiers;
}

function upsertIdentityMention(storeData, workspaceId, entityId, mention) {
  const key = clean(mention.key || `${mention.sourceKind}:${mention.sourceId}:${identityName(mention.name)}`);
  let row = storeData.identityMentions.find((entry) => entry.workspaceId === workspaceId && entry.key === key);
  if (!row) {
    row = { id: id("mention"), workspaceId, key, entityId: entityId || "", entityType: mention.entityType, name: clean(mention.name), sourceKind: clean(mention.sourceKind), sourceId: clea…74966 tokens truncated…const requestedAutomationPolicy = emailAutomationPolicy(body.automationPolicy);
    const timeZone = normalizeTimeZone(body.timeZone || body.scope?.timeZone || DEFAULT_EMAIL_TIME_ZONE);
    const connection = { id: id("email"), accountUserId: ctx.user?.id || "", workspaceId: ctx.workspaceId, sourceId: id("source_email"), name: clean(body.name || "Connected inbox"), emailAddress: clean(body.emailAddress).toLowerCase(), provider, status: "draft", authorizationStatus: authorizationReady ? "ready" : "credentials_required", authorizationReady, scope: { ...(body.scope || {}), timeZone }, timeZone, automationPolicy: requestedAutomationPolicy, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), activatedAt: "", authorizedAt: "", syncCursor: "", lastSyncAt: "", lastSyncError: "", syncStats: { processed: 0, drafted: 0, committed: 0 }, lastMessageAt: "", testEventId: "" };
    storeData.emailConnections.push(connection);
    storeData.sources.push({ id: connection.sourceId, accountUserId: ctx.user?.id || "", workspaceId: ctx.workspaceId, name: connection.name, type: "email", status: "draft", metadata: { connectionId: connection.id, provider: connection.provider, emailAddress: connection.emailAddress, automationPolicy: connection.automationPolicy, timeZone: connection.timeZone } });
    await saveStore(storeData);
    return send(res, 201, { connection });
  }
  const emailGoogleLinkMatch = route.match(/^\/api\/email-connections\/([^/]+)\/link-google$/);
  if (req.method === "POST" && emailGoogleLinkMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailGoogleLinkMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    if (connection.provider !== "gmail") return send(res, 400, { error: "Only Gmail connections can use a connected Google account." });
    const body = await readBody(req);
    const account = storeData.googleAccounts.find((entry) => entry.id === clean(body.googleAccountId) && entry.workspaceId === ctx.workspaceId && entry.status === "active" && entry.authorizationStatus === "authorized");
    if (!account) return send(res, 409, { error: "Connect and authorize the Google account first." });
    connection.googleAccountId = account.id;
    connection.oauthTokens = "";
    connection.emailAddress = account.email;
    connection.authorizationReady = true;
    connection.authorizationStatus = "authorized";
    connection.lastSyncError = "";
    connection.updatedAt = new Date().toISOString();
    account.enabledResources = { ...(account.enabledResources || {}), gmail: true };
    account.updatedAt = connection.updatedAt;
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId && entry.workspaceId === ctx.workspaceId);
    if (source) source.metadata = { ...(source.metadata || {}), googleAccountId: account.id, emailAddress: connection.emailAddress };
    await saveStore(storeData);
    const { oauthTokens, oauthStateHash, ...safeConnection } = connection;
    return send(res, 200, { connection: safeConnection, account: googleAccountSafe(account, storeData) });
  }
  const emailMicrosoftLinkMatch = route.match(/^\/api\/email-connections\/([^/]+)\/link-microsoft$/);
  if (req.method === "POST" && emailMicrosoftLinkMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailMicrosoftLinkMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    if (connection.provider !== "outlook") return send(res, 400, { error: "Only Outlook connections can use a connected Microsoft account." });
    const body = await readBody(req);
    const account = storeData.microsoftAccounts.find((entry) => entry.id === clean(body.microsoftAccountId) && entry.workspaceId === ctx.workspaceId && entry.status === "active" && entry.authorizationStatus === "authorized");
    if (!account) return send(res, 409, { error: "Connect and authorize the Microsoft account first." });
    if (!microsoftAuthorizedApps(account).includes("mail")) return send(res, 409, { error: "Approve Outlook Mail access for this Microsoft account first." });
    connection.microsoftAccountId = account.id;
    connection.oauthTokens = "";
    connection.emailAddress = account.email;
    connection.authorizationReady = true;
    connection.authorizationStatus = "authorized";
    connection.lastSyncError = "";
    connection.updatedAt = new Date().toISOString();
    account.enabledResources = { ...(account.enabledResources || {}), mail: true };
    account.updatedAt = connection.updatedAt;
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId && entry.workspaceId === ctx.workspaceId);
    if (source) source.metadata = { ...(source.metadata || {}), microsoftAccountId: account.id, emailAddress: connection.emailAddress };
    await saveStore(storeData);
    const { oauthTokens, oauthStateHash, ...safeConnection } = connection;
    return send(res, 200, { connection: safeConnection, account: microsoftAccountSafe(account, storeData) });
  }
  const emailImapMatch = route.match(/^\/api\/email-connections\/([^/]+)\/imap$/);
  if (req.method === "POST" && emailImapMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailImapMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    if (connection.provider !== "imap") return send(res, 400, { error: "This inbox does not use IMAP." });
    if (!emailTokenKey()) return send(res, 503, { error: `${EMAIL_TOKEN_KEY_ENV} is not configured.` });
    const body = await readBody(req);
    const credentials = { host: clean(body.host), port: Number(body.port || 993), username: clean(body.username || connection.emailAddress), password: String(body.appPassword || body.password || "") };
    if (!credentials.password) return send(res, 400, { error: "Enter the app password provided by your email provider." });
    await withImapSession(credentials, async () => true);
    connection.oauthTokens = encryptEmailTokens(credentials);
    connection.authorizationStatus = "authorized";
    connection.authorizationReady = true;
    connection.imapHost = credentials.host;
    connection.imapPort = credentials.port;
    connection.updatedAt = new Date().toISOString();
    await saveStore(storeData);
    return send(res, 200, { connection: { ...connection, oauthTokens: undefined }, verified: true });
  }
  const emailTestMatch = route.match(/^\/api\/email-connections\/([^/]+)\/test$/);
  if (req.method === "POST" && emailTestMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailTestMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    const body = await readBody(req);
    const emailPayload = { from: clean(body.from), to: clean(body.to || connection.emailAddress), subject: clean(body.subject), body: clean(body.body), threadId: clean(body.threadId), messageId: clean(body.messageId), receivedAt: clean(body.receivedAt || new Date().toISOString()) };
    const result = await processIngestion(storeData, { workspaceId: ctx.workspaceId, connection, payload: emailPayload, kind: "email", providerSubmissionId: emailPayload.messageId || id("test_message"), stageDrafts: false });
    connection.lastMessageAt = new Date().toISOString();
    connection.testEventId = result.event.id;
    await saveStore(storeData);
    return send(res, 200, { accepted: true, ...result });
  }
  const emailAuthorizeMatch = route.match(/^\/api\/email-connections\/([^/]+)\/authorize$/);
  if (req.method === "POST" && emailAuthorizeMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailAuthorizeMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    const config = emailProviderConfig(connection.provider);
    if (!config?.clientId || !config?.clientSecret) return send(res, 503, { error: `OAuth credentials are not configured for ${connection.provider}.` });
    if (!emailTokenKey()) return send(res, 503, { error: `${EMAIL_TOKEN_KEY_ENV} is not configured.` });
    const state = crypto.randomBytes(32).toString("base64url");
    connection.oauthStateHash = hashToken(state);
    connection.oauthStateExpiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
    connection.updatedAt = new Date().toISOString();
    const authorizeUrl = new URL(config.authorizeUrl);
    authorizeUrl.searchParams.set("client_id", config.clientId);
    authorizeUrl.searchParams.set("redirect_uri", `${ORIGIN}/api/email/oauth/callback`);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("scope", connection.provider === "gmail" ? GOOGLE_SHARED_SCOPES.join(" ") : config.scope);
    authorizeUrl.searchParams.set("state", state);
    if (connection.provider === "gmail") {
      authorizeUrl.searchParams.set("access_type", "offline");
      authorizeUrl.searchParams.set("prompt", "consent");
      authorizeUrl.searchParams.set("include_granted_scopes", "false");
      if (connection.emailAddress) authorizeUrl.searchParams.set("login_hint", connection.emailAddress);
    }
    await saveStore(storeData);
    return send(res, 200, { authorizeUrl: authorizeUrl.toString() });
  }
  const emailSyncMatch = route.match(/^\/api\/email-connections\/([^/]+)\/sync$/);
  if (req.method === "POST" && emailSyncMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailSyncMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    try {
      const result = await syncEmailConnection(storeData, connection);
      await saveStore(storeData);
      return send(res, 200, { connection: { ...connection, oauthTokens: undefined }, ...result });
    } catch (error) {
      connection.lastSyncAt = new Date().toISOString();
      const normalizedError = normalizeEmailSyncError(connection, error);
      await saveStore(storeData);
      throw normalizedError;
    }
  }
  const emailActivateMatch = route.match(/^\/api\/email-connections\/([^/]+)\/activate$/);
  if (req.method === "POST" && emailActivateMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailActivateMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    if (!connection.testEventId) return send(res, 409, { error: "Process a test email before activation." });
    const body = await readBody(req);
    connection.scope = body.scope || connection.scope;
    connection.automationPolicy = emailAutomationPolicy(body.automationPolicy ?? connection.automationPolicy);
    connection.status = connection.authorizationStatus === "authorized" ? "active" : "ready_to_authorize";
    connection.activatedAt = new Date().toISOString();
    connection.updatedAt = connection.activatedAt;
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId);
    if (source) source.status = connection.status === "active" ? "connected" : "ready_to_authorize";
    await saveStore(storeData);
    return send(res, 200, { connection: { ...connection, oauthTokens: undefined } });
  }
  if (req.method === "POST" && route === "/api/records/plan") {
    const plan = await makePlan(await readBody(req), ctx.workspaceId, storeData);
    storeData.plans.push(plan);
    reconcilePlanIdentities(storeData, plan, ctx.workspaceId);
    const drafts = stagePlanDrafts(storeData, plan, ctx.workspaceId);
    await saveStore(storeData);
    return send(res, 200, { plan, drafts });
  }
  if (req.method === "POST" && route === "/api/records/drafts/update") {
    const draft = updateDraftRecord(storeData, await readBody(req), ctx.workspaceId);
    await saveStore(storeData);
    return send(res, 200, { record: draft });
  }
  if (req.method === "POST" && route === "/api/records/drafts/publish") {
    const body = await readBody(req);
    const record = publishDraftRecord(storeData, clean(body.id), ctx.workspaceId);
    await saveStore(storeData);
    return send(res, 200, { record });
  }
  if (req.method === "POST" && route === "/api/records/commit") {
    const body = await readBody(req);
    const result = commitPlan(storeData, body.planId, body.actionIds, ctx.workspaceId);
    await saveStore(storeData);
    return send(res, 200, result);
  }
  if (req.method === "POST" && route === "/api/analytics/events") {
    const body = await readBody(req);
    const event = { id: id("event"), workspaceId: ctx.workspaceId, type: clean(body.type || "custom"), siteId: clean(body.siteId || "site_demo"), sessionId: clean(body.sessionId || id("session")), sourceUrl: clean(body.sourceUrl || ""), referrer: clean(body.referrer || ""), metadata: body.metadata || {}, createdAt: new Date().toISOString() };
    storeData.events.push(event);
    await saveStore(storeData);
    return send(res, 202, { accepted: true, eventId: event.id });
  }
  if (req.method === "POST" && route === "/api/sources/form") {
    const body = await readBody(req);
    const result = await processIngestion(storeData, { workspaceId: ctx.workspaceId, connection: null, payload: body.fields || { rawText: body.rawText || JSON.stringify(body) }, providerSubmissionId: body.providerSubmissionId || "" });
    await saveStore(storeData);
    return send(res, 202, { accepted: true, ...result });
  }
  if (req.method === "POST" && route === "/api/file-uploads/analyze") {
    const upload = await extractUploadedFile(await readBody(req, MAX_FILE_UPLOAD_BODY_BYTES));
    return send(res, 200, {
      analysis: upload.analysis,
      limits: { maxFileBytes: MAX_FILE_UPLOAD_BYTES, maxExtractedCharacters: MAX_EXTRACTED_FILE_CHARS },
      privacy: "The original file is not saved. Only approved CRM drafts and their extracted source text are stored."
    });
  }
  if (req.method === "POST" && ["/api/file-uploads/plan", "/api/uploads/import"].includes(route)) {
    const body = await readBody(req, MAX_FILE_UPLOAD_BODY_BYTES);
    let upload;
    if (route === "/api/uploads/import" && !body.contentBase64) {
      const legacyText = String(body.csv || body.text || "").split(/\r?\n/).slice(0, 100).join("\n").trim();
      if (!legacyText) throw fileUploadError("Add file content before creating records.");
      upload = { text: legacyText.slice(0, MAX_EXTRACTED_FILE_CHARS), fileName: clean(body.name || "Imported text"), extension: ".txt", size: Buffer.byteLength(legacyText), analysis: { fileName: clean(body.name || "Imported text"), format: "TXT", contentKind: "document", characters: legacyText.length, pages: 0, rowCount: 0, columnCount: 0, headers: [], previewRows: [], preview: legacyText.slice(0, 4_000), truncated: legacyText.length > MAX_EXTRACTED_FILE_CHARS, warnings: [], signals: { emailCount: 0, dateCount: 0, valueCount: 0 } } };
    } else upload = await extractUploadedFile(body);
    const source = ensureFileUploadSource(storeData, ctx.workspaceId, ctx.user?.id || "");
    const plan = await makePlan({ kind: "file_upload", sourceId: source.id, rawText: upload.text, payload: { fileName: upload.fileName, fileType: upload.extension.slice(1), fileSize: upload.size } }, ctx.workspaceId, storeData);
    storeData.plans.push(plan);
    reconcilePlanIdentities(storeData, plan, ctx.workspaceId);
    const drafts = stagePlanDrafts(storeData, plan, ctx.workspaceId);
    source.metadata.importedFiles = Number(source.metadata.importedFiles || 0) + 1;
    source.metadata.lastFileName = upload.fileName;
    source.metadata.lastImportedAt = new Date().toISOString();
    await saveStore(storeData);
    return send(res, 200, { plan, drafts, analysis: upload.analysis, reviewUrl: "/dashboard#crm-review" });
  }
  if (req.method === "POST" && route === "/api/search/natural") {
    const body = await readBody(req);
    const q = clean(body.query).toLowerCase();
    return send(res, 200, { plan: { q, explanation: "Converted plain English into safe filters." }, records: filtered(storeData, { q, type: /deal|quote/.test(q) ? "Deal" : /task|follow/.test(q) ? "Task" : "" }, ctx.workspaceId) });
  }
  if (req.method === "POST" && route === "/api/reports/generate") {
    const sum = dashboardSummary(storeData, ctx.workspaceId);
    const content = {
      title: "Business Activity Report",
      factualSummary: [`${sum.metrics.newLeads} lead/contact records are tracked.`, `${sum.metrics.activeDeals} active deals represent $${sum.metrics.revenueOpportunity.toLocaleString()} in opportunity.`, `${sum.metrics.trafficEvents} analytics events have been captured.`],
      recommendations: sum.recommendedActions.map((entry) => `${entry.title}: ${entry.reason}`)
    };
    const report = { id: id("report"), workspaceId: ctx.workspaceId, title: content.title, content, createdAt: new Date().toISOString() };
    storeData.reports.push(report);
    await saveStore(storeData);
    return send(res, 200, { report });
  }
  return send(res, 404, { error: "API route not found" });
}

const webServer = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, ORIGIN);
    const route = url.pathname.replace(/\/+$/, "") || "/";
    if (route.startsWith("/api/")) return await api(req, res, url, route);
    if (route === "/demo") return html(res, appPage({ demo: true }));
    if (["/signin", "/login"].includes(route)) return html(res, signInPage());
    if (["/projects", "/workspaces"].includes(route)) {
      const storeData = await loadStore();
      const user = currentUser(req, storeData);
      if (!user) return redirect(res, "/signin");
      const projects = projectsForUser(storeData, user.id);
      await saveStore(storeData);
      return html(res, projectSelectionPage({ user, projects, storeData }));
    }
    if (["/dashboard", "/app"].includes(route)) {
      const storeData = await loadStore();
      const user = currentUser(req, storeData);
      if (!user) return redirect(res, "/signin");
      const ctx = activeWorkspaceContext(req, storeData);
      if (!ctx) return redirect(res, "/projects");
      await saveStore(storeData);
      return html(res, appPage({ demo: false, user, project: ctx.project }));
    }
    return html(res, withPublicMobileFit(withPublicPaletteLayout(publicPage())));
  } catch (error) {
    send(res, error.status || 500, {
      error: error.message,
      ...(error.code ? { code: error.code } : {}),
      ...(error.databaseErrorCode ? { databaseErrorCode: error.databaseErrorCode } : {})
    });
  }
});
if (process.env.CONSTRAVA_GENERATE_ONLY !== "1") {
  webServer.listen(PORT, () => {
    console.log(`Constrava is running at ${ORIGIN}`);
    if (postgresPool) void ensurePostgresStore().catch(() => {});
  });
}

let emailSyncRunning = false;
async function syncActiveEmailConnections() {
  if (emailSyncRunning || !emailTokenKey()) return;
  emailSyncRunning = true;
  try {
    const storeData = await loadStore();
    for (const connection of storeData.emailConnections.filter((entry) => entry.status === "active" && (entry.oauthTokens || linkedGoogleAccount(storeData, entry)))) {
      try { await syncEmailConnection(storeData, connection); }
      catch (error) { connection.lastSyncAt = new Date().toISOString(); normalizeEmailSyncError(connection, error); }
    }
    await saveStore(storeData);
  } finally {
    emailSyncRunning = false;
  }
}
const emailSyncTimer = setInterval(syncActiveEmailConnections, EMAIL_SYNC_INTERVAL_MS);
emailSyncTimer.unref();

