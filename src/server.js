import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import tls from "node:tls";
import dns from "node:dns/promises";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const storeFile = path.join(root, "data", "store.json");
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
    baseRecord("Intake", "Website request about scheduling app", { rawText: "Green Valley Roofing asked about a scheduling app quote with a $4,000 budget." }, 78, ["quote requested"], workspaceId),
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
    reports: [],
    users: [],
    sessions: []
  };
}

function ensureUserWorkspace(storeData, user) {
  if (!user.workspaceId) user.workspaceId = `workspace_${user.id}`;
  if (!storeData.records.some((record) => record.workspaceId === user.workspaceId)) storeData.records.push(...starterRecords(user.workspaceId));
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
  storeData.reports ||= [];
  storeData.users ||= [];
  storeData.sessions ||= [];
  for (const source of fresh.sources) if (!storeData.sources.some((entry) => entry.id === source.id)) storeData.sources.push(source);
  for (const collection of [storeData.records, storeData.draftRecords, storeData.events, storeData.plans, storeData.reports]) for (const item of collection) item.workspaceId ||= "demo";
  if (!storeData.records.some((record) => record.workspaceId === "demo")) storeData.records.push(...starterRecords("demo"));
  ensureDeveloperAccount(storeData);
  return storeData;
}

async function loadStore() {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });
  try {
    return normalize(JSON.parse(await fs.readFile(storeFile, "utf8")));
  } catch {
    const fresh = normalize(seed());
    await fs.writeFile(storeFile, `${JSON.stringify(fresh, null, 2)}\n`);
    return fresh;
  }
}

async function saveStore(storeData) {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });
  await fs.writeFile(storeFile, `${JSON.stringify(normalize(storeData), null, 2)}\n`);
}

async function readBody(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return { rawText: raw }; }
}

function send(res, status, data, headers = {}) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(data, null, 2));
}

function html(res, markup) {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(markup);
}

function redirect(res, location) {
  res.writeHead(302, { location, "cache-control": "no-store" });
  res.end();
}

function passwordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(String(password || ""), salt, 32).toString("hex") };
}

function safeEqualText(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, user) {
  if (!user?.passwordSalt || !user?.passwordHash) return false;
  const { hash } = passwordHash(password, user.passwordSalt);
  return safeEqualText(hash, user.passwordHash);
}

function currentUser(req, storeData) {
  const sessionId = parseCookies(req)[COOKIE_NAME];
  if (!sessionId) return null;
  const session = storeData.sessions.find((entry) => entry.id === sessionId && (!entry.expiresAt || entry.expiresAt > new Date().toISOString()));
  if (!session) return null;
  const user = storeData.users.find((entry) => entry.id === session.userId) || null;
  if (user) ensureUserWorkspace(storeData, user);
  return user;
}

function publicUser(user) {
  return user ? { id: user.id, email: user.email, name: user.name, role: user.role || "user", workspaceId: user.workspaceId } : null;
}

function requestContext(req, url, storeData) {
  if (url.searchParams.get("demo") === "1") return { workspaceId: "demo", demo: true, user: null };
  const user = currentUser(req, storeData);
  return user ? { workspaceId: user.workspaceId, demo: false, user } : null;
}

const SENSITIVE_FIELD_PATTERN = /pass(word|code)?|secret|token|credit.?card|card.?number|cvv|cvc|social.?security|\bssn\b|bank.?account|routing.?number/i;

function sanitizeSubmission(value, excludedFields = [], pathName = "submission") {
  if (Array.isArray(value)) return value.slice(0, 100).map((entry, index) => sanitizeSubmission(entry, excludedFields, `${pathName}[${index}]`));
  if (!value || typeof value !== "object") return clean(String(value ?? "")).slice(0, 5000);
  const output = {};
  for (const [key, entry] of Object.entries(value).slice(0, 100)) {
    const fieldPath = `${pathName}.${key}`;
    if (SENSITIVE_FIELD_PATTERN.test(key)) {
      excludedFields.push(fieldPath);
      continue;
    }
    output[clean(key).slice(0, 100)] = sanitizeSubmission(entry, excludedFields, fieldPath);
  }
  return output;
}

function submissionText(payload) {
  return Object.entries(payload || {}).map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`).join("\n").slice(0, 24000);
}

function responseText(response) {
  if (response.output_text) return response.output_text;
  for (const item of response.output || []) for (const content of item.content || []) if (content.type === "output_text" && content.text) return content.text;
  return "";
}

function emailTokenKey() {
  const value = process.env[EMAIL_TOKEN_KEY_ENV];
  return value ? crypto.createHash("sha256").update(value).digest() : null;
}

function encryptEmailTokens(tokens) {
  const key = emailTokenKey();
  if (!key) throw Object.assign(new Error(`${EMAIL_TOKEN_KEY_ENV} is required before connecting a live inbox.`), { status: 503 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(tokens), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString("base64url")).join(".");
}

function decryptEmailTokens(value) {
  const key = emailTokenKey();
  if (!key || !value) return null;
  const [iv, tag, encrypted] = String(value).split(".").map((part) => Buffer.from(part, "base64url"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"));
}

function emailProviderConfig(provider) {
  if (provider === "gmail") return { clientId: process.env.GMAIL_CLIENT_ID, clientSecret: process.env.GMAIL_CLIENT_SECRET, authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth", tokenUrl: "https://oauth2.googleapis.com/token", scope: "openid email https://www.googleapis.com/auth/gmail.readonly" };
  if (provider === "outlook") return { clientId: process.env.MICROSOFT_CLIENT_ID, clientSecret: process.env.MICROSOFT_CLIENT_SECRET, authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token", scope: "openid email offline_access Mail.Read" };
  return null;
}

const GMAIL_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const GMAIL_PERMISSION_MESSAGE = "Google needs permission to read this inbox. Reconnect Google and approve read-only Gmail access.";

function hasGmailReadScope(tokens) {
  if (!tokens?.scope) return true;
  return String(tokens.scope).split(/\s+/).includes(GMAIL_READ_SCOPE);
}

function normalizeEmailSyncError(connection, error) {
  if (connection.provider === "gmail" && /insufficient authentication scopes|insufficient.*scope|insufficient permissions/i.test(error?.message || "")) {
    connection.status = "reauthorization_required";
    connection.authorizationStatus = "reauthorization_required";
    connection.lastSyncError = GMAIL_PERMISSION_MESSAGE;
    return Object.assign(new Error(GMAIL_PERMISSION_MESSAGE), { status: 409 });
  }
  connection.lastSyncError = error?.message || "Could not sync this inbox.";
  return error;
}

function imapQuote(value) {
  return `"${String(value || "").replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\r", "").replaceAll("\n", "")}"`;
}

function imapExchange(socket, tag, command, timeoutMs = 20_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const timeout = setTimeout(() => finish(new Error("The mail server timed out.")), timeoutMs);
    const onData = (chunk) => {
      chunks.push(chunk);
      const value = Buffer.concat(chunks);
      const text = value.toString("latin1");
      const match = text.match(new RegExp(`(?:^|\\r\\n)${tag} (OK|NO|BAD)[^\\r\\n]*`, "i"));
      if (!match) return;
      if (match[1].toUpperCase() !== "OK") return finish(new Error(match[0].trim().replace(`${tag} `, "") || "The mail server rejected the request."));
      finish(null, value);
    };
    const finish = (error, value) => {
      clearTimeout(timeout);
      socket.off("data", onData);
      socket.off("error", finish);
      if (error) reject(error); else resolve(value);
    };
    socket.on("data", onData);
    socket.once("error", finish);
    socket.write(`${tag} ${command}\r\n`);
  });
}

function privateNetworkAddress(address) {
  const value = String(address || "").toLowerCase();
  if (value === "::1" || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80:")) return true;
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 || (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
}

async function withImapSession(credentials, callback) {
  const host = clean(credentials.host).toLowerCase();
  const port = Number(credentials.port || 993);
  if (!host || port !== 993) throw Object.assign(new Error("Use a secure IMAP server on port 993."), { status: 400 });
  const addresses = await dns.lookup(host, { all: true });
  if (!addresses.length || addresses.some((entry) => privateNetworkAddress(entry.address))) throw Object.assign(new Error("The IMAP server must use a public internet address."), { status: 400 });
  const socket = tls.connect({ host: addresses[0].address, port, servername: host, rejectUnauthorized: true });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Could not reach the IMAP server.")), 15_000);
    socket.once("secureConnect", () => { clearTimeout(timeout); resolve(); });
    socket.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  try {
    await imapExchange(socket, "A1", `LOGIN ${imapQuote(credentials.username)} ${imapQuote(credentials.password)}`);
    return await callback(socket);
  } finally {
    try { socket.write("ZZ LOGOUT\r\n"); } catch {}
    socket.end();
  }
}

function decodeTransferBody(body, encoding) {
  const type = clean(encoding).toLowerCase();
  if (type === "base64") {
    try { return Buffer.from(body.replace(/\s/g, ""), "base64").toString("utf8"); } catch { return body; }
  }
  if (type === "quoted-printable") return body.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  return body;
}

function parseImapMessage(raw, uid) {
  const [headerBlock = "", ...bodyParts] = raw.split(/\r?\n\r?\n/);
  const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, " ");
  const header = (name) => unfolded.match(new RegExp(`^${name}:\\s*(.*)$`, "im"))?.[1]?.trim() || "";
  let body = bodyParts.join("\n\n");
  body = decodeTransferBody(body, header("Content-Transfer-Encoding"));
  if (/text\/html/i.test(header("Content-Type"))) body = body.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ");
  const received = new Date(header("Date") || Date.now());
  return { from: header("From"), to: header("To"), subject: header("Subject"), body: clean(body).slice(0, 24000), threadId: header("References") || header("In-Reply-To") || header("Message-ID"), messageId: header("Message-ID") || `imap-${uid}`, receivedAt: Number.isNaN(received.getTime()) ? new Date().toISOString() : received.toISOString(), imapUid: Number(uid) };
}

function imapLiteral(buffer) {
  const marker = buffer.toString("latin1").match(/\{(\d+)\}\r\n/);
  if (!marker) return "";
  const markerIndex = buffer.indexOf(Buffer.from(marker[0], "latin1"));
  const start = markerIndex + Buffer.byteLength(marker[0], "latin1");
  return buffer.subarray(start, start + Number(marker[1])).toString("utf8");
}

async function fetchImapMessages(connection) {
  const credentials = decryptEmailTokens(connection.oauthTokens);
  if (!credentials?.password) throw Object.assign(new Error("Reconnect this IMAP inbox before syncing."), { status: 409 });
  return withImapSession(credentials, async (socket) => {
    await imapExchange(socket, "A2", "SELECT INBOX");
    const startUid = Math.max(1, Number(connection.imapLastUid || 0) + 1);
    const searched = await imapExchange(socket, "A3", `UID SEARCH UID ${startUid}:*`);
    const line = searched.toString("latin1").match(/\* SEARCH([^\r\n]*)/i)?.[1] || "";
    const uids = line.trim().split(/\s+/).filter(Boolean).map(Number).filter(Number.isFinite).slice(-250);
    const messages = [];
    let tagNumber = 4;
    for (const uid of uids) {
      const tag = `A${tagNumber++}`;
      const fetched = await imapExchange(socket, tag, `UID FETCH ${uid} (UID RFC822)`, 30_000);
      const raw = imapLiteral(fetched);
      if (raw) messages.push(parseImapMessage(raw, uid));
    }
    if (uids.length) connection.imapLastUid = Math.max(...uids);
    return messages;
  });
}

async function emailProviderTokens(connection) {
  const tokens = decryptEmailTokens(connection.oauthTokens);
  if (!tokens) throw Object.assign(new Error("Authorize this mailbox before syncing."), { status: 409 });
  if (!tokens.expiresAt || tokens.expiresAt > Date.now() + 60_000) return tokens;
  const config = emailProviderConfig(connection.provider);
  if (!tokens.refresh_token || !config) throw Object.assign(new Error("Mailbox authorization expired. Reconnect the inbox."), { status: 401 });
  const body = new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, refresh_token: tokens.refresh_token, grant_type: "refresh_token" });
  if (connection.provider === "outlook") body.set("scope", config.scope);
  const response = await fetch(config.tokenUrl, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  const fresh = await response.json();
  if (!response.ok) throw Object.assign(new Error(fresh.error_description || fres…18767 tokens truncated….type === "manual_note" ? "manual-notes" : "",
        metadata: entry.metadata || {}
      }))
      .filter((entry) => entry.resourceId);
    return send(res, 200, { resources });
  }
  const emailMessagesMatch = route.match(/^\/api\/email-connections\/([^/]+)\/messages$/);
  if (req.method === "GET" && emailMessagesMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailMessagesMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    const view = ["new", "all", "review"].includes(url.searchParams.get("view")) ? url.searchParams.get("view") : "new";
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit")) || 50));
    const allEvents = storeData.ingestionEvents.filter((event) => event.workspaceId === ctx.workspaceId && event.connectionId === connection.id && event.kind === "email");
    const counts = {
      all: allEvents.length,
      new: allEvents.filter((event) => !event.viewedAt).length,
      review: allEvents.filter((event) => event.status === "review_required" || event.relevance?.decision === "needs_review").length
    };
    const messages = allEvents
      .filter((event) => view === "new" ? !event.viewedAt : view === "review" ? event.status === "review_required" || event.relevance?.decision === "needs_review" : true)
      .sort((a, b) => clean(b.payload?.receivedAt || b.createdAt).localeCompare(clean(a.payload?.receivedAt || a.createdAt)))
      .slice(0, limit)
      .map((event) => {
        const plan = storeData.plans.find((entry) => entry.planId === event.planId && entry.workspaceId === ctx.workspaceId) || null;
        const recordIds = new Set(plan?.committedRecordIds || []);
        const records = storeData.records
          .filter((record) => record.workspaceId === ctx.workspaceId && (recordIds.has(record.id) || record.metadata?.planId === event.planId))
          .map((record) => ({ id: record.id, type: record.type, title: record.title, status: record.status }));
        return {
          id: event.id,
          from: clean(event.payload?.from),
          to: clean(event.payload?.to),
          subject: clean(event.payload?.subject),
          body: clean(event.payload?.body),
          threadId: clean(event.payload?.threadId),
          messageId: clean(event.payload?.messageId),
          receivedAt: clean(event.payload?.receivedAt || event.createdAt),
          createdAt: event.createdAt,
          viewedAt: event.viewedAt || "",
          status: event.status,
          relevance: event.relevance,
          plan: plan ? { planId: plan.planId, status: plan.status, actions: plan.actions || [] } : null,
          records
        };
      });
    return send(res, 200, { connection: { id: connection.id, name: connection.name, emailAddress: connection.emailAddress, provider: connection.provider, status: connection.status, lastSyncAt: connection.lastSyncAt, lastSyncError: connection.lastSyncError }, messages, counts, limit, hasMore: counts[view] > messages.length });
  }
  const emailViewedMatch = route.match(/^\/api\/email-connections\/([^/]+)\/messages\/([^/]+)\/viewed$/);
  if (req.method === "POST" && emailViewedMatch) {
    const connection = storeData.emailConnections.find((entry) => entry.id === emailViewedMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Email connection not found." });
    const event = storeData.ingestionEvents.find((entry) => entry.id === emailViewedMatch[2] && entry.connectionId === connection.id && entry.workspaceId === ctx.workspaceId && entry.kind === "email");
    if (!event) return send(res, 404, { error: "Email message not found." });
    event.viewedAt = event.viewedAt || new Date().toISOString();
    await saveStore(storeData);
    return send(res, 200, { id: event.id, viewedAt: event.viewedAt });
  }
  if (req.method === "POST" && route === "/api/form-connections") {
    const body = await readBody(req);
    const token = crypto.randomBytes(24).toString("base64url");
    const connection = { id: id("form"), workspaceId: ctx.workspaceId, sourceId: id("source_form"), name: clean(body.name || "Website form"), formUrl: clean(body.formUrl), provider: clean(body.provider || "custom"), method: clean(body.method || "webhook"), status: "draft", tokenHash: hashToken(token), automationPolicy: clean(body.automationPolicy || "review"), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), lastSubmissionAt: "" };
    storeData.formConnections.push(connection);
    storeData.sources.push({ id: connection.sourceId, workspaceId: ctx.workspaceId, name: connection.name, type: "website_form", status: "draft", metadata: { connectionId: connection.id, provider: connection.provider } });
    await saveStore(storeData);
    return send(res, 201, { connection: { ...connection, tokenHash: undefined }, token, ingestUrl: `${ORIGIN}/api/forms/ingest` });
  }
  const formTestMatch = route.match(/^\/api\/form-connections\/([^/]+)\/test$/);
  if (req.method === "POST" && formTestMatch) {
    const connection = storeData.formConnections.find((entry) => entry.id === formTestMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Form connection not found." });
    const body = await readBody(req);
    const result = await processIngestion(storeData, { workspaceId: ctx.workspaceId, connection, payload: body.fields || body.payload || body, providerSubmissionId: body.providerSubmissionId || "", stageDrafts: false });
    connection.lastSubmissionAt = new Date().toISOString();
    connection.testEventId = result.event.id;
    await saveStore(storeData);
    return send(res, 200, { accepted: true, ...result });
  }
  const formActivateMatch = route.match(/^\/api\/form-connections\/([^/]+)\/activate$/);
  if (req.method === "POST" && formActivateMatch) {
    const connection = storeData.formConnections.find((entry) => entry.id === formActivateMatch[1] && entry.workspaceId === ctx.workspaceId);
    if (!connection) return send(res, 404, { error: "Form connection not found." });
    if (!connection.testEventId) return send(res, 409, { error: "Send a test submission before activation." });
    const body = await readBody(req);
    connection.status = "active";
    connection.automationPolicy = clean(body.automationPolicy || connection.automationPolicy || "review");
    connection.activatedAt = new Date().toISOString();
    connection.updatedAt = connection.activatedAt;
    const source = storeData.sources.find((entry) => entry.id === connection.sourceId);
    if (source) source.status = "connected";
    await saveStore(storeData);
    return send(res, 200, { connection: { ...connection, tokenHash: undefined } });
  }
  if (req.method === "POST" && route === "/api/email-connections") {
    const body = await readBody(req);
    const provider = clean(body.provider || "gmail");
    const authorizationReady = Boolean(emailTokenKey()) && (provider === "gmail" ? Boolean(process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET) : provider === "outlook" ? Boolean(process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET) : provider === "imap");
    const connection = { id: id("email"), workspaceId: ctx.workspaceId, sourceId: id("source_email"), name: clean(body.name || "Connected inbox"), emailAddress: clean(body.emailAddress).toLowerCase(), provider, status: "draft", authorizationStatus: authorizationReady ? "ready" : "credentials_required", authorizationReady, scope: body.scope || {}, automationPolicy: "review", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), activatedAt: "", authorizedAt: "", syncCursor: "", lastSyncAt: "", lastSyncError: "", syncStats: { processed: 0, committed: 0 }, lastMessageAt: "", testEventId: "" };
    storeData.emailConnections.push(connection);
    storeData.sources.push({ id: connection.sourceId, workspaceId: ctx.workspaceId, name: connection.name, type: "email", status: "draft", metadata: { connectionId: connection.id, provider: connection.provider, emailAddress: connection.emailAddress } });
    await saveStore(storeData);
    return send(res, 201, { connection });
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
    authorizeUrl.searchParams.set("scope", config.scope);
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
    connection.automationPolicy = clean(body.automationPolicy || "review");
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
  if (req.method === "POST" && route === "/api/uploads/import") {
    const body = await readBody(req);
    const plan = await makePlan({ kind: "upload", rawText: String(body.csv || body.text || "").split(/\r?\n/).slice(0, 100).join("\n") }, ctx.workspaceId, storeData);
    storeData.plans.push(plan);
    stagePlanDrafts(storeData, plan, ctx.workspaceId);
    await saveStore(storeData);
    return send(res, 200, { plan });
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

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, ORIGIN);
    const route = url.pathname.replace(/\/+$/, "") || "/";
    if (route.startsWith("/api/")) return await api(req, res, url, route);
    const storeData = await loadStore();
    if (route === "/demo") return html(res, appPage({ demo: true }));
    if (["/dashboard", "/app"].includes(route)) {
      const user = currentUser(req, storeData);
      if (!user) return redirect(res, "/signin");
      ensureUserWorkspace(storeData, user);
      await saveStore(storeData);
      return html(res, appPage({ demo: false, user }));
    }
    if (["/signin", "/login"].includes(route)) return html(res, signInPage());
    return html(res, publicPage());
  } catch (error) {
    send(res, error.status || 500, { error: error.message });
  }
}).listen(PORT, () => console.log(`Constrava is running at ${ORIGIN}`));

let emailSyncRunning = false;
async function syncActiveEmailConnections() {
  if (emailSyncRunning || !emailTokenKey()) return;
  emailSyncRunning = true;
  try {
    const storeData = await loadStore();
    for (const connection of storeData.emailConnections.filter((entry) => entry.status === "active" && entry.oauthTokens)) {
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

