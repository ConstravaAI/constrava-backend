import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeWrapperPath = path.join(here, "server-runtime.js");
const marker = "account-persistence-hardening-v1";

const replacements = [
  {
    old: 'const storeFile = path.join(root, "data", "store.json");',
    next: 'const storeFile = process.env.DATA_FILE || path.join(process.env.DATA_DIR || root, "data", "store.json");'
  },
  {
    old: "const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;",
    next: "const SESSION_MAX_AGE_SECONDS = Number(process.env.SESSION_MAX_AGE_SECONDS || 60 * 60 * 24 * 90);"
  },
  {
    old: `async function saveStore(storeData) {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });
  await fs.writeFile(storeFile, \`\${JSON.stringify(normalize(storeData), null, 2)}\\n\`);
}`,
    next: `let saveStoreQueue = Promise.resolve();

async function writeStoreFile(content) {
  await fs.mkdir(path.dirname(storeFile), { recursive: true });
  const tempFile = storeFile + "." + process.pid + "." + Date.now() + ".tmp";
  try {
    await fs.writeFile(tempFile, content);
    await fs.rename(tempFile, storeFile);
  } catch (error) {
    await fs.unlink(tempFile).catch(() => {});
    throw error;
  }
}

async function saveStore(storeData) {
  const content = JSON.stringify(normalize(storeData), null, 2) + "\\n";
  saveStoreQueue = saveStoreQueue.then(() => writeStoreFile(content), () => writeStoreFile(content));
  return saveStoreQueue;
}`
  },
  {
    old: `function ensureUserWorkspace(storeData, user) {
  if (!user.workspaceId) user.workspaceId = \`workspace_\${user.id}\`;
  if (!storeData.records.some((record) => record.workspaceId === user.workspaceId)) storeData.records.push(...starterRecords(user.workspaceId));
}`,
    next: `function ensureUserWorkspace(storeData, user) {
  if (!user.workspaceId) user.workspaceId = "workspace_" + user.id;
  const workspaceId = user.workspaceId;
  storeData.records ||= [];
  storeData.events ||= [];
  storeData.plans ||= [];
  storeData.reports ||= [];
  storeData.sessions ||= [];
  storeData.settings ||= {};
  storeData.settings[workspaceId] ||= {
    workspaceName: user.name ? user.name + "'s workspace" : "Personal workspace",
    theme: "light",
    density: "comfortable",
    defaultCrmView: "overview",
    notifications: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  for (const collection of [storeData.records, storeData.events, storeData.plans, storeData.reports]) {
    for (const item of collection) {
      if (!item.workspaceId && item.userId === user.id) item.workspaceId = workspaceId;
    }
  }
  if (!storeData.records.some((record) => record.workspaceId === workspaceId)) {
    storeData.records.push(...starterRecords(workspaceId));
  }
}`
  },
  {
    old: `function currentUser(req, storeData) {
  const sessionId = parseCookies(req)[COOKIE_NAME];
  if (!sessionId) return null;
  const session = storeData.sessions.find((entry) => entry.id === sessionId && (!entry.expiresAt || entry.expiresAt > new Date().toISOString()));
  if (!session) return null;
  const user = storeData.users.find((entry) => entry.id === session.userId) || null;
  if (user) ensureUserWorkspace(storeData, user);
  return user;
}`,
    next: `function currentUser(req, storeData) {
  const sessionId = parseCookies(req)[COOKIE_NAME];
  if (!sessionId) return null;
  const now = new Date();
  const session = storeData.sessions.find((entry) => entry.id === sessionId && (!entry.expiresAt || entry.expiresAt > now.toISOString()));
  if (!session) return null;
  const user = storeData.users.find((entry) => entry.id === session.userId) || null;
  if (user) {
    ensureUserWorkspace(storeData, user);
    session.workspaceId = user.workspaceId;
    session.lastSeenAt = now.toISOString();
    session.expiresAt = new Date(now.getTime() + SESSION_MAX_AGE_SECONDS * 1000).toISOString();
  }
  return user;
}`
  },
  {
    old: `  const ctx = requestContext(req, url, storeData);
  if (!ctx) return send(res, 401, { error: "Sign in required." });`,
    next: `  let ctx = requestContext(req, url, storeData);
  const publicWorkspaceId = clean(url.searchParams.get("workspaceId") || "");
  if (!ctx && publicWorkspaceId && req.method === "POST" && ["/api/analytics/events", "/api/sources/form"].includes(route)) {
    ctx = { workspaceId: publicWorkspaceId, demo: false, user: null, publicSource: true };
  }
  if (!ctx) return send(res, 401, { error: "Sign in required." });`
  },
  {
    old: `  if (req.method === "GET" && route === "/api/sources") return send(res, 200, { sources: storeData.sources, snippet: snippet() });`,
    next: `  if (req.method === "GET" && route === "/api/sources") return send(res, 200, { sources: storeData.sources.filter((source) => source.workspaceId === ctx.workspaceId || source.workspaceId === "demo"), snippet: snippet(ctx.workspaceId, ctx.demo) });`
  },
  {
    old: `  if (req.method === "GET" && route === "/api/health") return send(res, 200, { ok: true, cookieName: COOKIE_NAME, sessionMaxAgeDays: 30, secureCookie: isSecure(req), developerAccountConfigured: Boolean(process.env[DEV_LOGIN_KEY_ENV]), homepage: "/", demo: "/demo", signin: "/signin", dashboard: "/dashboard" });`,
    next: `  if (req.method === "GET" && route === "/api/health") return send(res, 200, { ok: true, cookieName: COOKIE_NAME, sessionMaxAgeDays: Math.round(SESSION_MAX_AGE_SECONDS / 86400), secureCookie: isSecure(req), dataFile: storeFile, developerAccountConfigured: Boolean(process.env[DEV_LOGIN_KEY_ENV]), homepage: "/", demo: "/demo", signin: "/signin", dashboard: "/dashboard" });`
  }
];

const snippetFunction = `function snippet(workspaceId = "demo", demo = false) {
  const safeWorkspaceId = clean(workspaceId || "demo") || "demo";
  const query = demo ? "?demo=1" : "?workspaceId=" + encodeURIComponent(safeWorkspaceId);
  const endpoint = ORIGIN + "/api/analytics/events" + query;
  const siteId = "site_" + safeWorkspaceId.replace(/[^a-zA-Z0-9_-]/g, "_");
  return '<script>(function(){var endpoint=' + JSON.stringify(endpoint) + ';var workspaceId=' + JSON.stringify(safeWorkspaceId) + ';var siteId=' + JSON.stringify(siteId) + ';var sid=localStorage.getItem("constrava_session_id")||Math.random().toString(36).slice(2);localStorage.setItem("constrava_session_id",sid);function send(type,metadata){fetch(endpoint,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({workspaceId:workspaceId,siteId:siteId,type:type,sessionId:sid,sourceUrl:location.href,referrer:document.referrer,metadata:metadata||{}})}).catch(function(){})}send("page_view",{title:document.title});document.addEventListener("submit",function(e){var data={};Array.prototype.forEach.call(e.target.elements||[],function(i){if(i.name)data[i.name]=i.value});send("form_submission",{fields:data})},true)})();</script>';
}`;

const injection = `// ${marker}
const accountPersistenceReplacements = ${JSON.stringify(replacements, null, 2)};
for (const replacement of accountPersistenceReplacements) {
  if (!source.includes(replacement.old)) throw new Error("Account persistence patch target was not found.");
  source = source.replace(replacement.old, replacement.next);
}

const accountSnippetFunction = ${JSON.stringify(snippetFunction)};
source = source.replace(new RegExp("function snippet\\\\(\\\\) \\\\{[\\\\s\\\\S]*?\\\\n\\\\}"), accountSnippetFunction);
if (!source.includes("function snippet(workspaceId = \\"demo\\", demo = false)")) {
  throw new Error("Account snippet patch target was not found.");
}
`;

let wrapperSource = await fs.readFile(runtimeWrapperPath, "utf8");
if (!wrapperSource.includes(marker)) {
  const target = "await fs.writeFile(runtimePath, source);";
  if (!wrapperSource.includes(target)) throw new Error("Runtime wrapper write target was not found.");
  wrapperSource = wrapperSource.replace(target, `${injection}\n${target}`);
  await fs.writeFile(runtimeWrapperPath, wrapperSource);
}

await import("./server-fonts.js");
