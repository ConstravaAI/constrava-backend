import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const sourceRuntimePath = path.join(here, "server-runtime.js");
const responsiveRuntimePath = path.join(here, ".server-runtime-responsive.js");

const responsiveCss = String.raw`
/* Responsive Constrava dashboard layer */
#search{display:none!important}
.workspace > div:last-child{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.workspace input{min-width:min(420px,100%)}.rightTools{flex-wrap:wrap}.tabs{flex-wrap:wrap}.card,dialog{max-width:100%}.notificationDropdown{position:fixed!important;top:72px!important;right:18px!important;left:auto!important;width:min(760px,calc(100vw - 36px))!important;max-width:calc(100vw - 36px)!important;min-width:min(680px,calc(100vw - 36px))!important;max-height:calc(100vh - 92px);overflow:auto;z-index:100}.notificationGrid{grid-template-columns:1fr 1fr}.notificationDropdown section{min-width:0}.notificationDropdown .item{overflow-wrap:anywhere}img,svg,canvas,pre{max-width:100%}pre{overflow:auto}.modalBody{max-height:min(72vh,720px);overflow:auto}dialog input,dialog select,dialog textarea{width:100%}
#editRecordDialog{width:min(520px,calc(100vw - 32px))!important;max-width:min(520px,calc(100vw - 32px))!important;max-height:calc(100vh - 36px)!important;border:0;border-radius:22px;padding:0;overflow:auto;box-shadow:0 28px 90px rgba(6,26,51,.28)}#editRecordDialog::backdrop{background:rgba(6,26,51,.34)}#editRecordDialog form{margin:0}#editRecordDialog .modalHead{padding:16px 18px 8px}#editRecordDialog .modalHead h2{font-size:24px;margin:0}#editRecordDialog .modalHead p{margin:4px 0 0}#editRecordDialog .modalBody{padding:0 18px 12px;display:grid;gap:8px;max-height:min(52vh,430px);overflow:auto}#editRecordDialog textarea{min-height:82px!important}#editRecordDialog .modalFoot{padding:12px 18px 16px;display:flex;gap:10px;justify-content:flex-end;border-top:1px solid #d9e3f2}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(2,1fr)}.two,.notificationPanel,.notificationGrid{grid-template-columns:1fr}.crmShell{grid-template-columns:1fr}.crmSide{position:static;top:auto;display:flex;gap:8px;overflow-x:auto;white-space:nowrap}.crmSideTitle{display:none}.crmTab{min-width:max-content;width:auto}.workspace{align-items:stretch}.workspace > div:last-child{justify-content:flex-start}.notificationDropdown{top:70px!important;right:12px!important;left:12px!important;width:auto!important;min-width:0!important;max-width:none!important}}
@media(max-width:760px){body{overflow-x:hidden}.topbar{display:flex;flex-direction:column;align-items:stretch;gap:12px;padding:12px}.leftTools{display:flex;flex-direction:column;align-items:stretch;gap:10px}.brand{font-size:22px}.tabs{display:flex;overflow-x:auto;padding-bottom:2px;gap:8px}.tab{flex:0 0 auto;padding:10px 12px}.rightTools{display:flex;justify-content:space-between;gap:8px;overflow:visible}.settingsIcon{width:44px;height:44px;flex:0 0 auto}.logoutText{flex:1}.shell{width:calc(100% - 20px)!important;margin:14px auto!important}.workspace{display:block;margin-bottom:14px}.workspace h1{font-size:32px}.workspace > div:last-child{display:grid;grid-template-columns:1fr;gap:8px;margin-top:14px}.workspace input,.workspace button{width:100%}.grid,.metrics,.two,.cards,.heroGrid,.crmShell,.notificationPanel,.notificationGrid{display:grid!important;grid-template-columns:1fr!important}.card{border-radius:16px;margin-bottom:12px}.in{padding:14px}.metricValue{font-size:28px}.recordCard{grid-template-columns:1fr!important}.recordCard > div:last-child{display:flex!important;justify-content:space-between!important;align-items:center!important;justify-items:stretch!important;margin-top:10px}.recordCard .secondary{min-width:100px}.crmSide{display:flex;overflow-x:auto;padding:8px;margin-bottom:12px}.crmTab{flex:0 0 auto}.notificationDropdown{position:fixed!important;left:10px!important;right:10px!important;top:118px!important;width:auto!important;min-width:0!important;max-width:none!important;max-height:calc(100vh - 140px);overflow:auto;padding:12px}.notificationHead{display:block}.notificationHead .ghostSmall{margin-top:8px}.modalHead,.modalBody,.modalFoot{padding:14px}.modalFoot{display:grid;grid-template-columns:1fr;gap:8px}dialog{width:calc(100vw - 20px);max-width:calc(100vw - 20px)}#editRecordDialog{width:calc(100vw - 24px)!important;max-width:calc(100vw - 24px)!important}#editRecordDialog .modalBody{max-height:52vh}#editRecordDialog .modalFoot{display:grid;grid-template-columns:1fr}textarea{min-height:110px}.resource{grid-template-columns:auto 1fr}.resource .secondary{grid-column:1 / -1;width:100%}}
@media(max-width:420px){.topbar{padding:10px}.tab{font-size:14px;padding:9px 10px}.workspace h1{font-size:28px}.metricValue{font-size:24px}.pill{font-size:11px}.fieldLine{font-size:12px}.notificationDropdown{top:126px!important}.card{border-radius:14px}.in{padding:12px}}
`;

let runtime = await fs.readFile(sourceRuntimePath, "utf8");
runtime = runtime
  .replaceAll("['edit','Edit Records']", "['edit','Add Record']")
  .replaceAll("<h2>Edit Records</h2>", "<h2>Add Record</h2>")
  .replaceAll(">Edit Records</button>", ">Add Record</button>")
  .replaceAll('if(!r.ok)throw new Error(data.error||"Authentication failed");location.href="/dashboard/"', 'if(!r.ok)throw new Error(data.error||"Authentication failed");if(data.sessionId){var cookieSecure=location.protocol==="https:"?"; SameSite=None; Secure":"; SameSite=Lax";document.cookie="constrava_session="+encodeURIComponent(data.sessionId)+"; Path=/; Max-Age="+(data.sessionMaxAgeSeconds||2592000)+cookieSecure;}location.href="/dashboard/"');

const styleNeedle = "</style>\n</head>";
const styleReplacement = responsiveCss + "\n</style>\n</head>";
const sourcePatches = [
  [
    'function sessionCookie(req, sessionId, clear = false) {\n  const secure = isSecure(req) ? "; Secure" : "";\n  if (clear) return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=0`;\n  return `${COOKIE_NAME}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${SESSION_MAX_AGE_SECONDS}`;\n}',
    'function sessionCookie(req, sessionId, clear = false) {\n  const secureRequest = isSecure(req);\n  const secure = secureRequest ? "; Secure" : "";\n  const sameSite = secureRequest ? "; SameSite=None" : "; SameSite=Lax";\n  if (clear) return `${COOKIE_NAME}=; Path=/; HttpOnly${sameSite}${secure}; Max-Age=0`;\n  return `${COOKIE_NAME}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly${sameSite}${secure}; Max-Age=${SESSION_MAX_AGE_SECONDS}`;\n}'
  ],
  [
    'return send(res, 200, { ok: true, user: publicUser(user) }, { "set-cookie": sessionCookie(req, session.id) });',
    'return send(res, 200, { ok: true, user: publicUser(user), sessionId: session.id, sessionMaxAgeSeconds: SESSION_MAX_AGE_SECONDS }, { "set-cookie": sessionCookie(req, session.id) });'
  ],
  [styleNeedle, styleReplacement]
];
const injection = "for (const [needle, replacement] of " + JSON.stringify(sourcePatches) + ") source = source.replace(needle, replacement);\n";
runtime = runtime.replace("await fs.writeFile(runtimePath, source);", injection + "await fs.writeFile(runtimePath, source);");
await fs.writeFile(responsiveRuntimePath, runtime);
await import(`${pathToFileURL(responsiveRuntimePath).href}?v=${Date.now()}`);
