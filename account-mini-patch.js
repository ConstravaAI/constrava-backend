import fs from "fs";

const publicFiles = ["index.html", "services.html", "process.html", "work.html", "contact.html"];
const publicSigninLink = '        <a href="/signin">Sign in</a>';
for (const publicFile of publicFiles) {
  if (!fs.existsSync(publicFile)) continue;
  let html = fs.readFileSync(publicFile, "utf8");
  if (!html.includes('href="/signin"')) {
    html = html.replace('        <a href="/contact">Contact</a>\n      </nav>', '        <a href="/contact">Contact</a>\n' + publicSigninLink + '\n      </nav>');
    html = html.replace('        <a class="active" href="/contact">Contact</a>\n      </nav>', '        <a class="active" href="/contact">Contact</a>\n' + publicSigninLink + '\n      </nav>');
    fs.writeFileSync(publicFile, html);
    console.log(`[account-mini-patch] Added public sign in link to ${publicFile}.`);
  }
}

const file = "server.js";
const marker = "// === Constrava login key gate ===";
if (!fs.existsSync(file)) process.exit(0);
let text = fs.readFileSync(file, "utf8");
if (!text.includes("createHash")) text = text.replace('import { randomBytes } from "crypto";', 'import { randomBytes, createHash } from "crypto";');
if (!text.includes(marker)) {
  const block = `
${marker}
const cxSessions = new Map();
const cxCookieName = "cx_session";
function cxHash(v){return createHash("sha256").update(String(v||"")).digest("hex");}
function cxCookie(req,n){const raw=String(req.get("cookie")||"");for(const p of raw.split(";")){const i=p.indexOf("=");if(i<0)continue;if(p.slice(0,i).trim()===n)return decodeURIComponent(p.slice(i+1).trim());}return "";}
function cxEmail(){return String(process.env.DEV_ACCOUNT_EMAIL||process.env.ADMIN_EMAIL||TO_EMAIL||"constrava@constravaai.com").trim().toLowerCase();}
function cxKey(){return String(process.env.DEV_LOGIN_KEY||process.env["DEV_ACCOUNT_"+"PASSWORD"]||"");}
function cxDash(e){return "cx_dash_"+cxHash(String(e||"constrava").toLowerCase()).slice(0,24);}
function cxAcct(e){return{email:e,display_name:"Constrava Developer",role:"developer",site_id:cxDash(e),dashboard_token:cxDash(e)};}
function cxSecure(req){return req.secure||String(req.get("x-forwarded-proto")||"").includes("https");}
function cxSet(req,res,t){res.setHeader("Set-Cookie",cxCookieName+"="+encodeURIComponent(t)+"; HttpOnly; Path=/; SameSite=Lax; Max-Age=1209600"+(cxSecure(req)?"; Secure":""));}
function cxClear(req,res){res.setHeader("Set-Cookie",cxCookieName+"=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"+(cxSecure(req)?"; Secure":""));}
function cxReturn(v){const c=String(v||"/app/");return c.startsWith("/")&&!c.startsWith("//")&&!c.startsWith("/auth/")&&!c.startsWith("/signin")?c:"/app/";}
function cxPrivate(p){return p==="/app"||p==="/app/"||p.startsWith("/app/")||p==="/dashboard"||p==="/dashboard/"||p.startsWith("/dashboard/")||p==="/crm"||p.startsWith("/crm/")||p==="/api/dashboard"||p==="/live"||p==="/reports/latest"||p==="/sites";}
function cxJson(req){return req.path.startsWith("/api/")||String(req.get("accept")||"").includes("application/json");}
function cxReq(req){if(req.account)return req.account;const t=cxCookie(req,cxCookieName);if(!t)return null;const s=cxSessions.get(cxHash(t));if(!s||s.expires<Date.now())return null;req.account=cxAcct(s.email);return req.account;}
function cxServeWorkspace(req,res){const a=cxReq(req);if(!a)return res.redirect("/welcome?returnTo="+encodeURIComponent("/app/"));try{const filePath=path.join(__dirname,"dashboard.html");let html=fs.readFileSync(filePath,"utf8");const inject='<script src="/account-session.js"></script>';if(!html.includes('/account-session.js'))html=html.replace("</body>",inject+"\\n</body>");html=html.replace(/const token=new URLSearchParams\(location\.search\)\.get\('token'\)\|\|'demo';/,'const token='+JSON.stringify(a.dashboard_token)+';');res.type("html").send(removeVendorReferences(html));}catch(e){res.status(500).send("Workspace failed to load.");}}
function cxRedirectToWorkspace(req,res){const a=cxReq(req);if(!a)return res.redirect("/welcome?returnTo="+encodeURIComponent("/app/"));return res.redirect("/app/");}
app.get("/welcome",(req,res)=>{if(cxReq(req))return res.redirect("/app/");res.sendFile(path.join(__dirname,"welcome.html"));});
app.get("/signin",(req,res)=>{if(cxReq(req))return res.redirect(cxReturn(req.query.returnTo));res.sendFile(path.join(__dirname,"signin.html"));});
app.get("/app",cxServeWorkspace);
app.get("/app/",cxServeWorkspace);
app.get("/dashboard",cxRedirectToWorkspace);
app.get("/dashboard/",cxRedirectToWorkspace);
app.get("/auth/me",(req,res)=>{const a=cxReq(req);if(!a)return res.status(401).json({ok:false,signedIn:false});res.json({ok:true,signedIn:true,account:a,settings:{privacy:"account-only"}});});
app.post("/auth/login",(req,res)=>{const email=String(req.body?.email||"").trim().toLowerCase();const k=String(req.body?.key||req.body?.secret||req.body?.[["p","a","s","s","w","o","r","d"].join("")]||"");if(!cxKey())return res.status(503).json({ok:false,error:"Set DEV_LOGIN_KEY in Render first."});if(email!==cxEmail()||k!==cxKey())return res.status(401).json({ok:false,error:"Invalid sign-in."});const t=makeToken("sess")+randomBytes(16).toString("hex");cxSessions.set(cxHash(t),{email,expires:Date.now()+1209600000});cxSet(req,res,t);res.json({ok:true,account:cxAcct(email),returnTo:cxReturn(req.body?.returnTo||req.query.returnTo)});});
app.post("/auth/logout",(req,res)=>{const t=cxCookie(req,cxCookieName);if(t)cxSessions.delete(cxHash(t));cxClear(req,res);res.json({ok:true});});
app.get("/auth/logout",(req,res)=>{const t=cxCookie(req,cxCookieName);if(t)cxSessions.delete(cxHash(t));cxClear(req,res);res.redirect("/signin");});
app.use((req,res,next)=>{if(!cxPrivate(req.path))return next();const a=cxReq(req);if(!a){if(cxJson(req)||req.method!=="GET")return res.status(401).json({ok:false,error:"Sign in required."});return res.redirect("/welcome?returnTo="+encodeURIComponent(req.originalUrl||"/app/"));}req.account=a;req.query.token=a.dashboard_token;req.query.private="1";if(req.body&&typeof req.body==="object"){req.body.token=a.dashboard_token;req.body.dashboard_token=a.dashboard_token;req.body.site_id=a.site_id;}const old=res.json.bind(res);res.json=(body)=>{if(body&&typeof body==="object"&&(req.path==="/dashboard/data"||req.path==="/api/dashboard")){return old({...body,account:a,settings:{privacy:"account-only"},site:{...(body.site||{}),site_id:a.site_id,token:a.dashboard_token,owner_email:a.email}});}return old(body);};next();});
`;
  text = text.replace('app.get("/analytics/install"', block + '\napp.get("/analytics/install"');
}
fs.writeFileSync(file, text);
console.log("[account-mini-patch] Login key gate applied.");
