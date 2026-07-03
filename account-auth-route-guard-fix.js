import fs from "fs";

const file = "server.js";
const marker = "// === Constrava account route guard middleware ===";

if (!fs.existsSync(file)) {
  console.warn("[account-auth-route-guard-fix] server.js not found; skipped.");
  process.exit(0);
}

let text = fs.readFileSync(file, "utf8");

if (!text.includes(marker)) {
  const middleware = `
${marker}
app.use(async (req, res, next) => {
  if (!privateAppPath(req.path)) return next();
  try {
    const account = await getAuthAccount(req);
    if (!account) {
      if (wantsJson(req) || req.method !== "GET") return res.status(401).json({ ok: false, error: "Sign in required." });
      return res.redirect("/welcome?returnTo=" + encodeURIComponent(req.originalUrl || "/dashboard"));
    }
    req.account = account;
    req.query.token = account.dashboard_token;
    req.query.private = "1";
    if (req.body && typeof req.body === "object") {
      req.body.token = account.dashboard_token;
      req.body.dashboard_token = account.dashboard_token;
      req.body.site_id = account.site_id;
    }
    req.accountSettings = await getAccountSettings(account).catch(() => defaultSettings());
    req.accountRecords = await listAccountRecords(account).catch(() => []);
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      if (body && typeof body === "object" && (req.path === "/dashboard/data" || req.path === "/api/dashboard")) {
        const existing = Array.isArray(body.records) ? body.records : Array.isArray(body.leads) ? body.leads : [];
        const records = [...req.accountRecords, ...existing];
        return originalJson({ ...body, account: publicAccount(account), settings: req.accountSettings, records, leads: records.length ? records : body.leads, site: { ...(body.site || {}), site_id: account.site_id, token: account.dashboard_token, owner_email: account.email } });
      }
      return originalJson(body);
    };
    next();
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "Account authorization failed." });
  }
});
`;

  if (text.includes('app.post("/dashboard/simulate"')) {
    text = text.replace('app.post("/dashboard/simulate"', middleware + '\napp.post("/dashboard/simulate"');
    fs.writeFileSync(file, text);
    console.log("[account-auth-route-guard-fix] Account route guard installed.");
  } else {
    console.warn("[account-auth-route-guard-fix] Dashboard route anchor not found; skipped.");
  }
} else {
  console.log("[account-auth-route-guard-fix] Account route guard already installed.");
}
