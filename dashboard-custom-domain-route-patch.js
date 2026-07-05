import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[dashboard-custom-domain-route-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

const marker = "// __dashboardCustomDomainRoute_v1";
const route = String.raw`${marker}
app.get(["/dashboard", "/dashboard/"], async (req, res, next) => {
  try {
    const fsMod = await import("fs");
    if (!fsMod.existsSync("dashboard.html")) return next();
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.send(fsMod.readFileSync("dashboard.html", "utf8"));
  } catch (error) {
    next(error);
  }
});
`;

if (!source.includes(marker)) {
  const anchors = [
    'app.get("/dashboard"',
    'app.get(\'/dashboard\'',
    'app.use(express.static',
    'app.get("/"',
    'app.get(\'/\''
  ];
  let insertAt = -1;
  for (const anchor of anchors) {
    const idx = source.indexOf(anchor);
    if (idx >= 0) { insertAt = idx; break; }
  }
  if (insertAt >= 0) {
    source = source.slice(0, insertAt) + route + "\n" + source.slice(insertAt);
    changed = true;
  } else {
    // Last-resort insert after common Express app declaration.
    const appIdx = source.indexOf("const app = express()");
    if (appIdx >= 0) {
      const semi = source.indexOf("\n", appIdx);
      source = source.slice(0, semi + 1) + route + "\n" + source.slice(semi + 1);
      changed = true;
    } else {
      console.warn("[dashboard-custom-domain-route-patch] Could not find a safe route anchor; skipping.");
    }
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[dashboard-custom-domain-route-patch] /dashboard and /dashboard/ now serve patched dashboard.html with no-store cache headers.");
} else {
  console.log("[dashboard-custom-domain-route-patch] Custom dashboard route already present or no changes needed.");
}
