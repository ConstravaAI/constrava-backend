import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverPath = path.join(__dirname, "server.js");
let server = fs.readFileSync(serverPath, "utf8");

if (!server.includes('/api/connect-website-guide/chat')) {
  const marker = 'app.get("/analytics/install", (req, res) => {';
  const insert = `
function connectWebsiteFallback(message = "", step = {}) {
  const lower = String(message || "").toLowerCase();
  if (lower.includes("squarespace")) return "For Squarespace, open Settings, go to Code Injection, paste the install line into Footer, save, then visit the live site once.";
  if (lower.includes("wordpress")) return "For WordPress, use a trusted header/footer tool or your theme footer area. Paste the install line once so it appears on every page.";
  if (lower.includes("shopify")) return "For Shopify, start with your theme or custom-code setup. A deeper app-style pixel can come later.";
  if (lower.includes("where") || lower.includes("paste")) return "Look for a site-wide custom code, footer code, header/footer, code injection, tag manager, or theme code area. The goal is to load the install line on every public page.";
  if (lower.includes("verify") || lower.includes("test")) return "After saving, open the live site in a private window. Then return to Constrava and look for a recent page view for this site.";
  return "I can help with that. You are on: " + String(step.title || "Connect a Website") + ". Tell me your website platform, and I will keep the next step simple.";
}

async function connectWebsiteAiReply({ message, step, token }) {
  if (!process.env.OPENAI_API_KEY) return connectWebsiteFallback(message, step);
  const prompt = [
    "You are Constrava's friendly website connection partner.",
    "Help a non-technical business user install a website analytics snippet without feeling overwhelmed.",
    "Keep replies short, calm, official, and step-by-step.",
    "Current step: " + JSON.stringify(step || {}),
    "Dashboard token label: " + String(token || "demo"),
    "User question: " + String(message || "")
  ].join("\\n");
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { "Authorization": "Bearer " + process.env.OPENAI_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ model: process.env.CONNECT_GUIDE_MODEL || process.env.OPENAI_MODEL || "gpt-4o-mini", input: prompt, max_output_tokens: 220 })
    });
    const data = await response.json();
    if (!response.ok) return connectWebsiteFallback(message, step);
    const text = data.output_text || (Array.isArray(data.output) ? data.output.flatMap((item) => item.content || []).map((part) => part.text || "").join(" ") : "");
    return String(text || connectWebsiteFallback(message, step)).trim().slice(0, 1200);
  } catch {
    return connectWebsiteFallback(message, step);
  }
}

app.post("/api/connect-website-guide/chat", requireAuth, async (req, res) => {
  try {
    const message = String(req.body?.message || "").slice(0, 1200);
    const step = req.body?.step && typeof req.body.step === "object" ? req.body.step : {};
    const token = String(req.body?.token || req.query.token || "demo");
    const reply = await connectWebsiteAiReply({ message, step, token });
    res.json({ ok: true, reply });
  } catch (err) {
    res.status(500).json({ ok: false, reply: connectWebsiteFallback(req.body?.message || "", req.body?.step || {}), error: err.message || "Guide chat failed." });
  }
});

`;
  if (!server.includes(marker)) throw new Error("Could not find analytics install route marker in server.js");
  server = server.replace(marker, insert + marker);
  fs.writeFileSync(serverPath, server);
  console.log("connect website AI guide endpoint patched into server.js");
} else {
  console.log("connect website AI guide endpoint already present");
}

const guidePath = path.join(__dirname, "connect-website-guide.js");
if (fs.existsSync(guidePath)) {
  let guide = fs.readFileSync(guidePath, "utf8");
  let changed = false;
  function quietReplace(search, replacement) {
    if (!guide.includes(search)) return;
    guide = guide.replace(search, replacement);
    changed = true;
  }

  quietReplace(
    "'.side-tools{margin-top:auto;padding-top:22px;display:grid;gap:8px}'",
    "'.side-tools{margin-top:auto;padding-top:18px;display:grid;gap:4px;border-top:1px solid rgba(236,253,245,.12)}'"
  );
  quietReplace(
    "'.side-tool{width:100%;border:0;border-radius:15px;padding:13px 14px;text-align:left;font-weight:900;text-decoration:none;color:rgba(236,253,245,.9);background:rgba(255,255,255,.08)}'",
    "'.side-tool{width:100%;border:0;border-radius:10px;padding:8px 10px;text-align:left;font-size:12px;font-weight:800;text-decoration:none;color:rgba(236,253,245,.62);background:transparent;box-shadow:none}'"
  );
  quietReplace(
    "'.side-tool:hover,.side-tool.active{background:linear-gradient(90deg,rgba(16,185,129,.32),rgba(255,255,255,.12));box-shadow:inset 3px 0 0 #12f7a3}'",
    "'.side-tool:hover,.side-tool.active{color:rgba(236,253,245,.92);background:rgba(255,255,255,.06);box-shadow:none}'"
  );
  quietReplace(
    "'.side-tool.signout{color:#fed7aa;background:rgba(251,146,60,.1)}'",
    "'.side-tool.signout{color:rgba(254,215,170,.68);background:transparent}'"
  );

  if (changed) {
    fs.writeFileSync(guidePath, guide);
    console.log("dashboard sidebar utility buttons made quieter");
  } else {
    console.log("dashboard sidebar utility button styles already quiet or unavailable");
  }
}
