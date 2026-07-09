import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverPath = path.join(__dirname, "server.js");
const guidePath = path.join(__dirname, "connect-website-guide.js");

function snippet(origin, token) {
  return `<script async src="${origin}/tracker.js" data-token="${String(token || "demo").replace(/"/g, "&quot;")}"></script>`;
}

function installServerCoach() {
  if (!fs.existsSync(serverPath)) return;
  let server = fs.readFileSync(serverPath, "utf8");
  if (server.includes("connectWebsiteCoachReply")) {
    console.log("AI website connection coach already present in server.js");
    return;
  }

  const coachBlock = `
function connectWebsiteCoachFallback({ message = "", step = {}, token = "demo", profile = {} }) {
  const lower = String(message || "").toLowerCase();
  const platform = String(profile.platform || "").toLowerCase();
  const installLine = \`<script async src="\${CANONICAL_ORIGIN}/tracker.js" data-token="\${String(token || "demo").replace(/"/g, "&quot;")}"></script>\`;
  let reply = "Tell me what website platform you use, and I will walk you through the exact place to paste the Constrava install line.";
  let nextStep = "Choose your website platform, then copy the install line.";
  if (lower.includes("squarespace") || platform.includes("squarespace")) { reply = "For Squarespace: open Settings, go to Developer Tools or Code Injection, paste the install line into Footer, save, then visit the live site once."; nextStep = "Open Squarespace Code Injection and paste the install line in Footer."; }
  else if (lower.includes("wordpress") || platform.includes("wordpress")) { reply = "For WordPress: use a trusted header/footer code plugin or your theme footer area. Paste the install line once so it appears on every public page."; nextStep = "Open your header/footer code tool and paste the install line site-wide."; }
  else if (lower.includes("shopify") || platform.includes("shopify")) { reply = "For Shopify: open Online Store, edit the active theme, and place the install line near the closing body tag. A custom pixel can come later."; nextStep = "Open your Shopify theme code and paste the install line before the closing body tag."; }
  else if (lower.includes("webflow") || platform.includes("webflow")) { reply = "For Webflow: open Site Settings, Custom Code, paste the install line in Footer Code, publish the site, then visit the live domain."; nextStep = "Paste the install line in Webflow Footer Code and publish."; }
  else if (lower.includes("wix") || platform.includes("wix")) { reply = "For Wix: use Settings, Custom Code, add the install line to all pages, place it in body end, then publish."; nextStep = "Add the install line as Wix Custom Code on all pages."; }
  else if (lower.includes("verify") || lower.includes("test")) { reply = "After saving, open the live site in a private window, click around once, then return to this dashboard and check for a recent page view."; nextStep = "Visit the live site once, then check live events in Constrava."; }
  return { ok: true, reply, next_step: nextStep, platform: profile.platform || "Unknown", confidence: "fallback", install_line: installLine, checklist: ["Copy the install line", "Paste it once in site-wide footer/body-end code", "Publish or save", "Visit the live site", "Check Constrava for the first page view"] };
}
function parseConnectCoachJson(text, fallback) {
  try { return JSON.parse(String(text || "")); } catch {}
  const match = String(text || "").match(/\\{[\\s\\S]*\\}/);
  if (match) { try { return JSON.parse(match[0]); } catch {} }
  return fallback;
}
async function connectWebsiteCoachReply({ message, step, token, profile, history }) {
  const fallback = connectWebsiteCoachFallback({ message, step, token, profile });
  if (!process.env.OPENAI_API_KEY) return { ...fallback, ai: false, error: "OPENAI_API_KEY is not configured." };
  const installLine = \`<script async src="\${CANONICAL_ORIGIN}/tracker.js" data-token="\${String(token || "demo").replace(/"/g, "&quot;")}"></script>\`;
  const prompt = [
    "You are Constrava's AI website connection coach.",
    "Your job is to help a non-technical business user connect their website analytics snippet successfully.",
    "Be calm, practical, and direct. Ask one question at a time only when needed.",
    "Use platform-specific instructions for Squarespace, WordPress, Shopify, Webflow, Wix, Google Tag Manager, custom HTML, and unknown sites.",
    "Never ask for secrets or admin passwords. Do not claim the site is connected unless verification data confirms it.",
    "Return ONLY valid JSON with keys: reply, next_step, platform, confidence, checklist.",
    "Keep reply under 90 words. Checklist should be 3 to 5 short strings.",
    "Install line: " + installLine,
    "Current guide step: " + JSON.stringify(step || {}),
    "User profile: " + JSON.stringify(profile || {}),
    "Recent chat: " + JSON.stringify((history || []).slice(-6)),
    "User message: " + String(message || "")
  ].join("\\n");
  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { "Authorization": "Bearer " + process.env.OPENAI_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ model: process.env.CONNECT_GUIDE_MODEL || process.env.OPENAI_MODEL || "gpt-4o-mini", input: prompt, max_output_tokens: 520 })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || data.error || "OpenAI guide failed.");
    const text = data.output_text || (Array.isArray(data.output) ? data.output.flatMap((item) => item.content || []).map((part) => part.text || "").join(" ") : "");
    const parsed = parseConnectCoachJson(text, fallback);
    return { ...fallback, ...parsed, ok: true, ai: true, install_line: installLine };
  } catch (err) {
    return { ...fallback, ai: false, error: err.message || "AI guide failed." };
  }
}

app.post("/api/connect-website-guide/chat", requireAuth, async (req, res) => {
  try {
    const message = String(req.body?.message || "").slice(0, 1600);
    const step = req.body?.step && typeof req.body.step === "object" ? req.body.step : {};
    const profile = req.body?.profile && typeof req.body.profile === "object" ? req.body.profile : {};
    const history = Array.isArray(req.body?.history) ? req.body.history : [];
    const token = String(req.body?.token || req.query.token || "demo");
    const result = await connectWebsiteCoachReply({ message, step, token, profile, history });
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, ...connectWebsiteCoachFallback({ message: req.body?.message || "", step: req.body?.step || {}, token: req.body?.token || "demo", profile: req.body?.profile || {} }), error: err.message || "Guide chat failed." });
  }
});
`;

  const routePattern = /function connectWebsiteFallback[\s\S]*?app\.post\("\/api\/connect-website-guide\/chat"[\s\S]*?\n\}\);\n/;
  if (routePattern.test(server)) {
    server = server.replace(routePattern, coachBlock);
    fs.writeFileSync(serverPath, server);
    console.log("AI website connection coach upgraded server route");
  } else {
    const marker = 'app.get("/analytics/install", (req, res) => {';
    if (!server.includes(marker)) throw new Error("Could not find analytics install route marker in server.js");
    server = server.replace(marker, coachBlock + "\n" + marker);
    fs.writeFileSync(serverPath, server);
    console.log("AI website connection coach inserted server route");
  }
}

function installClientCoach() {
  if (!fs.existsSync(guidePath)) return;
  let guide = fs.readFileSync(guidePath, "utf8");
  if (guide.includes("connectWebsiteCoachUpgrade")) {
    console.log("AI website connection coach already present in guide");
    return;
  }

  const upgrade = `

  ready(function connectWebsiteCoachUpgrade() {
    var stateKey = 'constravaWebsiteConnectCoachV1';
    var chatHistory = [];
    function el(id) { return document.getElementById(id); }
    function params() { return new URLSearchParams(location.search); }
    function token() { return params().get('token') || 'demo'; }
    function readState() { try { return JSON.parse(localStorage.getItem(stateKey) || '{}') || {}; } catch { return {}; } }
    function writeState(next) { localStorage.setItem(stateKey, JSON.stringify(Object.assign(readState(), next || {}))); }
    function installLine() { return '<script async src="' + location.origin + '/tracker.js" data-token="' + escapeHtml(token()) + '"></script>'; }
    function addCoachStyles() {
      if (el('cwCoachStyles')) return;
      var style = document.createElement('style');
      style.id = 'cwCoachStyles';
      style.textContent = '.cw-profile{display:grid;grid-template-columns:1.2fr .8fr auto;gap:10px;margin:14px 0}.cw-code{display:flex;gap:8px;align-items:center;padding:10px;border:1px solid #dbe8e4;border-radius:12px;background:#06251e;color:#d1fae5;overflow:auto}.cw-code code{font-size:12px;white-space:nowrap}.cw-status{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:10px}.cw-status span{padding:8px 10px;border-radius:10px;background:#f8fafc;border:1px solid #dbe8e4;color:#475569;font-size:12px;font-weight:850}.cw-checklist{display:grid;gap:6px;margin-top:10px}.cw-checklist div{padding:8px 10px;border-radius:10px;background:#ecfdf5;color:#047857;font-size:12px;font-weight:850}@media(max-width:900px){.cw-profile,.cw-status{grid-template-columns:1fr}}';
      document.head.appendChild(style);
    }
    function ensureCoachUi() {
      var guide = el('connectWebsiteGuide');
      var chatLog = el('cwChatLog');
      if (!guide || !chatLog || el('cwCoachProfile')) return;
      addCoachStyles();
      var saved = readState();
      var profile = document.createElement('div');
      profile.id = 'cwCoachProfile';
      profile.innerHTML = [
        '<div class="cw-profile">',
          '<input class="field" id="cwSiteUrl" placeholder="Website URL" value="' + escapeHtml(saved.siteUrl || '') + '">',
          '<select class="field" id="cwPlatform"><option value="">Platform</option><option>Squarespace</option><option>WordPress</option><option>Shopify</option><option>Webflow</option><option>Wix</option><option>Google Tag Manager</option><option>Custom HTML</option><option>Not sure</option></select>',
          '<button class="btn primary" id="cwCoachStart" type="button">Ask AI Guide</button>',
        '</div>',
        '<div class="cw-code"><code id="cwInstallLine"></code><button class="btn tiny" id="cwCopySnippet" type="button">Copy</button></div>',
        '<div class="cw-status"><span id="cwPlatformStatus">Platform: not set</span><span id="cwStepStatus">Next: choose platform</span><span id="cwAiStatus">AI guide ready</span></div>',
        '<div class="cw-checklist" id="cwChecklist"></div>'
      ].join('');
      guide.insertBefore(profile, guide.children[3] || guide.firstChild);
      if (saved.platform && el('cwPlatform')) el('cwPlatform').value = saved.platform;
      updateCoachUi({ checklist: ['Choose platform', 'Copy install line', 'Paste site-wide', 'Publish and verify'] });
      el('cwSiteUrl').addEventListener('input', function () { writeState({ siteUrl: this.value.trim() }); updateCoachUi(); });
      el('cwPlatform').addEventListener('change', function () { writeState({ platform: this.value }); updateCoachUi(); askCoach('My platform is ' + (this.value || 'not sure') + '. What should I do next?'); });
      el('cwCoachStart').addEventListener('click', function () { askCoach('Help me connect this website.'); });
      el('cwCopySnippet').addEventListener('click', async function () {
        try { await navigator.clipboard.writeText(installLine()); addChat('assistant', 'Copied. Now paste that line once in your site-wide footer or body-end code area.'); }
        catch { addChat('assistant', 'Copy this install line: ' + installLine()); }
      });
    }
    function updateCoachUi(result) {
      var saved = readState();
      if (el('cwInstallLine')) el('cwInstallLine').textContent = installLine();
      if (el('cwPlatformStatus')) el('cwPlatformStatus').textContent = 'Platform: ' + (saved.platform || result?.platform || 'not set');
      if (el('cwStepStatus')) el('cwStepStatus').textContent = 'Next: ' + (result?.next_step || 'choose platform');
      if (el('cwAiStatus')) el('cwAiStatus').textContent = result?.ai === false ? 'Fallback guidance' : 'AI guide active';
      if (el('cwChecklist')) el('cwChecklist').innerHTML = (result?.checklist || []).map(function (item) { return '<div>' + escapeHtml(item) + '</div>'; }).join('');
    }
    function profile() {
      var saved = readState();
      return { siteUrl: el('cwSiteUrl') ? el('cwSiteUrl').value.trim() : saved.siteUrl || '', platform: el('cwPlatform') ? el('cwPlatform').value : saved.platform || '', installLine: installLine() };
    }
    function addChat(role, text) {
      var log = el('cwChatLog');
      if (!log) return;
      var bubble = document.createElement('div');
      bubble.style.padding = '10px 12px';
      bubble.style.borderRadius = '12px';
      bubble.style.margin = '8px 0';
      bubble.style.background = role === 'user' ? '#ecfdf5' : '#f8fafc';
      bubble.style.border = '1px solid #dbe8e4';
      bubble.innerHTML = '<b>' + (role === 'user' ? 'You' : 'Constrava AI Guide') + ':</b> ' + escapeHtml(text);
      log.appendChild(bubble);
      log.scrollTop = log.scrollHeight;
      chatHistory.push({ role: role, text: text });
      chatHistory = chatHistory.slice(-8);
    }
    async function askCoach(message) {
      ensureCoachUi();
      var input = el('cwChatInput');
      var userMessage = message || (input ? input.value.trim() : '');
      if (!userMessage) return;
      if (input) input.value = '';
      addChat('user', userMessage);
      addChat('assistant', 'Thinking through the safest next step...');
      try {
        var response = await fetch('/api/connect-website-guide/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: userMessage, step: { title: el('cwStepTitle') ? el('cwStepTitle').textContent : 'Connect a Website' }, token: token(), profile: profile(), history: chatHistory })
        });
        var data = await response.json();
        var log = el('cwChatLog');
        if (log && log.lastChild) log.removeChild(log.lastChild);
        updateCoachUi(data);
        addChat('assistant', data.reply || 'I can help. Tell me your platform and where you are stuck.');
      } catch (err) {
        var chatLog = el('cwChatLog');
        if (chatLog && chatLog.lastChild) chatLog.removeChild(chatLog.lastChild);
        addChat('assistant', 'I could not reach the AI guide. Tell me your platform, and I can still give the basic install path.');
      }
    }
    var timer = setInterval(function () { ensureCoachUi(); if (el('cwCoachProfile')) clearInterval(timer); }, 300);
    document.addEventListener('click', function (event) {
      var send = event.target && event.target.closest ? event.target.closest('#cwChatSend') : null;
      if (!send) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      askCoach();
    }, true);
    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Enter' || event.target?.id !== 'cwChatInput') return;
      event.preventDefault();
      event.stopImmediatePropagation();
      askCoach();
    }, true);
  });
`;

  guide = guide.replace(/\n\}\)\(\);\s*$/, upgrade + "\n})();\n");
  fs.writeFileSync(guidePath, guide);
  console.log("AI website connection coach upgraded dashboard guide");
}

installServerCoach();
installClientCoach();
