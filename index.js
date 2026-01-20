import express from "express";
import cors from "cors";
import pkg from "pg";
import fetch from "node-fetch"; // keep this to avoid runtime surprises on Render

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL env var");
}

const pool = new Pool({ connectionString: DATABASE_URL });

/* -------------------------
   BASIC
-------------------------- */
app.get("/", (req, res) => res.send("Backend is running ✅"));

app.get("/db-test", async (req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* -------------------------
   EVENTS (validated site_id)
-------------------------- */
app.post("/events", async (req, res) => {
  const { site_id, event_name, page_type, device } = req.body;
  if (!site_id || !event_name) {
    return res.status(400).json({ error: "site_id and event_name required" });
  }

  try {
    const site = await pool.query("SELECT 1 FROM sites WHERE site_id = $1", [
      site_id
    ]);
    if (site.rows.length === 0) {
      return res.status(403).json({ error: "Invalid site_id" });
    }

    await pool.query(
      `INSERT INTO events_raw (site_id, event_name, page_type, device)
       VALUES ($1, $2, $3, $4)`,
      [site_id, event_name, page_type || null, device || null]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* -------------------------
   DAILY METRICS (manual trigger)
-------------------------- */
app.post("/run-daily", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT site_id, COUNT(*) AS total_events
      FROM events_raw
      WHERE created_at::date = CURRENT_DATE
      GROUP BY site_id
    `);
    res.json({ ok: true, metrics: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* -------------------------
   GENERATE + SAVE REPORT
-------------------------- */
app.post("/generate-report", async (req, res) => {
  try {
    const metricsRes = await pool.query(`
      SELECT site_id, COUNT(*) AS total_events
      FROM events_raw
      WHERE created_at::date = CURRENT_DATE
      GROUP BY site_id
    `);

    const metrics = metricsRes.rows;
    const siteId = metrics[0]?.site_id || "test_site";

    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ ok: false, error: "Missing OPENAI_API_KEY" });
    }

    const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [
          { role: "system", content: "You write short daily business reports." },
          {
            role: "user",
            content:
              `Metrics (JSON): ${JSON.stringify(metrics)}\n` +
              "Write:\n1) Summary\n2) 3 next actions\n3) One metric to watch"
          }
        ]
      })
    });

    const aiData = await aiRes.json();
    const reportText = aiData?.choices?.[0]?.message?.content;
    if (!reportText) throw new Error("AI response missing");

    await pool.query(
      `
      INSERT INTO daily_reports (site_id, report_date, report_text)
      VALUES ($1, CURRENT_DATE, $2)
      ON CONFLICT (site_id, report_date)
      DO UPDATE SET report_text = EXCLUDED.report_text
      `,
      [siteId, reportText]
    );

    res.json({ ok: true, site_id: siteId, report: reportText });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* -------------------------
   REPORTS APIs
-------------------------- */
function requireDashboardKey(req, res) {
  // if DASHBOARD_KEY is set, enforce it
  if (process.env.DASHBOARD_KEY && req.query.key !== process.env.DASHBOARD_KEY) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return false;
  }
  return true;
}

// VIEW LATEST REPORT
app.get("/reports/latest", async (req, res) => {
  try {
    if (!requireDashboardKey(req, res)) return;

    const site_id = req.query.site_id || "test_site";
    const r = await pool.query(
      `
      SELECT site_id, report_date, report_text, created_at
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "No report found" });
    }

    res.json({ ok: true, report: r.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// LIST REPORTS
app.get("/reports", async (req, res) => {
  try {
    if (!requireDashboardKey(req, res)) return;

    const site_id = req.query.site_id || "test_site";
    const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);

    const r = await pool.query(
      `
      SELECT site_id, report_date, created_at, LEFT(report_text, 200) AS preview
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT $2
      `,
      [site_id, limit]
    );

    res.json({ ok: true, reports: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* -------------------------
   EMAIL LATEST REPORT (Resend)
-------------------------- */
app.post("/email-latest", async (req, res) => {
  try {
    const site_id = req.body.site_id || "test_site";
    const to_email = req.body.to_email;
    if (!to_email) {
      return res.status(400).json({ ok: false, error: "to_email required" });
    }
    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ ok: false, error: "Missing RESEND_API_KEY" });
    }

    const r = await pool.query(
      `
      SELECT report_text, report_date
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "No report found" });
    }

    const emailRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: process.env.FROM_EMAIL || "onboarding@resend.dev",
        to: [to_email],
        subject: `Daily Report (${site_id})`,
        html: `<pre style="white-space:pre-wrap;">${r.rows[0].report_text}</pre>`
      })
    });

    const emailData = await emailRes.json();
    res.json({ ok: true, resend: emailData });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* -------------------------
   DASHBOARD (pretty UI)
-------------------------- */
const DASHBOARD_HTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Constrava Dashboard</title>
  <style>
    :root{
      --bg:#0b0f19;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --border:rgba(255,255,255,.08);
      --accent:#60a5fa;
      --accent2:#34d399;
      --danger:#fb7185;
      --shadow: 0 10px 30px rgba(0,0,0,.35);
      --radius:16px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 800px at 20% -10%, rgba(96,165,250,.25), transparent 60%),
                  radial-gradient(900px 600px at 90% 0%, rgba(52,211,153,.18), transparent 55%),
                  var(--bg);
      color:var(--text);
    }
    .wrap{max-width:1100px; margin:0 auto; padding:28px 18px 60px;}
    .topbar{
      display:flex; align-items:center; justify-content:space-between;
      gap:14px; padding:18px;
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .brand{display:flex; align-items:center; gap:12px;}
    .logo{
      width:40px; height:40px; border-radius:12px;
      background: linear-gradient(135deg, rgba(96,165,250,.9), rgba(52,211,153,.85));
    }
    h1{font-size:18px; margin:0;}
    .sub{font-size:12px; color:var(--muted); margin-top:2px;}
    .controls{display:flex; gap:10px; align-items:center; flex-wrap:wrap;}
    .input{
      display:flex; align-items:center; gap:10px;
      padding:10px 12px; border-radius:12px;
      border:1px solid var(--border);
      background: rgba(17,24,39,.6);
      min-width: 280px;
    }
    .input label{font-size:12px; color:var(--muted)}
    .input input{
      width: 180px;
      background: transparent; border:none; outline:none;
      color: var(--text); font-size:14px;
    }
    .btn{
      padding:10px 14px;
      border-radius:12px;
      border:1px solid var(--border);
      background: rgba(96,165,250,.12);
      color: var(--text);
      cursor:pointer;
      font-weight:600;
    }
    .grid{
      margin-top:18px;
      display:grid;
      grid-template-columns: 1.2fr .8fr;
      gap:16px;
    }
    @media (max-width: 900px){
      .grid{grid-template-columns:1fr}
      .input{min-width: 100%}
      .input input{width: 100%}
    }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
    }
    .row{display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;}
    .pill{
      font-size:12px;
      color: var(--muted);
      border:1px solid var(--border);
      padding:6px 10px;
      border-radius:999px;
      background: rgba(15,23,42,.6);
    }
    .latest{
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
      font-size: 13px;
      line-height: 1.45;
      background: rgba(15,23,42,.65);
      border:1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      overflow:auto;
      min-height: 200px;
    }
    .muted{color:var(--muted); font-size:12px}
    .historyItem{
      padding:12px;
      border-radius: 14px;
      border:1px solid var(--border);
      background: rgba(15,23,42,.55);
      margin-top:10px;
    }
    .historyItem .date{font-weight:700; font-size:12px}
    .historyItem .preview{margin-top:8px; font-size:13px; color: var(--text)}
    .status{display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);}
    .dot{width:8px; height:8px; border-radius:50%; background: var(--accent2);}
    .err{color: var(--danger); font-weight:600}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Constrava Dashboard</h1>
          <div class="sub">Daily AI reports • Live events • MVP UI</div>
        </div>
      </div>

      <div class="controls">
        <div class="input">
          <label>Site ID</label>
          <input id="siteId" value="test_site" />
        </div>
        <button class="btn" onclick="loadAll()">Refresh</button>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="row">
          <div>
            <div class="muted">Latest report</div>
            <div id="latestMeta" class="muted"></div>
          </div>
          <div class="status"><span class="dot"></span><span id="statusText">Ready</span></div>
        </div>
        <div id="latest" class="latest">Loading...</div>
      </div>

      <div class="card">
        <div class="row" style="margin:0">
          <div style="font-weight:700">Report History</div>
          <span class="pill" id="countPill">0</span>
        </div>
        <div class="muted" style="margin-top:8px">Recent reports for this site.</div>
        <div id="history"></div>
      </div>
    </div>
  </div>

<script>
  const base = location.origin;
  const key = new URLSearchParams(location.search).get("key");

  function setStatus(text, isError=false){
    const el = document.getElementById("statusText");
    el.textContent = text;
    el.className = isError ? "err" : "";
  }

  async function loadAll() {
    const siteId = document.getElementById("siteId").value.trim();
    await loadLatest(siteId);
    await loadHistory(siteId);
  }

  async function loadLatest(siteId) {
    setStatus("Loading latest...");
    const meta = document.getElementById("latestMeta");
    const box = document.getElementById("latest");
    box.textContent = "Loading...";

    const r = await fetch(\`\${base}/reports/latest?site_id=\${encodeURIComponent(siteId)}&key=\${encodeURIComponent(key)}\`);
    const data = await r.json();

    if (!data.ok) {
      setStatus("Error", true);
      meta.textContent = "";
      box.textContent = data.error || "No latest report";
      return;
    }

    const d = new Date(data.report.report_date);
    meta.textContent = \`\${d.toDateString()} • \${data.report.site_id}\`;
    box.textContent = data.report.report_text;
    setStatus("Up to date");
  }

  async function loadHistory(siteId) {
    setStatus("Loading history...");
    const el = document.getElementById("history");
    const pill = document.getElementById("countPill");
    el.innerHTML = "";

    const r = await fetch(\`\${base}/reports?site_id=\${encodeURIComponent(siteId)}&limit=30&key=\${encodeURIComponent(key)}\`);
    const data = await r.json();

    if (!data.ok) {
      setStatus("Error", true);
      el.innerHTML = \`<div class="historyItem"><div class="err">\${data.error || "No history"}</div></div>\`;
      pill.textContent = "0";
      return;
    }

    pill.textContent = data.reports.length;

    el.innerHTML = data.reports.map(rep => {
      const d = new Date(rep.report_date);
      const safePreview = escapeHtml(rep.preview || "");
      return \`
        <div class="historyItem">
          <div class="row" style="margin:0">
            <div class="date">\${d.toDateString()}</div>
          </div>
          <div class="preview">\${safePreview}...</div>
        </div>
      \`;
    }).join("");

    setStatus("Ready");
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, m => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[m]));
  }

  loadAll();
</script>
</body>
</html>`;

app.get("/dashboard", (req, res) => {
  const key = req.query.key;
  if (!process.env.DASHBOARD_KEY || key !== process.env.DASHBOARD_KEY) {
    return res.status(401).send("Unauthorized. Add ?key=YOUR_KEY");
  }
  res.setHeader("Content-Type", "text/html");
  res.send(DASHBOARD_HTML);
});

/* -------------------------
   TRACKER SCRIPT (JS ONLY)
-------------------------- */
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");

  // loads site_id from <script data-site-id="...">
  // sends a page_view event
  res.send(`
(function () {
  try {
    var script = document.currentScript;
    var siteId = script && script.getAttribute("data-site-id");
    if (!siteId) return;

    var base = "${process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com"}";
    fetch(base + "/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        site_id: siteId,
        event_name: "page_view",
        page_type: window.location.pathname,
        device: /Mobi|Android/i.test(navigator.userAgent) ? "mobile" : "desktop"
      })
    }).catch(function(){});
  } catch (e) {}
})();
`);
});

/* -------------------------
   AUTOMATION (runs once after boot, then every 24h)
-------------------------- */
const ONE_DAY = 24 * 60 * 60 * 1000;

setTimeout(runDailyJob, 60 * 1000);
setInterval(runDailyJob, ONE_DAY);

async function runDailyJob() {
  try {
    console.log("Running daily report job...");
    await fetch(`http://127.0.0.1:${PORT}/generate-report`, { method: "POST" });
    console.log("Daily report completed");
  } catch (err) {
    console.error("Daily job failed:", err.message);
  }
}
function makeSiteId() {
  // short, URL-safe id
  return "site_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 6);
}

app.post("/sites", async (req, res) => {
  try {
    const { site_name, owner_email } = req.body;

    if (!site_name || !owner_email) {
      return res.status(400).json({
        ok: false,
        error: "site_name and owner_email required"
      });
    }

    function makeSiteId() {
      return (
        "site_" +
        Math.random().toString(36).slice(2, 10) +
        Math.random().toString(36).slice(2, 6)
      );
    }

    let site_id = makeSiteId();

    // ensure uniqueness
    for (let i = 0; i < 5; i++) {
      const exists = await pool.query(
        "SELECT 1 FROM sites WHERE site_id = $1",
        [site_id]
      );
      if (exists.rows.length === 0) break;
      site_id = makeSiteId();
    }

    await pool.query(
      `INSERT INTO sites (site_id, site_name, owner_email)
       VALUES ($1, $2, $3)`,
      [site_id, site_name, owner_email]
    );

    const base =
      process.env.PUBLIC_BASE_URL ||
      "https://constrava-backend.onrender.com";

    res.json({
      ok: true,
      site_id,
      install_snippet: `<script src="${base}/tracker.js" data-site-id="${site_id}"></script>`,
      dashboard_url: `${base}/dashboard?key=${process.env.DASHBOARD_KEY}`
    });
  } catch (err) {
    console.error("Create site failed:", err);
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});

    const base = process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com";

  res.json({
  ok: true,
  site_id,
  install_snippet: `<script src="${base}/tracker.js" data-site-id="${site_id}"></script>`,
  dashboard_url: `${base}/dashboard?key=${process.env.DASHBOARD_KEY}`
});

    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// DO NOT PUT ROUTES BELOW THIS
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
