import express from "express";
import cors from "cors";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

const pool = new Pool({ connectionString: DATABASE_URL });

app.get("/", (req, res) => res.send("Backend is running ✅"));

app.get("/db-test", async (req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// EVENTS (validated site_id)
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

// DAILY METRICS (manual trigger)
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

// GENERATE + SAVE REPORT
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

// VIEW LATEST REPORT
app.get("/reports/latest", async (req, res) => {
  try {
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

// EMAIL LATEST REPORT (Resend)
app.post("/email-latest", async (req, res) => {
  try {
    const site_id = req.body.site_id || "test_site";
    const to_email = req.body.to_email;
    if (!to_email) {
      return res.status(400).json({ ok: false, error: "to_email required" });
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

// AUTOMATION (runs once after boot, then every 24h)
const ONE_DAY = 24 * 60 * 60 * 1000;

setTimeout(runDailyJob, 60 * 1000);
setInterval(runDailyJob, ONE_DAY);

async function runDailyJob() {
  try {
    console.log("Running daily report job...");
    await fetch(`http://localhost:${PORT}/generate-report`, { method: "POST" });
    console.log("Daily report completed");
  } catch (err) {
    console.error("Daily job failed:", err.message);
  }
}
// CLIENT TRACKER SCRIPT
app.get("/tracker.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript");

  res.send(`
    (function () {
      const siteId = document.currentScript.getAttribute("data-site-id");
      if (!siteId) return;

      fetch("${process.env.PUBLIC_BASE_URL || "https://constrava-backend.onrender.com"}/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          site_id: siteId,
          event_name: "page_view",
          page_type: window.location.pathname,
          device: /Mobi|Android/i.test(navigator.userAgent) ? "mobile" : "desktop"
        })
      });
    })();
  `);
});
// List recent reports (for dashboard)
app.get("/reports", async (req, res) => {
  try {
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

// DO NOT PUT ROUTES BELOW THIS
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
