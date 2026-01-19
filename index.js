import express from "express";
import cors from "cors";
import pkg from "pg";
import fetch from "node-fetch";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;

const pool = new Pool({ connectionString: DATABASE_URL });

app.get("/", (req, res) => {
  res.send("Backend is running ✅");
});

app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/events", async (req, res) => {
  const { site_id, event_name, page_type, device } = req.body;

  if (!site_id || !event_name) {
    return res.status(400).json({ error: "site_id and event_name required" });
  }

  try {
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

app.post("/run-daily", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT site_id, COUNT(*) as total_events
      FROM events_raw
      WHERE created_at::date = CURRENT_DATE
      GROUP BY site_id
    `);

    res.json({ ok: true, metrics: result.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Generate + SAVE a daily report (always saves at least one row)
app.post("/generate-report", async (req, res) => {
  try {
    const metricsRes = await pool.query(`
      SELECT site_id, COUNT(*) as total_events
      FROM events_raw
      WHERE created_at::date = CURRENT_DATE
      GROUP BY site_id
    `);

    const metrics = metricsRes.rows;

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
              `Write:\n1) Summary\n2) 3 next actions\n3) One metric to watch`
          }
        ]
      })
    });

    const aiData = await aiRes.json();
    const reportText = aiData?.choices?.[0]?.message?.content;
    if (!reportText) throw new Error("AI response missing");

    const siteId = metrics[0]?.site_id || "test_site";

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
// ---- Daily automated run (every 24 hours) ----
const ONE_DAY = 24 * 60 * 60 * 1000;

// run once shortly after server starts
setTimeout(runDailyJob, 60 * 1000);

// then run every 24 hours
setInterval(runDailyJob, ONE_DAY);

async function runDailyJob() {
  try {
    console.log("Running daily report job...");

    await fetch("http://localhost:" + PORT + "/generate-report", {
      method: "POST"
    });

    console.log("Daily report completed");
  } catch (err) {
    console.error("Daily job failed:", err.message);
  }
}
// View latest saved report (for dashboard/email)
app.get("/reports/latest", async (req, res) => {
  try {
    const site_id = req.query.site_id || "test_site";

    const result = await pool.query(
      `
      SELECT site_id, report_date, report_text, created_at
      FROM daily_reports
      WHERE site_id = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT 1
      `,
      [site_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "No reports found" });
    }

    res.json({ ok: true, report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});
app.post("/email-latest", async (req, res) => {
  try {
    const site_id = req.body.site_id || "test_site";
    const to_email = req.body.to_email; // required

    if (!to_email) {
      return res.status(400).json({ ok: false, error: "to_email required" });
    }

    const r = await pool.query(
      `
      SELECT site_id, report_date, report_text
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

    const report = r.rows[0];
    const fromEmail = process.env.FROM_EMAIL || "onboarding@resend.dev";

    const emailResp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [to_email],
        subject: `Your Daily Report (${report.site_id})`,
        html: `
          <h2>Daily Report for ${report.site_id}</h2>
          <p><strong>Date:</strong> ${new Date(report.report_date).toDateString()}</p>
          <pre style="white-space:pre-wrap;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">${report.report_text}</pre>
        `
      })
    });

    const emailData = await emailResp.json();

    res.json({ ok: true, resend: emailData });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
