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

// Connect to Neon via DATABASE_URL
const pool = new Pool({ connectionString: DATABASE_URL });

app.get("/", (req, res) => {
  res.send("Backend is running ✅");
});

// DB test route
app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});
// Receive events from client websites
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
// Daily aggregation (manual trigger for now)
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
// Generate a simple AI daily report (manual trigger)
app.post("/generate-report", async (req, res) => {
  try {
    // 1) pull today's metrics
    const metricsRes = await pool.query(`
      SELECT site_id, COUNT(*) as total_events
      FROM events_raw
      WHERE created_at::date = CURRENT_DATE
      GROUP BY site_id
    `);

    const metrics = metricsRes.rows;

    // 2) call OpenAI (GPT-4o) to turn metrics into advice
    const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content:
              "You generate short daily business reports. Be specific, actionable, and concise."
          },
          {
            role: "user",
            content:
              `Here are today's metrics (JSON): ${JSON.stringify(metrics)}\n` +
              `Write a daily report with:\n` +
              `1) Summary of what happened\n` +
              `2) 3 prioritized next actions\n` +
              `3) One metric to watch tomorrow\n`
          }
        ]
      })
    });

    const aiData = await aiRes.json();
    const reportText = aiData?.choices?.[0]?.message?.content;

    if (!reportText) {
      return res.status(500).json({ ok: false, error: "AI response missing" });
    }

    res.json({ ok: true, report: reportText });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
