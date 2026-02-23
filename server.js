import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Parse JSON body
app.use(express.json({ limit: "200kb" }));

// Serve all files in this folder (index.html, styles.css, main.js, etc.)
app.use(express.static(__dirname));

// Health check (quick test in browser)
app.get("/health", (req, res) => res.status(200).send("ok"));

// Resend setup
const resend = new Resend(process.env.RESEND_API_KEY);
const TO_EMAIL = "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL;

function esc(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Form endpoint
app.post("/api/lead", async (req, res) => {
  try {
    const { name, email, company, message } = req.body || {};
    if (!name || !email) {
      return res.status(400).json({ ok: false, error: "Name and email are required." });
    }

    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ ok: false, error: "Missing RESEND_API_KEY env var." });
    }
    if (!FROM_EMAIL) {
      return res.status(500).json({ ok: false, error: "Missing FROM_EMAIL env var." });
    }

    const subject = `New Constrava Request — ${name}${company ? ` (${company})` : ""}`;

    const html = `
      <div style="font-family:Arial,sans-serif;line-height:1.5">
        <h2>New Constrava Project Request</h2>
        <p><b>Name:</b> ${esc(name)}</p>
        <p><b>Email:</b> ${esc(email)}</p>
        <p><b>Company/Project:</b> ${esc(company || "")}</p>
        <p><b>Message:</b></p>
        <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:10px">${esc(message || "")}</pre>
      </div>
    `;

    await resend.emails.send({
      from: FROM_EMAIL,
      to: TO_EMAIL,
      replyTo: email,
      subject,
      html,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("EMAIL ERROR:", err);
    return res.status(500).json({ ok: false, error: "Email send failed (see logs)." });
  }
});

// Make sure homepage always works
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log("Constrava web service listening on port", port);
});
