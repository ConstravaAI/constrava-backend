import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "200kb" }));

// Serve your static files (index.html, services.html, styles.css, main.js, etc.)
app.use(express.static(__dirname));

// Email sender
const resend = new Resend(process.env.RESEND_API_KEY);
const TO_EMAIL = "constrava@constravaai.com";
const FROM_EMAIL = process.env.FROM_EMAIL; // must be verified in Resend

function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Contact form endpoint
app.post("/api/lead", async (req, res) => {
  try {
    const { name, email, company, message } = req.body || {};

    if (!name || !email) {
      return res.status(400).json({ ok: false, error: "Name and email are required." });
    }

    const subject = `New Constrava Request — ${name}${company ? ` (${company})` : ""}`;

    const html = `
      <div style="font-family:Arial,sans-serif; line-height:1.5">
        <h2>New Constrava Project Request</h2>
        <p><strong>Name:</strong> ${escapeHtml(name)}</p>
        <p><strong>Email:</strong> ${escapeHtml(email)}</p>
        <p><strong>Company/Project:</strong> ${escapeHtml(company || "")}</p>
        <p><strong>Message:</strong></p>
        <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:10px">${escapeHtml(message || "")}</pre>
      </div>
    `;

    await resend.emails.send({
      from: FROM_EMAIL,
      to: TO_EMAIL,
      replyTo: email,
      subject,
      html,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Email send failed." });
  }
});

// Nice URLs (optional): /services -> services.html, etc.
app.get("/services", (req, res) => res.sendFile(path.join(__dirname, "services.html")));
app.get("/process", (req, res) => res.sendFile(path.join(__dirname, "process.html")));
app.get("/work", (req, res) => res.sendFile(path.join(__dirname, "work.html")));
app.get("/contact", (req, res) => res.sendFile(path.join(__dirname, "contact.html")));

// Default to homepage
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Constrava site running on", port));
