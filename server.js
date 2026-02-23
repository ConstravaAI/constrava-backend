import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "200kb" }));

// Serve static files in repo root
app.use(express.static(__dirname));

// Health check (to prove server is running)
app.get("/health", (req, res) => res.status(200).send("ok"));

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

app.post("/api/lead", async (req, res) => {
  try {
    const { name, email, company, message } = req.body || {};

    if (!name || !email || !message) {
      return res.status(400).json({ ok: false, error: "Please include name, email, and message." });
    }

    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ ok: false, error: "Server missing RESEND_API_KEY (Render env var)." });
    }
    if (!FROM_EMAIL) {
      return res.status(500).json({ ok: false, error: "Server missing FROM_EMAIL (Render env var)." });
    }

    const subject = `Constrava Lead — ${name}${company ? ` (${company})` : ""}`;

    const html = `
      <div style="font-family:Arial,sans-serif;line-height:1.5">
        <h2>New Constrava Request</h2>
        <p><b>Name:</b> ${esc(name)}</p>
        <p><b>Email:</b> ${esc(email)}</p>
        <p><b>Company:</b> ${esc(company || "")}</p>
        <p><b>Message:</b></p>
        <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:10px">${esc(message)}</pre>
      </div>
    `;

    await resend.emails.send({
      from: FROM_EMAIL,
      to: TO_EMAIL,
      replyTo: email,
      subject,
      html
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("SEND ERROR:", err);
    return res.status(500).json({ ok: false, error: "Email send failed (check Render logs)." });
  }
});

// Friendly routes (optional)
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/services", (req, res) => res.sendFile(path.join(__dirname, "services.html")));
app.get("/process", (req, res) => res.sendFile(path.join(__dirname, "process.html")));
app.get("/work", (req, res) => res.sendFile(path.join(__dirname, "work.html")));
app.get("/contact", (req, res) => res.sendFile(path.join(__dirname, "contact.html")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Constrava running on port", port));
