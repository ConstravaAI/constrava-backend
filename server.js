import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Resend } from "resend";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "200kb" }));
app.use(express.static(__dirname));

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
    const {
      name,
      email,
      company,
      role,
      type,
      timeline,
      budget,
      links,
      memberCode,
      message,
      website
    } = req.body || {};

    // Honeypot
    if (website && website.trim() !== "") {
      return res.json({ ok: true });
    }

    if (!name || !email || !message) {
      return res.status(400).json({ ok: false, error: "Please include name, email, and message." });
    }

    if (!process.env.RESEND_API_KEY) {
      return res.status(500).json({ ok: false, error: "Missing RESEND_API_KEY env var." });
    }
    if (!FROM_EMAIL) {
      return res.status(500).json({ ok: false, error: "Missing FROM_EMAIL env var." });
    }

    const subject = `Constrava Request — ${esc(name)} (${esc(type || "Project")})`;

    const html = `
      <div style="font-family:Arial,sans-serif;line-height:1.5">
        <h2>New Constrava Project Request</h2>
        <p><b>Name:</b> ${esc(name)}</p>
        <p><b>Email:</b> ${esc(email)}</p>
        <p><b>Company:</b> ${esc(company || "")}</p>
        <p><b>Role:</b> ${esc(role || "")}</p>
        <p><b>Type:</b> ${esc(type || "")}</p>
        <p><b>Timeline:</b> ${esc(timeline || "")}</p>
        <p><b>Budget:</b> ${esc(budget || "")}</p>
        <p><b>Links:</b> ${esc(links || "")}</p>
        <p><b>Member Code:</b> ${esc(memberCode || "None")}</p>
        <p><b>Message:</b></p>
        <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:10px">${esc(message || "")}</pre>
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
    return res.status(500).json({ ok: false, error: "Email send failed (see logs)." });
  }
});

// nice routes (optional)
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/services", (req, res) => res.sendFile(path.join(__dirname, "services.html")));
app.get("/process", (req, res) => res.sendFile(path.join(__dirname, "process.html")));
app.get("/work", (req, res) => res.sendFile(path.join(__dirname, "work.html")));
app.get("/contact", (req, res) => res.sendFile(path.join(__dirname, "contact.html")));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Constrava running on port", port));
