const { name, email, company, role, type, timeline, budget, links, message, website } = req.body || {};

if (website && website.trim() !== "") {
  return res.json({ ok: true }); // honeypot bot
}

const subject = `Constrava Request — ${name} (${type || "Project"})`;

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
    <p><b>Message:</b></p>
    <pre style="white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:10px">${esc(message || "")}</pre>
  </div>
`;
