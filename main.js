function $(id){ return document.getElementById(id); }

const form = $("leadForm");
const note = $("formNote");

if (form && note) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const data = Object.fromEntries(new FormData(form).entries());

    // Honeypot: if bots fill this, silently succeed (no spam email)
    if (data.website && data.website.trim() !== "") {
      form.reset();
      note.textContent = "Sent!";
      return;
    }

    note.textContent = "Sending…";

    try {
      const r = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const raw = await r.text();
      let out = {};
      try { out = JSON.parse(raw); } catch {}

      if (!r.ok || !out.ok) {
        throw new Error(out.error || `Request failed (${r.status}): ${raw}`);
      }

      note.textContent = "Sent! We’ll get back to you soon.";
      form.reset();
    } catch (err) {
      note.textContent = "Error: " + err.message;
    }
  });
}
