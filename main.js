function byId(id) {
  return document.getElementById(id);
}

const form = byId("leadForm");
const note = byId("formNote");

function setNote(message, type = "") {
  if (!note) return;
  note.textContent = message;
  note.className = type ? `note ${type}` : "note";
}

if (form && note) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const submitButton = form.querySelector("button[type='submit']");
    const data = Object.fromEntries(new FormData(form).entries());

    if (data.website && data.website.trim() !== "") {
      form.reset();
      setNote("Sent!", "success");
      return;
    }

    setNote("Sending…");
    if (submitButton) submitButton.disabled = true;

    try {
      const response = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const raw = await response.text();
      let output = {};
      try { output = JSON.parse(raw); } catch {}

      if (!response.ok || !output.ok) {
        throw new Error(output.error || `Request failed (${response.status})`);
      }

      form.reset();
      setNote("Sent — we’ll get back to you soon.", "success");
    } catch (error) {
      setNote(`Error: ${error.message}`, "error");
    } finally {
      if (submitButton) submitButton.disabled = false;
    }
  });
}
