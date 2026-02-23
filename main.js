// Set footer year if present
const yearEl = document.getElementById("year");
if (yearEl) yearEl.textContent = new Date().getFullYear();

// Copy email helper if present
window.copyToClipboard = function (text) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => alert("Copied: " + text))
      .catch(() => prompt("Copy this:", text));
  } else {
    prompt("Copy this:", text);
  }
};

// Contact form behavior (works without a backend).
// If you later add a backend endpoint, replace MAILTO with a real POST.
const form = document.getElementById("leadForm");
const note = document.getElementById("formNote");

if (form && note) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());

    note.textContent = "Sending…";

    try {
      const r = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const text = await r.text(); // read raw text first
      let out = {};
      try { out = JSON.parse(text); } catch {}

      if (!r.ok || !out.ok) {
        throw new Error(out.error || `Request failed: ${r.status} ${text}`);
      }

      note.textContent = "Sent! We’ll get back to you soon.";
      form.reset();
      setTimeout(() => (note.textContent = ""), 7000);
    } catch (err) {
      note.textContent = "Error: " + err.message;
      setTimeout(() => (note.textContent = ""), 12000);
    }
  });
}

    // Opens user's email client to send to constrava@constravaai.com
    const to = "constrava@constravaai.com";
    const subject = encodeURIComponent(`Constrava Project Request — ${data.name || ""}`);
    const body = encodeURIComponent(
`Name: ${data.name || ""}
Email: ${data.email || ""}
Company/Project: ${data.company || ""}

Message:
${data.message || ""}`
    );

    window.location.href = `mailto:${to}?subject=${subject}&body=${body}`;
    note.textContent = "Opening your email app… If it didn't open, copy the email below.";
    setTimeout(() => (note.textContent = ""), 8000);
  });
}
