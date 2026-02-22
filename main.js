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
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());

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
