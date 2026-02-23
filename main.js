function $(id){ return document.getElementById(id); }

const form = $("leadForm");
const note = $("formNote");

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
    <section class="card" style="margin-top:14px">
  <h2 style="margin:0 0 8px">If you’re stuck in spreadsheets, DMs, and manual steps… we fix that.</h2>
  <p>
    Most teams don’t need “more tools.” They need one simple app that turns a messy process into a clean workflow:
    clear inputs, approvals, tracking, and a dashboard everyone can trust.
  </p>

  <div class="grid grid3" style="margin-top:12px">
    <div class="card">
      <b>Dashboards that answer questions</b>
      <p>Stop hunting for numbers. Get one place to see orders, ops, clients, and performance.</p>
      <a class="btn" href="/work">See examples →</a>
    </div>
    <div class="card">
      <b>Portals customers actually use</b>
      <p>Requests, uploads, invoices, updates — without email chains and confusion.</p>
      <a class="btn" href="/services">Explore services →</a>
    </div>
    <div class="card">
      <b>Automations that remove busywork</b>
      <p>Connect Stripe, Shopify, CRMs, and internal tools so your team stops copying data around.</p>
      <a class="btn" href="/process">How we build →</a>
    </div>
  </div>
</section>
