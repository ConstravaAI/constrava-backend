import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-universal-ai-form-router-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
if (source.includes("__crmUniversalAiFormRouterPatch_v1")) {
  console.log("Universal AI form router patch already applied.");
  process.exit(0);
}

let changed = false;

const leadRouteAnchor = 'app.post("/api/lead", async (req, res) => {';
const universalRoutes = `// __crmUniversalAiFormRouterPatch_v1
async function ingestAnyFormResponse(req, res, siteSlugInput, formSlugInput) {
  cors(res);
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const siteSlug = String(siteSlugInput || body.site_slug || body.siteSlug || body.dashboard_token || body.token || "demo");
    const formSlug = String(formSlugInput || body.form_slug || body.formSlug || body.form_name || body.formName || body.provider || "universal-form").replace(/[^a-z0-9_-]+/gi, "-").slice(0, 80) || "universal-form";
    const lead = await normalizeFormLeadSmart(body, siteSlug, formSlug, req);
    const crmStored = await insertCrmLead(siteSlug, lead);
    const eventStored = await insertEvent(siteSlug, "form_lead", {
      source: lead.source,
      path: "/forms/" + formSlug,
      amount: lead.value,
      lead,
      dashboard_token: lead.dashboard_token,
      metadata: { normalization: lead.normalization, form_slug: formSlug }
    });
    res.json({
      ok: true,
      message: "Form response AI-sorted and saved into CRM.",
      lead_id: lead.lead_id,
      site_slug: siteSlug,
      form_slug: formSlug,
      crm_stored: crmStored,
      event_stored: eventStored,
      normalization: lead.normalization,
      lead
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "AI form intake failed." });
  }
}
app.options("/api/forms/intake", (req, res) => { cors(res); res.status(204).end(); });
app.post("/api/forms/intake", async (req, res) => ingestAnyFormResponse(req, res));
app.options("/api/forms/submit", (req, res) => { cors(res); res.status(204).end(); });
app.post("/api/forms/submit", async (req, res) => ingestAnyFormResponse(req, res));
app.options("/api/crm/forms/submit", (req, res) => { cors(res); res.status(204).end(); });
app.post("/api/crm/forms/submit", async (req, res) => ingestAnyFormResponse(req, res));
`;

if (source.includes(leadRouteAnchor)) {
  source = source.replace(leadRouteAnchor, universalRoutes + "\n" + leadRouteAnchor);
  changed = true;
} else {
  console.warn("[crm-universal-ai-form-router-patch] Could not find /api/lead anchor for universal routes.");
}

const oldGoogleIntake = 'app.post("/api/forms/intake/:siteSlug/:formSlug", async (req, res) => { cors(res); try { const siteSlug = String(req.params.siteSlug || "external-site"); const formSlug = String(req.params.formSlug || "external-form"); const lead = await normalizeFormLeadSmart(req.body || {}, siteSlug, formSlug, req); const crmStored = await insertCrmLead(siteSlug, lead); const eventStored = await insertEvent(siteSlug, "form_lead", { source: lead.source, path: `/forms/${formSlug}`, amount: lead.value, lead, dashboard_token: lead.dashboard_token }); res.json({ ok: true, message: "Form submission received and converted into a CRM lead.", lead_id: lead.lead_id, crm_stored: crmStored, event_stored: eventStored, session_stored: true, lead }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Form intake failed." }); } });';
const newGoogleIntake = 'app.post("/api/forms/intake/:siteSlug/:formSlug", async (req, res) => ingestAnyFormResponse(req, res, req.params.siteSlug || "external-site", req.params.formSlug || "external-form"));';
if (source.includes(oldGoogleIntake)) {
  source = source.replace(oldGoogleIntake, newGoogleIntake);
  changed = true;
}

const oldLeadRoute = 'app.post("/api/lead", async (req, res) => { try { const { name, email, message, website } = req.body || {}; if (website && String(website).trim() !== "") return res.json({ ok: true }); if (!name || !email || !message) return res.status(400).json({ ok: false, error: "Please include name, email, and message." }); await insertEvent("demo", "lead", { source: "contact_form", path: "/contact", metadata: { name, email }, dashboard_token: "demo" }); if (!process.env.RESEND_API_KEY || !FROM_EMAIL) return res.json({ ok: true, warning: "Lead received. Email is not configured." }); await resend.emails.send({ from: FROM_EMAIL, to: TO_EMAIL, replyTo: email, subject: `Constrava Request — ${esc(name)}`, html: `<p><b>Name:</b> ${esc(name)}</p><p><b>Email:</b> ${esc(email)}</p><pre>${esc(message)}</pre>` }); res.json({ ok: true }); } catch { res.status(500).json({ ok: false, error: "Lead send failed." }); } });';
const newLeadRoute = 'app.post("/api/lead", async (req, res) => { try { const body = req.body || {}; if (body.website && String(body.website).trim() !== "") return res.json({ ok: true }); const lead = await normalizeFormLeadSmart({ ...body, provider: "Constrava Website", source: "Website Contact Form", form_name: "website-contact" }, "demo", "website-contact", req); const crmStored = await insertCrmLead("demo", lead); const eventStored = await insertEvent("demo", "form_lead", { source: lead.source, path: "/contact", metadata: { lead_id: lead.lead_id, normalization: lead.normalization }, lead, dashboard_token: "demo" }); if (process.env.RESEND_API_KEY && FROM_EMAIL && lead.email) { try { await resend.emails.send({ from: FROM_EMAIL, to: TO_EMAIL, replyTo: lead.email, subject: `Constrava Request — ${esc(lead.name)}`, html: `<p><b>Name:</b> ${esc(lead.name)}</p><p><b>Email:</b> ${esc(lead.email)}</p><p><b>Phone:</b> ${esc(lead.phone)}</p><pre>${esc(lead.notes)}</pre>` }); } catch {} } res.json({ ok: true, message: "Lead AI-sorted and saved into CRM.", lead_id: lead.lead_id, crm_stored: crmStored, event_stored: eventStored, normalization: lead.normalization, lead }); } catch (err) { res.status(500).json({ ok: false, error: err.message || "Lead intake failed." }); } });';
if (source.includes(oldLeadRoute)) {
  source = source.replace(oldLeadRoute, newLeadRoute);
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("Universal AI form router patch applied.");
} else {
  console.log("Universal AI form router patch made no changes.");
}
