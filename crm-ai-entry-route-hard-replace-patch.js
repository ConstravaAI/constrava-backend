import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-ai-entry-route-hard-replace-patch] server.js not found.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");

const fnName = "async function handleCrmAiEntry";
const start = source.indexOf(fnName);
if (start === -1) {
  console.warn("[crm-ai-entry-route-hard-replace-patch] handleCrmAiEntry not found.");
  process.exit(0);
}

const braceStart = source.indexOf("{", start);
if (braceStart === -1) {
  console.warn("[crm-ai-entry-route-hard-replace-patch] handleCrmAiEntry opening brace not found.");
  process.exit(0);
}

let depth = 0;
let end = -1;
let inString = false;
let stringChar = "";
let escaped = false;
let inTemplate = false;

for (let i = braceStart; i < source.length; i++) {
  const ch = source[i];
  const prev = source[i - 1];

  if (escaped) { escaped = false; continue; }
  if (ch === "\\") { escaped = true; continue; }

  if (inString) {
    if (ch === stringChar) inString = false;
    continue;
  }

  if (inTemplate) {
    if (ch === "`") inTemplate = false;
    continue;
  }

  if (ch === "\"" || ch === "'") { inString = true; stringChar = ch; continue; }
  if (ch === "`") { inTemplate = true; continue; }
  if (ch === "{") depth++;
  if (ch === "}") {
    depth--;
    if (depth === 0) { end = i + 1; break; }
  }
}

if (end === -1) {
  console.warn("[crm-ai-entry-route-hard-replace-patch] Could not locate handleCrmAiEntry end.");
  process.exit(0);
}

const safeFunction = `async function handleCrmAiEntry(req, res) {
  try {
    const text = String(req.body?.text || req.body?.entry || req.body?.note || "").trim();
    if (!text) return res.status(400).json({ ok: false, error: "Please include plain text for the AI entry." });

    const token = String(req.body?.token || req.query.token || "demo");
    const site = await findSiteByToken(token);
    const siteId = String(valueFrom(site || virtualSite(token), ["site_id", "id"], token || "demo"));
    const current = await getUnifiedCrmLeadList(siteId, token);
    const plan = await llmPlanCrmEntry(text, current) || fallbackPlanCrmEntry(text);
    const results = [];

    for (const action of plan.actions || []) {
      const kind = String(action.action || "create").toLowerCase();
      const patch = action.entry && typeof action.entry === "object" ? action.entry : {};
      let finalEntry;
      let matched = null;

      if (kind === "update") {
        matched = findMatchingEntry(current, action.match || patch || {});
        finalEntry = completeCrmEntry(mergeEntryUpdate(matched || {}, patch, text), siteId, text);
        finalEntry.record_type = finalEntry.record_type || "crm_entry_update";
        finalEntry.source = patch.source || "AI CRM Update";
      } else {
        const baseEntry = {
          ...patch,
          plain_text: text,
          notes: patch.notes || patch.message || text,
          provider: "AI CRM Entry",
          source: patch.source || "AI CRM Entry",
          dashboard_token: token
        };
        finalEntry = completeCrmEntry(baseEntry, siteId, text);
      }

      finalEntry.dashboard_token = token;
      finalEntry.site_id = siteId;
      finalEntry.site_slug = siteId;

      await insertCrmLead(siteId, finalEntry);
      results.push({
        action: kind,
        matched_lead_id: matched?.lead_id || null,
        lead_id: finalEntry.lead_id,
        reason: action.reason || "AI interpreted CRM entry.",
        entry: finalEntry
      });
    }

    const refreshed = await getUnifiedCrmLeadList(siteId, token);
    res.json({
      ok: true,
      message: "AI entry processed into the unified CRM list.",
      source: "unified_crm_entry_list",
      actions: results,
      summary: crmListSummary(refreshed),
      entries: refreshed
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "AI CRM entry failed." });
  }
}`;

const currentFunction = source.slice(start, end);
if (currentFunction === safeFunction) {
  console.log("AI CRM entry route already hard-replaced.");
  process.exit(0);
}

source = source.slice(0, start) + safeFunction + source.slice(end);
fs.writeFileSync(file, source);
console.log("AI CRM entry route hard-replaced without normalizeFormLeadSmart dependency.");
