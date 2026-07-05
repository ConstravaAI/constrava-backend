import fs from "fs";

const file = "server.js";
if (!fs.existsSync(file)) {
  console.warn("[crm-openai-diagnostics-patch] server.js not found; skipping.");
  process.exit(0);
}

let source = fs.readFileSync(file, "utf8");
let changed = false;

if (!source.includes("__crmOpenAiDiagnosticsPatch_v3")) {
  for (const marker of ["// __crmOpenAiDiagnosticsPatch_v2", "// __crmOpenAiDiagnosticsPatch_v1"]) {
    const oldStart = source.indexOf(marker);
    const oldEnd = oldStart >= 0 ? source.indexOf('app.get("/api/crm/entries"', oldStart) : -1;
    if (oldStart >= 0 && oldEnd > oldStart) {
      source = source.slice(0, oldStart) + source.slice(oldEnd);
      changed = true;
    }
  }

  const anchor = 'app.get("/api/crm/entries"';
  const insertAt = source.indexOf(anchor);
  const route = `// __crmOpenAiDiagnosticsPatch_v3
app.all("/api/openai/diagnostic", async (req, res) => {
  const started = Date.now();
  try {
    const token = String(req.query.token || req.body?.token || "").trim();
    const privateToken = "9f57ffbe-eba8-46ad-9573-c867aa4d1e66";
    if (!token) return res.status(401).json({ ok: false, error: "Missing dashboard token." });
    if (token !== privateToken) return res.status(403).json({ ok: false, error: "Invalid diagnostic token." });
    const hasKey = Boolean(process.env.OPENAI_API_KEY);
    const model = process.env.OPENAI_MODEL || "gpt-5.4-mini";
    if (!hasKey) return res.status(500).json({ ok: false, hasKey, model, error: "OPENAI_API_KEY is not set in Render." });

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.OPENAI_API_KEY },
      body: JSON.stringify({
        model,
        max_completion_tokens: 40,
        messages: [
          { role: "system", content: "Return only this JSON object: {\\\"diagnostic\\\":\\\"ok\\\"}" },
          { role: "user", content: "diagnostic" }
        ]
      })
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(200).json({
        ok: false,
        calledOpenAI: true,
        hasKey,
        model,
        status: response.status,
        errorType: json.error?.type || null,
        errorCode: json.error?.code || null,
        errorMessage: json.error?.message || "OpenAI request failed.",
        elapsedMs: Date.now() - started
      });
    }
    res.json({
      ok: true,
      calledOpenAI: true,
      hasKey,
      model,
      status: response.status,
      responsePreview: String(json.choices?.[0]?.message?.content || "").slice(0, 120),
      usage: json.usage || null,
      elapsedMs: Date.now() - started
    });
  } catch (err) {
    res.status(200).json({ ok: false, calledOpenAI: false, errorMessage: err.message || "Diagnostic failed.", elapsedMs: Date.now() - started });
  }
});
`;
  if (insertAt >= 0) {
    source = source.slice(0, insertAt) + route + "\n" + source.slice(insertAt);
    changed = true;
  } else {
    console.warn("[crm-openai-diagnostics-patch] Could not find CRM route anchor; skipping.");
  }
}

if (changed) {
  fs.writeFileSync(file, source);
  console.log("[crm-openai-diagnostics-patch] Added restricted /api/openai/diagnostic route with max_completion_tokens.");
} else {
  console.log("[crm-openai-diagnostics-patch] Diagnostics route already present or no changes needed.");
}
