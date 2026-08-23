const originalFetch = globalThis.fetch;

globalThis.fetch = async function companyResolutionFetch(input, init = {}) {
  const url = String(typeof input === "string" ? input : input?.url || input);
  if (!url.startsWith("https://api.openai.com/v1/responses")) return originalFetch(input, init);
  const request = JSON.parse(String(init.body || "{}"));
  const schemaName = request.text?.format?.name;
  if (schemaName !== "crm_company_resolution") return new Response(JSON.stringify({ error: { message: `Unexpected structured response: ${schemaName}` } }), { status: 400, headers: { "content-type": "application/json" } });
  const payload = JSON.parse(request.input || "{}");
  const mention = String(payload.mention || "");
  const greenRoof = (payload.candidates || []).find((candidate) => [candidate.name, ...(candidate.aliases || [])].some((name) => /green roof(?: construction)?$/i.test(String(name))));
  let result;
  if (/^green roof construction$/i.test(mention) && greenRoof) result = { decision: "match", matchedRecordId: greenRoof.id, canonicalName: "Green Roof Construction", confidence: 0.97, reasoning: "The fuller construction name and the shorter trading name describe the same organization." };
  else if (/^green roof$/i.test(mention) && greenRoof) result = { decision: "match", matchedRecordId: greenRoof.id, canonicalName: greenRoof.name, confidence: 0.96, reasoning: "The shorter name is a known alias of the existing organization." };
  else result = { decision: "create", matchedRecordId: "", canonicalName: mention, confidence: 0.92, reasoning: "The similar wording does not provide enough evidence that this is the same organization." };
  return new Response(JSON.stringify({ output_text: JSON.stringify(result) }), { status: 200, headers: { "content-type": "application/json" } });
};
