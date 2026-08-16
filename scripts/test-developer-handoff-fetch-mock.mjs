const nativeFetch = globalThis.fetch;

globalThis.fetch = async function developerHandoffTestFetch(input, init = {}) {
  const url = input instanceof URL ? input : new URL(String(input));
  if (url.href === "https://api.resend.com/emails") {
    const payload = JSON.parse(String(init.body || "{}"));
    const required = [
      Array.isArray(payload.to) && payload.to.includes("developer@example.com"),
      payload.from === "Constrava <handoff@updates.example.com>",
      payload.reply_to === "owner@example.com",
      /Website tracker installation for Test Website/.test(payload.subject || ""),
      /Please deploy this before launch\./.test(payload.text || ""),
      /CRM project: Website Test CRM/.test(payload.text || ""),
      /Traffic sources and campaigns/.test(payload.text || ""),
      /workspaceId=workspace_test/.test(payload.text || ""),
      /site_workspace_test/.test(payload.html || ""),
      /^website-handoff:handoff_/.test(new Headers(init.headers).get("idempotency-key") || "")
    ];
    if (required.some((value) => !value)) {
      return new Response(JSON.stringify({ message: "Test email was missing required handoff content." }), { status: 422, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ id: "email_developer_handoff_test" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return nativeFetch(input, init);
};

