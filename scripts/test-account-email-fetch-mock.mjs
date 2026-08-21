import { writeFile } from "node:fs/promises";

const nativeFetch = globalThis.fetch;

globalThis.fetch = async function accountEmailTestFetch(input, init = {}) {
  const url = input instanceof URL ? input : new URL(String(input));
  if (url.href === "https://api.resend.com/emails") {
    const payload = JSON.parse(String(init.body || "{}"));
    const verificationUrl = String(payload.text || "").match(/https?:\/\/[^\s]+\/verify-email\?token=[a-f0-9]{64}/i)?.[0] || "";
    const required = [
      Array.isArray(payload.to) && payload.to.includes("taylor@example.com"),
      payload.from === "Constrava <accounts@updates.example.com>",
      payload.subject === "Verify your Constrava account",
      verificationUrl,
      /expires in 24 hours/i.test(payload.text || ""),
      /^account-verification:user_/.test(new Headers(init.headers).get("idempotency-key") || "")
    ];
    if (required.some((value) => !value)) {
      return new Response(JSON.stringify({ message: "Test verification email was missing required content." }), { status: 422, headers: { "content-type": "application/json" } });
    }
    if (process.env.ACCOUNT_TEST_EMAIL_FILE) await writeFile(process.env.ACCOUNT_TEST_EMAIL_FILE, JSON.stringify({ ...payload, verificationUrl }), "utf8");
    return new Response(JSON.stringify({ id: "email_account_verification_test" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return nativeFetch(input, init);
};
