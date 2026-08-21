const nativeFetch = globalThis.fetch;

globalThis.fetch = async function googleAuthTestFetch(input, init = {}) {
  const url = input instanceof URL ? input : new URL(String(input));
  if (url.href === "https://oauth2.googleapis.com/token") {
    const code = new URLSearchParams(String(init.body || "")).get("code") || "primary";
    return new Response(JSON.stringify({ access_token: `access_${code}`, refresh_token: `refresh_${code}`, id_token: code, expires_in: 3600, scope: "openid email profile", token_type: "Bearer" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/tokeninfo") {
    const second = url.searchParams.get("id_token") === "second";
    return new Response(JSON.stringify({
      iss: "https://accounts.google.com",
      aud: process.env.GOOGLE_CALENDAR_CLIENT_ID,
      sub: second ? "google_subject_second" : "google_subject_primary",
      email: second ? "second-google@example.com" : "primary-google@example.com",
      email_verified: "true",
      name: second ? "Second Google" : "Primary Google"
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return nativeFetch(input, init);
};
