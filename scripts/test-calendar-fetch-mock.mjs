const nativeFetch = globalThis.fetch;

globalThis.fetch = async function calendarTestFetch(input, init) {
  const url = input instanceof URL ? input : new URL(String(input));
  if (url.href === "https://oauth2.googleapis.com/token") {
    return new Response(JSON.stringify({
      access_token: "combined-google-access-token",
      refresh_token: "combined-google-refresh-token",
      expires_in: 3600,
      scope: "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.events.readonly",
      token_type: "Bearer"
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.href === "https://openidconnect.googleapis.com/v1/userinfo") {
    return new Response(JSON.stringify({ email: "owner@example.com", name: "Calendar Owner" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.href === "https://gmail.googleapis.com/gmail/v1/users/me/profile") {
    return new Response(JSON.stringify({ emailAddress: "owner@example.com", messagesTotal: 42, threadsTotal: 18 }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://www.googleapis.com" && url.pathname === "/calendar/v3/users/me/calendarList") {
    return new Response(JSON.stringify({
      items: [
        { id: "owner@example.com", summary: "Primary calendar", primary: true, accessRole: "owner" },
        { id: "calendar_test_secondary", summary: "Test Calendar", accessRole: "owner" }
      ]
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://www.googleapis.com" && url.pathname.endsWith("/calendars/owner%40example.com/events")) {
    return new Response(JSON.stringify({ items: [], nextSyncToken: "primary-calendar-sync-token-test" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://www.googleapis.com" && url.pathname.endsWith("/calendars/calendar_test_secondary/events")) {
    const now = new Date();
    const start = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const end = new Date(start.getTime() + 45 * 60 * 1000);
    return new Response(JSON.stringify({
      items: [{
        id: "event_calendar_sync_test",
        status: "confirmed",
        eventType: "default",
        summary: "Call Peter",
        description: "",
        start: { dateTime: start.toISOString() },
        end: { dateTime: end.toISOString() },
        created: now.toISOString(),
        updated: now.toISOString(),
        organizer: { email: "owner@example.com", self: true },
        attendees: [],
        htmlLink: "https://calendar.google.com/calendar/event?eid=test"
      }],
      nextSyncToken: "secondary-calendar-sync-token-test"
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return nativeFetch(input, init);
};
