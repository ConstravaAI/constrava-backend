const nativeFetch = globalThis.fetch;

globalThis.fetch = async function calendarTestFetch(input, init) {
  const url = input instanceof URL ? input : new URL(String(input));
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
