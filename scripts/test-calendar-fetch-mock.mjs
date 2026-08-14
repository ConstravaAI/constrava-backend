const nativeFetch = globalThis.fetch;

globalThis.fetch = async function calendarTestFetch(input, init) {
  const url = input instanceof URL ? input : new URL(String(input));
  if (url.origin === "https://www.googleapis.com" && url.pathname === "/calendar/v3/calendars/primary/events") {
    const now = new Date();
    const start = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const end = new Date(start.getTime() + 45 * 60 * 1000);
    return new Response(JSON.stringify({
      items: [{
        id: "event_calendar_sync_test",
        status: "confirmed",
        eventType: "default",
        summary: "Website quote call with North Star Construction",
        description: "Alex needs a website proposal with a $12,000 budget. Follow up after the meeting.",
        start: { dateTime: start.toISOString() },
        end: { dateTime: end.toISOString() },
        created: now.toISOString(),
        updated: now.toISOString(),
        organizer: { email: "owner@example.com", self: true },
        attendees: [{ email: "alex@northstar.example", displayName: "Alex Morgan", responseStatus: "accepted" }],
        htmlLink: "https://calendar.google.com/calendar/event?eid=test"
      }],
      nextSyncToken: "calendar-sync-token-test"
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return nativeFetch(input, init);
};
