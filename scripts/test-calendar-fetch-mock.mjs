const nativeFetch = globalThis.fetch;

globalThis.fetch = async function calendarTestFetch(input, init) {
  const url = input instanceof URL ? input : new URL(String(input));
  if (url.href === "https://oauth2.googleapis.com/token") {
    return new Response(JSON.stringify({
      access_token: "combined-google-access-token",
      refresh_token: "combined-google-refresh-token",
      expires_in: 3600,
      scope: "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.calendarlist.readonly https://www.googleapis.com/auth/calendar.events.readonly https://www.googleapis.com/auth/adsense.readonly",
      token_type: "Bearer"
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.href === "https://openidconnect.googleapis.com/v1/userinfo") {
    return new Response(JSON.stringify({ email: "owner@example.com", name: "Calendar Owner" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.href === "https://login.microsoftonline.com/common/oauth2/v2.0/token") {
    return new Response(JSON.stringify({
      access_token: "combined-microsoft-access-token",
      refresh_token: "combined-microsoft-refresh-token",
      expires_in: 3600,
      scope: "openid email offline_access User.Read Mail.Read Calendars.Read Files.Read Contacts.Read Team.ReadBasic.All",
      token_type: "Bearer"
    }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me") {
    return new Response(JSON.stringify({ id: "microsoft-user-test", displayName: "Microsoft Owner", mail: "microsoft@example.com", userPrincipalName: "microsoft@example.com" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me/mailFolders/inbox") {
    return new Response(JSON.stringify({ displayName: "Inbox", totalItemCount: 32, unreadItemCount: 4 }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me/calendars") {
    return new Response(JSON.stringify({ value: [{ id: "calendar_primary", name: "Calendar" }, { id: "calendar_team", name: "Team calendar" }] }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me/drive") {
    return new Response(JSON.stringify({ id: "drive_test", driveType: "business", owner: { user: { displayName: "Microsoft Owner" } } }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me/contacts") {
    return new Response(JSON.stringify({ "@odata.count": 12, value: [{ id: "contact_test" }] }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me/joinedTeams") {
    return new Response(JSON.stringify({ value: [{ id: "team_test", displayName: "Sales" }] }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://graph.microsoft.com" && url.pathname === "/v1.0/me/drive/root/search(q='.xlsx')") {
    return new Response(JSON.stringify({ value: [{ id: "workbook_test", name: "Pipeline.xlsx", file: {} }] }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.href === "https://gmail.googleapis.com/gmail/v1/users/me/profile") {
    return new Response(JSON.stringify({ emailAddress: "owner@example.com", messagesTotal: 42, threadsTotal: 18 }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://adsense.googleapis.com" && url.pathname === "/v2/accounts") {
    return new Response(JSON.stringify({ accounts: [{ name: "accounts/pub-123456789", displayName: "Constrava Publisher", state: "READY", premium: false, timeZone: { id: "America/New_York" }, pendingTasks: [] }] }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (url.origin === "https://adsense.googleapis.com" && url.pathname === "/v2/accounts/pub-123456789/reports:generate") {
    const dimensions = url.searchParams.getAll("dimensions");
    const headers = [dimensions[0], "ESTIMATED_EARNINGS", "PAGE_VIEWS", "IMPRESSIONS", "CLICKS", "PAGE_VIEWS_RPM", "PAGE_VIEWS_CTR"].map((name, index) => ({ name, type: index === 0 ? "DIMENSION" : name === "ESTIMATED_EARNINGS" || name === "PAGE_VIEWS_RPM" ? "METRIC_CURRENCY" : name.endsWith("CTR") ? "METRIC_RATIO" : "METRIC_TALLY", ...(name === "ESTIMATED_EARNINGS" || name === "PAGE_VIEWS_RPM" ? { currencyCode: "USD" } : {}) }));
    const row = (values) => ({ cells: values.map((value) => ({ value: String(value) })) });
    if (dimensions[0] === "DOMAIN_NAME") return new Response(JSON.stringify({ headers, rows: [row(["example.com", 8.25, 900, 720, 18, 9.17, 0.02])], totals: row(["", 8.25, 900, 720, 18, 9.17, 0.02]), warnings: [] }), { status: 200, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ headers, rows: [row(["2026-08-14", 5.5, 600, 480, 12, 9.17, 0.02]), row(["2026-08-15", 2.75, 300, 240, 6, 9.17, 0.02])], totals: row(["", 8.25, 900, 720, 18, 9.17, 0.02]), warnings: [], startDate: { year: 2026, month: 8, day: 1 }, endDate: { year: 2026, month: 8, day: 15 } }), { status: 200, headers: { "content-type": "application/json" } });
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

