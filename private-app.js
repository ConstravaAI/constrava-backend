(() => {
  const $ = (id) => document.getElementById(id);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));
  const STAGES = ["New", "Contacted", "Qualified", "Proposal", "Won", "Lost"];
  const DEFAULT_SETTINGS = {
    workspaceName: "Constrava Workspace",
    defaultView: "dashboard",
    reminderWindow: "7",
    mode: "real",
    onboarded: false
  };
  const state = {
    account: null,
    dashboard: {},
    records: [],
    tasks: [],
    inbox: [],
    timeline: [],
    savedViews: [],
    settings: { ...DEFAULT_SETTINGS },
    view: "dashboard",
    storageKey: "",
    inboxFilter: "all"
  };

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function money(value) {
    return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(Number(value || 0));
  }

  function toast(message) {
    const el = $("toast");
    if (!el) return;
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(window.__cxToastTimer);
    window.__cxToastTimer = setTimeout(() => el.classList.remove("show"), 2400);
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options
    });
    let data = {};
    try { data = await response.json(); } catch {}
    if (response.status === 401) {
      window.location.href = "/signin?returnTo=/app/";
      return null;
    }
    if (!response.ok) throw new Error(data.error || "Request failed.");
    return data;
  }

  function storageKeyFor(account) {
    return "constrava.private.v4." + String(account?.email || account?.dashboard_token || "unknown").toLowerCase();
  }

  function loadLocal() {
    try { return JSON.parse(localStorage.getItem(state.storageKey) || "{}"); } catch { return {}; }
  }

  function saveLocal() {
    const saved = {
      records: state.records.filter((record) => record.localOnly || record.createdLocal),
      tasks: state.tasks,
      inbox: state.inbox,
      timeline: state.timeline,
      savedViews: state.savedViews,
      settings: state.settings,
      savedAt: new Date().toISOString()
    };
    localStorage.setItem(state.storageKey, JSON.stringify(saved));
    renderCounts();
  }

  function recordKey(record, index) {
    return String(record.id || record.email || record.name || record.company || "record_" + index).toLowerCase();
  }

  function mergeRecords(serverRecords, localRecords) {
    const map = new Map();
    [...(serverRecords || []), ...(localRecords || [])].forEach((record, index) => {
      const key = recordKey(record, index);
      map.set(key, { ...record, id: record.id || key });
    });
    return Array.from(map.values());
  }

  function demoRecords() {
    return [
      { id: "demo_northstar", name: "Avery Morgan", email: "avery@example.com", company: "Northstar Studio", status: "Qualified", value: 4800, source: "Demo", notes: "Needs a client portal and analytics dashboard." },
      { id: "demo_manufacturing", name: "Jordan Lee", email: "jordan@example.com", company: "Lee Manufacturing", status: "Proposal", value: 8200, source: "Demo", notes: "Production tracking and maintenance reporting." },
      { id: "demo_fitness", name: "Nora Kim", email: "nora@example.com", company: "Kim Fitness", status: "Contacted", value: 3900, source: "Demo", notes: "Booking, payments, and client follow-up system." }
    ];
  }

  function stageOf(record) {
    return String(record.status || record.stage || "New");
  }

  function stageClass(value) {
    return String(value || "").toLowerCase().replace(/\s+/g, "-");
  }

  function todayStart() {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate());
  }

  function daysUntil(dateValue) {
    if (!dateValue) return null;
    return Math.round((new Date(dateValue + "T12:00:00") - todayStart()) / 86400000);
  }

  function dateLabel(dateValue) {
    if (!dateValue) return "No due date";
    return new Date(dateValue + "T12:00:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  }

  function taskNotice(task) {
    if (String(task.status || "").toLowerCase() === "done") return { level: "done", label: "Completed", rank: 99 };
    const diff = daysUntil(task.dueDate);
    if (diff === null) return { level: "none", label: "No due date", rank: 50 };
    if (diff < 0) return { level: "overdue", label: `${Math.abs(diff)} day${Math.abs(diff) === 1 ? "" : "s"} overdue`, rank: 0 };
    if (diff === 0) return { level: "today", label: "Due today", rank: 1 };
    if (diff === 1) return { level: "today", label: "Due tomorrow", rank: 2 };
    if (diff <= 7) return { level: "upcoming", label: "Due this week", rank: 3 };
    return { level: "later", label: "Upcoming", rank: 20 };
  }

  function activeNotifications() {
    const windowDays = Number(state.settings.reminderWindow || 7);
    return state.tasks
      .map((task) => ({ task, notice: taskNotice(task) }))
      .filter((item) => item.notice.level !== "done" && (item.notice.rank <= 3 || daysUntil(item.task.dueDate) <= windowDays))
      .sort((a, b) => a.notice.rank - b.notice.rank || String(a.task.dueDate || "9999").localeCompare(String(b.task.dueDate || "9999")));
  }

  function addTimeline(type, message, meta = {}) {
    state.timeline.unshift({ id: "activity_" + Date.now() + Math.random(), type, message, meta, time: new Date().toISOString() });
    state.timeline = state.timeline.slice(0, 150);
    saveLocal();
  }

  function addInbox(kind, title, body, level = "system") {
    state.inbox.unshift({ id: "inbox_" + Date.now() + Math.random(), kind, title, body, level, read: false, time: new Date().toISOString() });
    state.inbox = state.inbox.slice(0, 150);
    saveLocal();
  }

  function addComputedTaskNotice(force = false) {
    const urgent = activeNotifications().filter((item) => ["overdue", "today"].includes(item.notice.level));
    const alreadyExists = state.inbox.some((item) => item.kind === "task" && item.title === "Task reminders" && item.body.includes("need attention"));
    if ((force || urgent.length) && !alreadyExists) {
      addInbox("task", "Task reminders", `${urgent.length} task${urgent.length === 1 ? "" : "s"} need attention based on today's date.`, urgent.length ? "today" : "system");
    }
  }

  function kpi(title, value, caption) {
    return `<article class="card kpi"><small>${escapeHtml(title)}</small><strong>${escapeHtml(value)}</strong><span>${escapeHtml(caption)}</span></article>`;
  }

  function setView(view) {
    state.view = view;
    $$(".section").forEach((section) => section.classList.remove("active"));
    const section = $("view-" + view);
    if (section) section.classList.add("active");
    $$('[data-view]').forEach((button) => button.classList.toggle("active", button.dataset.view === view));
    const titles = {
      dashboard: ["Dashboard", "Private SaaS command center"],
      crm: ["CRM records", "Saved account records"],
      pipeline: ["Pipeline", "Stage board"],
      tasks: ["Tasks", "Date-aware reminders"],
      inbox: ["Inbox", "Notifications"],
      search: ["Command search", "Search everything"],
      timeline: ["Timeline", "Activity history"],
      settings: ["Settings", "Browser persistence"],
      security: ["Security", "Audit and privacy"],
      account: ["Account", "Signed-in controls"]
    };
    const [title, subtitle] = titles[view] || ["Workspace", "Private app"];
    $("pageTitle").textContent = title;
    $("pageSub").textContent = subtitle;
  }

  function renderAll() {
    const account = state.account || {};
    $("sideEmail").textContent = account.email || "Signed in";
    $("accountEmail").textContent = account.email || "—";
    $("accountRole").textContent = account.role || "developer";
    $("accountSite").textContent = account.site_id || "—";
    $("securityEmail").textContent = account.email || "—";
    $("lastLoadedAt").textContent = new Date().toLocaleString();
    $("todayPill").textContent = "Today: " + new Date().toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
    $("tokenPill").textContent = "Token: " + String(account.dashboard_token || "").slice(0, 18) + "…";
    $("modePill").textContent = state.settings.mode === "demo" ? "Demo mode" : "Private mode";
    $("storageKeyCode").textContent = state.storageKey;
    renderDashboard();
    renderCrm();
    renderPipeline();
    renderTasks();
    renderInbox();
    renderSearch();
    renderTimeline();
    renderSettings();
    renderCounts();
  }

  function renderDashboard() {
    const summary = state.dashboard.summary || {};
    const events = state.dashboard.recentEvents || [];
    const openTasks = state.tasks.filter((task) => String(task.status || "").toLowerCase() !== "done");
    const pipelineValue = state.records.reduce((sum, record) => sum + Number(record.value || record.amount || 0), 0);
    $("kpis").innerHTML = [
      kpi("Visitors", summary.visitors || summary.sessions || events.length, "Private traffic"),
      kpi("CRM records", state.records.length, "Saved + server"),
      kpi("Open tasks", openTasks.length, "Date-aware"),
      kpi("Pipeline", money(pipelineValue), "Estimated value")
    ].join("");
    renderChart(events);
    $("briefingList").innerHTML = dailyBriefing().map((item) => `
      <div class="notice ${escapeHtml(item.level)}"><div><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.body)}</p></div><span class="stage ${escapeHtml(item.level)}">${escapeHtml(item.tag)}</span></div>
    `).join("");
    $("eventsBody").innerHTML = (events || []).slice(0, 10).map((event) => `
      <tr><td>${escapeHtml(event.type || "event")}</td><td>${escapeHtml(event.path || "/")}</td><td>${escapeHtml(event.source || "direct")}</td><td>${escapeHtml(event.device || "")}</td><td>${escapeHtml(event.time || event.created_at || "")}</td></tr>
    `).join("") || '<tr><td colspan="5">No recent events yet.</td></tr>';
  }

  function dailyBriefing() {
    const urgent = activeNotifications().filter((item) => ["overdue", "today"].includes(item.notice.level));
    const proposals = state.records.filter((record) => stageOf(record) === "Proposal");
    const noNextAction = state.records.filter((record) => {
      const key = String(record.name || record.company || "").toLowerCase();
      return key && !state.tasks.some((task) => String(task.linkedRecord || "").toLowerCase().includes(key));
    });
    return [
      { title: "Tasks needing attention", body: urgent.length ? `${urgent.length} overdue or due-today task(s) need attention.` : "No urgent task reminders right now.", tag: "Tasks", level: urgent.length ? "today" : "upcoming" },
      { title: "Pipeline status", body: proposals.length ? `${proposals.length} proposal-stage record(s) may need follow-up.` : "No proposal-stage risk detected.", tag: "CRM", level: proposals.length ? "today" : "upcoming" },
      { title: "Next-action gap", body: `${noNextAction.length} CRM record(s) have no linked task.`, tag: "Action", level: noNextAction.length ? "overdue" : "upcoming" }
    ];
  }

  function renderChart(events) {
    const values = events.length ? events.slice(0, 8).map((_, index) => index + 1) : [2, 4, 3, 7, 5, 9, 8, 11];
    const max = Math.max(...values, 1);
    const points = values.map((value, index) => [35 + index * (520 / (values.length - 1 || 1)), 244 - (value / max) * 196]);
    const line = "M " + points.map((point) => point.join(" ")).join(" L ");
    const area = line + " L " + points[points.length - 1][0] + " 267 L 35 267 Z";
    $("chart").innerHTML = `<svg viewBox="0 0 600 286" preserveAspectRatio="none"><path class="gridline" d="M35 65H575M35 130H575M35 195H575M35 260H575"/><path class="area" d="${area}"/><path class="line" d="${line}"/>${points.map((point) => `<circle class="dot" cx="${point[0]}" cy="${point[1]}" r="5"/>`).join("")}<text class="axis" x="35" y="25">Activity</text><text class="axis" x="505" y="275">Latest</text></svg>`;
  }

  function filteredRecords() {
    const query = ($("recordSearch")?.value || "").toLowerCase();
    const stage = ($("recordStage")?.value || "all").toLowerCase();
    return state.records.filter((record) => {
      const text = [record.name, record.email, record.company, record.status, record.source, record.notes, record.message].join(" ").toLowerCase();
      return (!query || text.includes(query)) && (stage === "all" || stageOf(record).toLowerCase() === stage);
    });
  }

  function renderCrm() {
    const records = filteredRecords();
    $("crmBody").innerHTML = records.map((record) => `
      <tr><td><strong>${escapeHtml(record.name || "Unnamed")}</strong><br><span class="muted">${escapeHtml(record.email || "")}</span></td><td>${escapeHtml(record.company || "—")}</td><td><span class="stage ${stageClass(stageOf(record))}">${escapeHtml(stageOf(record))}</span></td><td>${money(record.value || record.amount || 0)}</td><td><button class="btn" data-open-record="${escapeHtml(record.id)}">Open</button></td></tr>
    `).join("") || '<tr><td colspan="5">No records match this view.</td></tr>';
    $("recordCards").innerHTML = records.map((record) => `
      <div class="record" data-open-record="${escapeHtml(record.id)}"><div><h3>${escapeHtml(record.name || "Unnamed record")}</h3><p>${escapeHtml(record.company || "No company")} · ${escapeHtml(record.email || "No email")}</p><p>${escapeHtml(record.notes || record.message || "No notes yet.")}</p></div><span class="stage">${escapeHtml(stageOf(record))}</span></div>
    `).join("") || '<div class="empty">No records yet.</div>';
    renderSavedViews();
  }

  function renderPipeline() {
    $("pipelineBoard").innerHTML = STAGES.map((stage) => {
      const records = state.records.filter((record) => stageOf(record) === stage);
      return `<div class="col"><h3>${escapeHtml(stage)} · ${records.length}</h3>${records.map((record) => `
        <div class="deal"><strong>${escapeHtml(record.name || record.company || "Unnamed")}</strong><span>${escapeHtml(record.company || record.email || "")}</span><em>${money(record.value || 0)}</em><div class="row-actions"><button class="btn" data-open-record="${escapeHtml(record.id)}">Open</button><button class="btn" data-move-record="${escapeHtml(record.id)}">Move</button></div></div>
      `).join("") || '<div class="empty">No records</div>'}</div>`;
    }).join("");
  }

  function renderTasks() {
    const notifications = activeNotifications();
    const openTasks = state.tasks.filter((task) => String(task.status || "").toLowerCase() !== "done");
    $("taskNavCount").textContent = notifications.filter((item) => ["overdue", "today"].includes(item.notice.level)).length;
    $("taskDateLine").textContent = "Today is " + new Date().toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" }) + ".";
    $("taskSummary").innerHTML = [
      kpi("Open tasks", openTasks.length, "Still active"),
      kpi("Needs attention", notifications.filter((item) => ["overdue", "today"].includes(item.notice.level)).length, "Overdue/today"),
      kpi("Saved tasks", state.tasks.length, "Browser account store")
    ].join("");
    $("taskNotifications").innerHTML = notifications.map(notificationHtml).join("") || '<div class="empty">No task notifications in this reminder window.</div>';
    const sorted = [...state.tasks].sort((a, b) => String(a.dueDate || "9999").localeCompare(String(b.dueDate || "9999")));
    $("taskBody").innerHTML = sorted.map((task) => {
      const notice = taskNotice(task);
      return `<tr><td><strong>${escapeHtml(task.title || "Untitled")}</strong><br><span class="muted">${escapeHtml(task.linkedRecord || "")}</span></td><td>${escapeHtml(dateLabel(task.dueDate))}</td><td>${escapeHtml(task.priority || "Normal")}</td><td>${escapeHtml(task.status || "Open")}</td><td><span class="stage ${escapeHtml(notice.level)}">${escapeHtml(notice.label)}</span></td><td><button class="btn" data-done-task="${escapeHtml(task.id)}">Done</button></td></tr>`;
    }).join("") || '<tr><td colspan="6">No tasks yet.</td></tr>';
  }

  function notificationHtml(item) {
    return `<div class="notice ${escapeHtml(item.notice.level)}"><div><h3>${escapeHtml(item.task.title || "Untitled task")}</h3><p>${escapeHtml(item.notice.label)} · ${escapeHtml(dateLabel(item.task.dueDate))}${item.task.linkedRecord ? " · " + escapeHtml(item.task.linkedRecord) : ""}</p><p>${escapeHtml(item.task.notes || "")}</p></div><span class="stage ${escapeHtml(item.notice.level)}">${escapeHtml(item.task.priority || "Normal")}</span></div>`;
  }

  function renderInbox() {
    const unread = state.inbox.filter((item) => !item.read).length;
    $("inboxNavCount").textContent = unread;
    $$('[data-inbox-filter]').forEach((button) => button.classList.toggle("active", button.dataset.inboxFilter === state.inboxFilter));
    const items = state.inbox.filter((item) => state.inboxFilter === "all" || (state.inboxFilter === "unread" ? !item.read : item.kind === state.inboxFilter));
    $("inboxList").innerHTML = items.map((item) => `
      <div class="notice ${escapeHtml(item.level || "upcoming")}"><div><h3>${item.read ? "" : "● "}${escapeHtml(item.title)}</h3><p>${escapeHtml(item.body)}</p><p>${new Date(item.time).toLocaleString()}</p></div><div class="stack narrow"><span class="stage">${escapeHtml(item.kind)}</span><button class="btn" data-read-inbox="${escapeHtml(item.id)}">Read</button><button class="btn danger" data-dismiss-inbox="${escapeHtml(item.id)}">Dismiss</button></div></div>
    `).join("") || '<div class="empty">Inbox is empty.</div>';
  }

  function renderSearch() {
    const query = ($("commandSearch")?.value || "").toLowerCase();
    const results = query ? searchItems(query) : [];
    $("searchResults").innerHTML = results.map((item) => `<div class="result"><div><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.body)}</p></div><span class="stage">${escapeHtml(item.type)}</span></div>`).join("") || '<div class="empty">Search CRM records, tasks, inbox, saved views, and timeline.</div>';
    renderSavedViews();
  }

  function searchItems(query) {
    const items = [];
    state.records.forEach((record) => items.push({ type: "CRM", title: record.name || record.company || "Record", body: [record.company, record.email, record.status, record.notes, record.message].join(" ") }));
    state.tasks.forEach((task) => items.push({ type: "Task", title: task.title || "Task", body: [task.dueDate, task.priority, task.status, task.linkedRecord, task.notes].join(" ") }));
    state.inbox.forEach((item) => items.push({ type: "Inbox", title: item.title, body: item.body }));
    state.timeline.forEach((item) => items.push({ type: "Activity", title: item.type, body: item.message }));
    state.savedViews.forEach((view) => items.push({ type: "Saved view", title: view.name, body: [view.query, view.stage].join(" ") }));
    return items.filter((item) => (item.title + " " + item.body).toLowerCase().includes(query)).slice(0, 40);
  }

  function renderTimeline() {
    $("timelineList").innerHTML = state.timeline.map((item) => `<div class="activity"><div><h3>${escapeHtml(item.type)}</h3><p>${escapeHtml(item.message)}</p><p>${new Date(item.time).toLocaleString()}</p></div><span class="stage">Audit</span></div>`).join("") || '<div class="empty">No activity recorded yet.</div>';
  }

  function renderSavedViews() {
    const select = $("savedViewSelect");
    if (select) select.innerHTML = '<option value="">Saved views</option>' + state.savedViews.map((view) => `<option value="${escapeHtml(view.id)}">${escapeHtml(view.name)}</option>`).join("");
    const list = $("savedViewsList");
    if (list) {
      list.innerHTML = state.savedViews.map((view) => `<div class="record"><div><h3>${escapeHtml(view.name)}</h3><p>Search: ${escapeHtml(view.query || "none")} · Stage: ${escapeHtml(view.stage || "all")}</p></div><button class="btn" data-apply-view="${escapeHtml(view.id)}">Apply</button></div>`).join("") || '<div class="empty">No saved views yet.</div>';
    }
  }

  function renderSettings() {
    const form = $("settingsForm");
    if (form) {
      form.workspaceName.value = state.settings.workspaceName || "";
      form.defaultView.value = state.settings.defaultView || "dashboard";
      form.reminderWindow.value = String(state.settings.reminderWindow || "7");
      form.mode.value = state.settings.mode || "real";
    }
  }

  function renderCounts() {
    if ($("savedRecordCount")) $("savedRecordCount").textContent = state.records.filter((record) => record.localOnly || record.createdLocal).length + " browser saved";
    if ($("savedTaskCount")) $("savedTaskCount").textContent = state.tasks.length + " browser saved";
    if ($("savedInboxCount")) $("savedInboxCount").textContent = state.inbox.length + " saved";
    if ($("savedActivityCount")) $("savedActivityCount").textContent = state.timeline.length + " saved";
  }

  function openRecord(id) {
    const record = state.records.find((item) => item.id === id);
    if (!record) return;
    const key = String(record.name || record.company || "").toLowerCase();
    const linkedTasks = state.tasks.filter((task) => key && String(task.linkedRecord || "").toLowerCase().includes(key));
    $("detailTitle").textContent = record.name || record.company || "Client detail";
    $("detailSub").textContent = [record.company, record.email, stageOf(record)].filter(Boolean).join(" · ");
    $("detailBody").innerHTML = `
      <div class="grid two"><div><h3>Profile</h3><div class="code">${escapeHtml(JSON.stringify(record, null, 2))}</div></div><div><h3>Linked tasks</h3>${linkedTasks.map((task) => `<div class="notice ${escapeHtml(taskNotice(task).level)}"><h3>${escapeHtml(task.title)}</h3><p>${escapeHtml(taskNotice(task).label)} · ${escapeHtml(dateLabel(task.dueDate))}</p></div>`).join("") || '<div class="empty">No linked tasks.</div>'}<button class="btn primary" id="quickTaskBtn">Create follow-up task</button></div></div>
    `;
    $("detailModal").classList.add("open");
    $("quickTaskBtn").onclick = () => {
      const due = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
      state.tasks.unshift({ id: "task_" + Date.now(), title: "Follow up with " + (record.name || record.company || "client"), linkedRecord: record.name || record.company || "", priority: "High", status: "Open", dueDate: due, notes: "Created from client detail." });
      addTimeline("Task created", "Follow-up task created from client detail.");
      addInbox("task", "Follow-up task created", "A follow-up task was added for " + (record.name || record.company || "client") + ".", "today");
      saveLocal();
      renderAll();
      toast("Follow-up task created");
    };
  }

  function moveRecord(id) {
    const record = state.records.find((item) => item.id === id);
    if (!record) return;
    const current = STAGES.indexOf(stageOf(record));
    record.status = STAGES[Math.min(current + 1, STAGES.length - 1)] || "New";
    record.localOnly = true;
    addTimeline("Pipeline move", `${record.name || record.company || "Record"} moved to ${record.status}.`);
    saveLocal();
    renderAll();
    toast("Moved to " + record.status);
  }

  function completeTask(id) {
    const task = state.tasks.find((item) => item.id === id);
    if (!task) return;
    task.status = "Done";
    addTimeline("Task completed", task.title || "Task completed");
    saveLocal();
    renderAll();
    toast("Task completed");
  }

  function applySavedView(id) {
    const view = state.savedViews.find((item) => item.id === id);
    if (!view) return;
    $("recordSearch").value = view.query || "";
    $("recordStage").value = view.stage || "all";
    setView("crm");
    renderCrm();
    toast("Saved view applied");
  }

  function download(filename, text, type = "text/plain") {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([text], { type }));
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 800);
  }

  function csv(rows) {
    return rows.map((row) => row.map((cell) => '"' + String(cell ?? "").replaceAll('"', '""') + '"').join(",")).join("\n");
  }

  function wireEvents() {
    document.addEventListener("click", (event) => {
      const viewButton = event.target.closest("[data-view]");
      if (viewButton) setView(viewButton.dataset.view);
      const viewLink = event.target.closest("[data-view-link]");
      if (viewLink) setView(viewLink.dataset.viewLink);
      const openRecordButton = event.target.closest("[data-open-record]");
      if (openRecordButton) openRecord(openRecordButton.dataset.openRecord);
      const moveButton = event.target.closest("[data-move-record]");
      if (moveButton) moveRecord(moveButton.dataset.moveRecord);
      const doneButton = event.target.closest("[data-done-task]");
      if (doneButton) completeTask(doneButton.dataset.doneTask);
      const applyButton = event.target.closest("[data-apply-view]");
      if (applyButton) applySavedView(applyButton.dataset.applyView);
      const readButton = event.target.closest("[data-read-inbox]");
      if (readButton) {
        const item = state.inbox.find((inboxItem) => inboxItem.id === readButton.dataset.readInbox);
        if (item) item.read = true;
        saveLocal();
        renderInbox();
      }
      const dismissButton = event.target.closest("[data-dismiss-inbox]");
      if (dismissButton) {
        state.inbox = state.inbox.filter((item) => item.id !== dismissButton.dataset.dismissInbox);
        saveLocal();
        renderInbox();
      }
      const inboxFilter = event.target.closest("[data-inbox-filter]");
      if (inboxFilter) {
        state.inboxFilter = inboxFilter.dataset.inboxFilter;
        renderInbox();
      }
    });

    ["logoutSide", "logoutTop", "logoutAccount"].forEach((id) => $(id)?.addEventListener("click", async () => {
      saveLocal();
      await fetch("/auth/logout", { method: "POST" }).catch(() => {});
      window.location.href = "/signin";
    }));

    $("refreshBtn")?.addEventListener("click", () => load().then(() => toast("Refreshed")));
    $("recordSearch")?.addEventListener("input", renderCrm);
    $("recordStage")?.addEventListener("change", renderCrm);
    $("savedViewSelect")?.addEventListener("change", (event) => event.target.value && applySavedView(event.target.value));
    $("globalSearch")?.addEventListener("input", (event) => {
      if (event.target.value.trim()) {
        setView("search");
        $("commandSearch").value = event.target.value;
        renderSearch();
      }
    });
    $("commandSearch")?.addEventListener("input", renderSearch);

    $("recordForm")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const record = Object.fromEntries(new FormData(event.currentTarget).entries());
      record.id = "local_" + Date.now();
      record.localOnly = true;
      record.createdLocal = true;
      record.source = "Manual";
      state.records.unshift(record);
      addTimeline("CRM record created", record.name || record.company || "New record");
      addInbox("crm", "New CRM record saved", (record.name || record.company || "A record") + " was added.", "upcoming");
      event.currentTarget.reset();
      saveLocal();
      renderAll();
      toast("CRM record saved");
    });

    $("taskForm")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const task = Object.fromEntries(new FormData(event.currentTarget).entries());
      task.id = "task_" + Date.now();
      task.createdAt = new Date().toISOString();
      state.tasks.unshift(task);
      addTimeline("Task created", task.title || "New task");
      addInbox("task", "Task saved", (task.title || "Task") + " is " + taskNotice(task).label + ".", taskNotice(task).level);
      event.currentTarget.reset();
      saveLocal();
      renderAll();
      toast("Task saved");
    });

    $("settingsForm")?.addEventListener("submit", (event) => {
      event.preventDefault();
      state.settings = { ...state.settings, ...Object.fromEntries(new FormData(event.currentTarget).entries()), onboarded: true };
      addTimeline("Settings changed", "Workspace settings were updated.");
      saveLocal();
      renderAll();
      setView(state.settings.defaultView || "dashboard");
      toast("Settings saved");
    });

    $("onboardingForm")?.addEventListener("submit", (event) => {
      event.preventDefault();
      state.settings = { ...state.settings, ...Object.fromEntries(new FormData(event.currentTarget).entries()), onboarded: true };
      $("onboarding").classList.remove("open");
      addTimeline("Onboarding completed", "Workspace setup completed.");
      saveLocal();
      renderAll();
      setView(state.settings.defaultView || "dashboard");
      toast("Workspace ready");
    });

    $("openOnboardingBtn")?.addEventListener("click", () => $("onboarding").classList.add("open"));
    $("closeDetailBtn")?.addEventListener("click", () => $("detailModal").classList.remove("open"));
    $("clearDoneBtn")?.addEventListener("click", () => {
      state.tasks = state.tasks.filter((task) => String(task.status || "").toLowerCase() !== "done");
      addTimeline("Tasks cleared", "Completed tasks were cleared.");
      saveLocal();
      renderAll();
      toast("Completed tasks cleared");
    });
    $("clearTimelineBtn")?.addEventListener("click", () => {
      state.timeline = [];
      saveLocal();
      renderTimeline();
      toast("Timeline cleared");
    });
    $("markInboxReadBtn")?.addEventListener("click", () => {
      state.inbox.forEach((item) => item.read = true);
      saveLocal();
      renderInbox();
      toast("Inbox marked read");
    });
    $("saveViewBtn")?.addEventListener("click", () => {
      const name = prompt("Name this CRM view");
      if (!name) return;
      state.savedViews.unshift({ id: "view_" + Date.now(), name, query: $("recordSearch").value, stage: $("recordStage").value });
      addTimeline("Saved view created", name);
      saveLocal();
      renderSavedViews();
      toast("View saved");
    });
    $("insightBtn")?.addEventListener("click", () => {
      const urgent = activeNotifications().filter((item) => ["overdue", "today"].includes(item.notice.level));
      addInbox("system", "Workspace insight", `${urgent.length} urgent task(s), ${state.records.filter((record) => stageOf(record) === "Proposal").length} proposal record(s), ${state.records.length} total CRM record(s).`, urgent.length ? "today" : "upcoming");
      renderInbox();
      toast("Insight added to inbox");
    });
    $("browserNotifyBtn")?.addEventListener("click", async () => {
      const urgent = activeNotifications().filter((item) => ["overdue", "today"].includes(item.notice.level));
      if (!("Notification" in window)) return toast("Browser notifications not supported");
      const permission = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
      if (permission === "granted" && urgent[0]) new Notification("Constrava task reminder", { body: urgent[0].task.title + " — " + urgent[0].notice.label });
      toast(permission === "granted" ? "Notification checked" : "Permission not granted");
    });
    $("exportJsonBtn")?.addEventListener("click", () => download("constrava-backup.json", JSON.stringify({ records: state.records.filter((record) => record.localOnly || record.createdLocal), tasks: state.tasks, inbox: state.inbox, timeline: state.timeline, savedViews: state.savedViews, settings: state.settings }, null, 2), "application/json"));
    $("exportCrmCsvBtn")?.addEventListener("click", () => download("constrava-crm.csv", csv([["name", "email", "company", "status", "value", "notes"], ...state.records.map((record) => [record.name, record.email, record.company, stageOf(record), record.value, record.notes || record.message])]), "text/csv"));
    $("exportTaskCsvBtn")?.addEventListener("click", () => download("constrava-tasks.csv", csv([["title", "dueDate", "priority", "status", "linkedRecord", "notes"], ...state.tasks.map((task) => [task.title, task.dueDate, task.priority, task.status, task.linkedRecord, task.notes])]), "text/csv"));
    $("importJsonFile")?.addEventListener("change", async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      const data = JSON.parse(await file.text());
      state.records = mergeRecords(state.records, data.records || []);
      state.tasks = Array.isArray(data.tasks) ? data.tasks : state.tasks;
      state.inbox = Array.isArray(data.inbox) ? data.inbox : state.inbox;
      state.timeline = Array.isArray(data.timeline) ? data.timeline : state.timeline;
      state.savedViews = Array.isArray(data.savedViews) ? data.savedViews : state.savedViews;
      state.settings = { ...state.settings, ...(data.settings || {}) };
      addTimeline("Backup imported", "A JSON backup was restored.");
      saveLocal();
      renderAll();
      toast("Backup imported");
    });
    $("resetLocalBtn")?.addEventListener("click", () => {
      if (!confirm("Reset local saved data for this account in this browser?")) return;
      localStorage.removeItem(state.storageKey);
      location.reload();
    });
  }

  async function load() {
    const me = await api("/auth/me");
    if (!me) return;
    state.account = me.account;
    state.storageKey = storageKeyFor(me.account);
    const local = loadLocal();
    state.settings = { ...DEFAULT_SETTINGS, ...(local.settings || {}) };
    state.tasks = Array.isArray(local.tasks) ? local.tasks : [];
    state.inbox = Array.isArray(local.inbox) ? local.inbox : [];
    state.timeline = Array.isArray(local.timeline) ? local.timeline : [];
    state.savedViews = Array.isArray(local.savedViews) ? local.savedViews : [];
    const dashboard = await api("/api/dashboard");
    state.dashboard = dashboard || {};
    const baseRecords = state.settings.mode === "demo" ? demoRecords() : (dashboard?.leads || []);
    state.records = mergeRecords(baseRecords, local.records || []);
    addComputedTaskNotice(false);
    renderAll();
    if (!state.settings.onboarded) setTimeout(() => $("onboarding").classList.add("open"), 250);
    setView(state.settings.defaultView || "dashboard");
  }

  wireEvents();
  load().catch((error) => {
    console.error(error);
    toast(error.message || "Private app failed to load");
  });
})();
