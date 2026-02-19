const POLL_MS = 2000;

const state = {
  knownTransitionIds: new Set(),
  knownJobIds: new Set(),
  knownMessageIds: new Set(),
  pollHandle: null,
};

const el = {
  form: document.getElementById("composer-form"),
  input: document.getElementById("composer-input"),
  submit: document.getElementById("composer-submit"),
  status: document.getElementById("composer-status"),
  runtime: document.getElementById("runtime-kv"),
  scheduler: document.getElementById("scheduler-kv"),
  inbox: document.getElementById("inbox-kv"),
  transitions: document.getElementById("transitions-list"),
  jobs: document.getElementById("jobs-list"),
  messages: document.getElementById("messages-list"),
};

function relativeTimeFromNs(ns) {
  if (!ns) {
    return "n/a";
  }
  const diffMs = Math.max(0, Date.now() - Math.floor(ns / 1e6));
  if (diffMs < 1000) return "just now";
  if (diffMs < 60000) return `${Math.floor(diffMs / 1000)}s ago`;
  if (diffMs < 3600000) return `${Math.floor(diffMs / 60000)}m ago`;
  return `${Math.floor(diffMs / 3600000)}h ago`;
}

function statusBadge(text, kind = "ok") {
  const cls = kind === "ok" ? "badge" : kind === "warn" ? "badge warn" : "badge danger";
  return `<span class="${cls}">${text}</span>`;
}

function escapeHtml(input) {
  return String(input)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderStats(container, rows) {
  container.innerHTML = rows
    .map(([label, value]) => {
      return `<div class="stat"><span>${escapeHtml(label)}</span><code>${escapeHtml(value)}</code></div>`;
    })
    .join("");
}

function renderTimeline(container, items, idKey, labelBuilder, knownSet) {
  const rows = items.map((item) => {
    const id = item[idKey] || "";
    const isNew = id && !knownSet.has(id);
    if (id) {
      knownSet.add(id);
    }
    return `<div class="timeline-row${isNew ? " new" : ""}">
      <div>${labelBuilder(item)}</div>
      <code>${escapeHtml(id)}</code>
    </div>`;
  });
  container.innerHTML = rows.length > 0 ? rows.join("") : '<p class="muted">No data yet.</p>';
}

async function apiFetch(path, init) {
  const response = await fetch(path, {
    cache: "no-store",
    ...init,
  });
  const bodyText = await response.text();
  let data = null;
  try {
    data = bodyText ? JSON.parse(bodyText) : null;
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    const message = (data && data.error) || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return data;
}

async function refreshSnapshot() {
  try {
    const snapshot = await apiFetch("/api/snapshot", { method: "GET" });
    const runtime = snapshot.runtime || {};
    const scheduler = snapshot.scheduler || {};
    const inboxStats = snapshot.inbox_stats || {};
    const messages = snapshot.inbox_messages || [];
    const jobs = snapshot.recent_jobs || [];
    const transitions = snapshot.recent_transitions || [];

    const runtimeState = runtime.state || "Unknown";
    const runtimeBadge = runtimeState === "Faulted" ? statusBadge(runtimeState, "danger") : statusBadge(runtimeState, "ok");
    renderStats(el.runtime, [
      ["state", runtimeState],
      ["state badge", runtimeBadge.replace(/<[^>]+>/g, runtimeState)],
      ["soul", runtime.soul || "n/a"],
      ["turns", String(runtime.turn_counter || 0)],
      ["last transition", relativeTimeFromNs(runtime.last_transition_at_ns)],
      ["loop enabled", String(runtime.loop_enabled)],
    ]);

    const lastTickErr = scheduler.last_tick_error ? "yes" : "no";
    const mode = scheduler.low_cycles_mode ? "low-cycles" : "normal";
    renderStats(el.scheduler, [
      ["mode", mode],
      ["enabled", String(scheduler.enabled)],
      ["active lease", scheduler.active_mutating_lease ? "active" : "none"],
      ["next seq", String(scheduler.next_job_seq || 0)],
      ["last tick", relativeTimeFromNs(scheduler.last_tick_finished_ns)],
      ["last tick error", lastTickErr],
    ]);

    renderStats(el.inbox, [
      ["total", String(inboxStats.total_messages || 0)],
      ["pending", String(inboxStats.pending_count || 0)],
      ["staged", String(inboxStats.staged_count || 0)],
      ["consumed", String(inboxStats.consumed_count || 0)],
    ]);

    renderTimeline(
      el.transitions,
      transitions,
      "id",
      (item) =>
        `${escapeHtml(item.from_state || "?")} -> ${escapeHtml(item.to_state || "?")} · ${relativeTimeFromNs(item.occurred_at_ns)}`,
      state.knownTransitionIds
    );
    renderTimeline(
      el.jobs,
      jobs,
      "id",
      (item) =>
        `${escapeHtml(item.kind || "?")} · ${escapeHtml(item.status || "?")} · ${relativeTimeFromNs(item.finished_at_ns || item.created_at_ns)}`,
      state.knownJobIds
    );
    renderTimeline(
      el.messages,
      messages,
      "id",
      (item) =>
        `${escapeHtml(item.status || "?")} · ${relativeTimeFromNs(item.posted_at_ns)}<code>${escapeHtml(item.body || "")}</code>`,
      state.knownMessageIds
    );

    el.status.textContent = `Live · updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    el.status.textContent = `Snapshot error: ${error.message}`;
  }
}

async function submitMessage(message) {
  return apiFetch("/api/inbox", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ message }),
  });
}

el.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = el.input.value.trim();
  if (!message) {
    el.status.textContent = "Message is empty.";
    return;
  }

  el.submit.disabled = true;
  el.status.textContent = "Transmitting...";
  try {
    const result = await submitMessage(message);
    el.input.value = "";
    el.status.textContent = `Accepted as ${result.id}`;
    await refreshSnapshot();
  } catch (error) {
    el.status.textContent = `Transmit failed: ${error.message}`;
  } finally {
    el.submit.disabled = false;
  }
});

async function boot() {
  await refreshSnapshot();
  state.pollHandle = setInterval(refreshSnapshot, POLL_MS);
}

boot();
