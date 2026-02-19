const POLL_MS = 2000;

const state = {
  knownTransitionIds: new Set(),
  knownJobIds: new Set(),
  pollHandle: null,
  inferenceDirty: false,
  inferenceConfig: {
    provider: "llm_canister",
    model: "",
    openrouter_has_api_key: false,
  },
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
  chat: document.getElementById("chat-list"),
  inferenceForm: document.getElementById("inference-form"),
  inferenceSubmit: document.getElementById("inference-submit"),
  inferenceStatus: document.getElementById("inference-status"),
  inferenceProvider: document.getElementById("inference-provider"),
  inferenceModelSection: document.getElementById("inference-model-section"),
  inferenceModelPreset: document.getElementById("inference-model-preset"),
  inferenceModelCustom: document.getElementById("inference-model-custom"),
  inferenceKeySection: document.getElementById("inference-key-section"),
  inferenceKeyAction: document.getElementById("inference-key-action"),
  inferenceApiKey: document.getElementById("inference-api-key"),
  inferenceKeyHelp: document.getElementById("inference-key-help"),
};

const INFERENCE_MODEL_PRESETS = [
  "openai/gpt-4o-mini",
  "meta-llama/llama-3.1-8b-instruct",
  "anthropic/claude-3.5-sonnet",
  "moonshotai/kimi-k2.5",
];

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
  container.innerHTML = rows.length > 0 ? rows.join("") : "<p class=\"muted\">No data yet.</p>";
}

function renderChat(container, inboxMessages, outboxMessages) {
  const rows = [];
  for (const inbox of inboxMessages) {
    rows.push({
      id: inbox.id || "",
      role: "user",
      body: inbox.body || "",
      ts: Number(inbox.posted_at_ns || 0),
      meta: `${inbox.status || "pending"} · ${relativeTimeFromNs(inbox.posted_at_ns)}`,
    });
  }
  for (const outbox of outboxMessages) {
    const sourceCount = Array.isArray(outbox.source_inbox_ids) ? outbox.source_inbox_ids.length : 0;
    rows.push({
      id: outbox.id || "",
      role: "assistant",
      body: outbox.body || "",
      ts: Number(outbox.created_at_ns || 0),
      meta: `${escapeHtml(outbox.turn_id || "turn:unknown")} · replies:${sourceCount} · ${relativeTimeFromNs(
        outbox.created_at_ns
      )}`,
    });
  }
  rows.sort((a, b) => a.ts - b.ts);

  container.innerHTML =
    rows.length === 0
      ? "<p class=\"muted\">No chat yet.</p>"
      : rows
          .map(
            (row) => `<article class="chat-row ${row.role}">
      <p class="chat-meta">${escapeHtml(row.role)} · ${row.meta}</p>
      <div class="chat-bubble"><p>${escapeHtml(row.body)}</p></div>
      <code>${escapeHtml(row.id)}</code>
    </article>`
          )
          .join("");
}

function inferModelFromForm() {
  const customModel = el.inferenceModelCustom.value.trim();
  if (customModel) {
    return customModel;
  }
  if (el.inferenceModelPreset.value === "custom") {
    return "";
  }
  return el.inferenceModelPreset.value;
}

function syncInferenceModelSelect(model) {
  if (INFERENCE_MODEL_PRESETS.includes(model)) {
    el.inferenceModelPreset.value = model;
    el.inferenceModelCustom.value = "";
  } else {
    el.inferenceModelPreset.value = "custom";
    el.inferenceModelCustom.value = model;
  }
}

function syncInferenceControls(options = {}) {
  const { preferFormProvider = false } = options;
  const config = state.inferenceConfig || {};
  const selectedProvider = el.inferenceProvider.value;
  const configProvider =
    config.provider === "OpenRouter" || config.provider === "openrouter"
      ? "openrouter"
      : "llm_canister";
  const provider =
    preferFormProvider &&
    (selectedProvider === "openrouter" || selectedProvider === "llm_canister")
      ? selectedProvider
      : configProvider;
  const hasOpenRouterKey = Boolean(config.openrouter_has_api_key);
  const model = config.model || "";
  const isOpenRouter = provider === "openrouter" || provider === "OpenRouter";

  el.inferenceProvider.value = isOpenRouter ? "openrouter" : "llm_canister";
  syncInferenceModelSelect(model);
  el.inferenceModelSection.hidden = !isOpenRouter;
  el.inferenceKeySection.hidden = !isOpenRouter;
  el.inferenceModelPreset.disabled = !isOpenRouter;
  el.inferenceModelCustom.disabled = !isOpenRouter;

  el.inferenceKeyHelp.textContent = hasOpenRouterKey
    ? "Current key: present"
    : "Current key: not present";
  if (!isOpenRouter) {
    el.inferenceKeyHelp.textContent = "Key controls are available for OpenRouter only";
    el.inferenceKeyAction.value = "keep";
    el.inferenceApiKey.value = "";
  }

  el.inferenceKeyAction.disabled = !isOpenRouter;
  el.inferenceApiKey.disabled = !isOpenRouter;
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
    const outboxMessages = snapshot.outbox_messages || [];
    const jobs = snapshot.recent_jobs || [];
    const transitions = snapshot.recent_transitions || [];

    const runtimeState = runtime.state || "Unknown";
    const runtimeBadge =
      runtimeState === "Faulted" ? statusBadge(runtimeState, "danger") : statusBadge(runtimeState, "ok");
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
        `${escapeHtml(item.from_state || "?")} -> ${escapeHtml(item.to_state || "?")} · ${relativeTimeFromNs(
          item.occurred_at_ns
        )}`,
      state.knownTransitionIds
    );
    renderTimeline(
      el.jobs,
      jobs,
      "id",
      (item) =>
        `${escapeHtml(item.kind || "?")} · ${escapeHtml(item.status || "?")} · ${relativeTimeFromNs(
          item.finished_at_ns || item.created_at_ns
        )}`,
      state.knownJobIds
    );
    renderChat(el.chat, messages, outboxMessages);

    el.status.textContent = `Live · updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    el.status.textContent = `Snapshot error: ${error.message}`;
  }
}

async function refreshInferenceConfig() {
  try {
    const config = await apiFetch("/api/inference/config", { method: "GET" });
    state.inferenceConfig = config;
    if (!state.inferenceDirty) {
      syncInferenceControls();
      return;
    }
    const hasOpenRouterKey = Boolean(config.openrouter_has_api_key);
    el.inferenceKeyHelp.textContent = hasOpenRouterKey
      ? "Current key: present"
      : "Current key: not present";
    if (el.inferenceProvider.value !== "openrouter") {
      el.inferenceKeyHelp.textContent = "Key controls are available for OpenRouter only";
    }
  } catch (error) {
    el.inferenceStatus.textContent = `Inference config error: ${error.message}`;
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

async function applyInferenceConfig() {
  const provider = el.inferenceProvider.value;
  const model = inferModelFromForm();
  const keyAction = el.inferenceKeyAction.value;
  const apiKey = el.inferenceApiKey.value.trim();
  const isOpenRouter = provider === "openrouter";

  if (!provider) {
    el.inferenceStatus.textContent = "Provider is required.";
    return;
  }
  if (isOpenRouter && !model) {
    el.inferenceStatus.textContent = "Model is required for openrouter.";
    return;
  }
  if (!isOpenRouter) {
    if (keyAction !== "keep") {
      el.inferenceStatus.textContent =
        "Key actions are only available for OpenRouter.";
      return;
    }
  } else if (keyAction === "set" && !apiKey) {
    el.inferenceStatus.textContent = "API key is required when key action is set.";
    return;
  }

  const payload = {
    provider,
    key_action: isOpenRouter ? keyAction : "keep",
  };

  if (isOpenRouter && model) {
    payload.model = model;
  }

  if (keyAction === "set") {
    payload.api_key = apiKey;
  }

  el.inferenceSubmit.disabled = true;
  state.inferenceDirty = false;
  el.inferenceStatus.textContent = "Applying inference config...";
  try {
    await apiFetch("/api/inference/config", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    el.inferenceStatus.textContent = "Inference config updated.";
    if (keyAction !== "keep") {
      el.inferenceApiKey.value = "";
    }
    await refreshInferenceConfig();
    await refreshSnapshot();
  } catch (error) {
    state.inferenceDirty = true;
    el.inferenceStatus.textContent = `Inference config update failed: ${error.message}`;
  } finally {
    el.inferenceSubmit.disabled = false;
  }
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

el.inferenceForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await applyInferenceConfig();
});

el.inferenceModelPreset.addEventListener("change", () => {
  state.inferenceDirty = true;
  if (el.inferenceModelPreset.value === "custom") {
    el.inferenceModelCustom.focus();
  }
});

el.inferenceProvider.addEventListener("change", () => {
  state.inferenceDirty = true;
  syncInferenceControls({ preferFormProvider: true });
});

el.inferenceModelCustom.addEventListener("input", () => {
  state.inferenceDirty = true;
});

el.inferenceKeyAction.addEventListener("change", () => {
  state.inferenceDirty = true;
});

el.inferenceApiKey.addEventListener("input", () => {
  state.inferenceDirty = true;
});

async function boot() {
  await Promise.all([refreshInferenceConfig(), refreshSnapshot()]);
  state.pollHandle = setInterval(() => {
    refreshSnapshot();
    refreshInferenceConfig();
  }, POLL_MS);
}

boot();
