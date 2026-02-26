const DEFAULT_SNAPSHOT_PATH = '/api/snapshot';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_DEDUPE_TTL_SECS = 24 * 60 * 60;
const TERMINAL_JOB_STATUSES = new Set(['Failed', 'TimedOut', 'Skipped']);
const TOOL_FAILURE_PREFIX = 'tool execution reported failures:';
const DEDUPE_KEY_PREFIX = 'seen_event:';
const IN_MEMORY_DEDUPE = new Map();

export function normalizeBaseUrl(raw) {
  const trimmed = String(raw ?? '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    throw new Error('CANISTER_BASE_URL is required');
  }
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    throw new Error('CANISTER_BASE_URL must start with http:// or https://');
  }
  return trimmed;
}

export function normalizeIngestEndpoint(raw) {
  const trimmed = String(raw ?? '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    throw new Error('BETTERSTACK_INGESTING_HOST is required');
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

function requiredEnv(env, key) {
  const value = env[key];
  if (value === undefined || value === null || String(value).trim() === '') {
    throw new Error(`${key} is required`);
  }
  return String(value).trim();
}

function parsePositiveInt(raw, fallback, key) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  const parsed = Number.parseInt(String(raw), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${key} must be a positive integer`);
  }
  return parsed;
}

function parseBool(raw, fallback) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  const normalized = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  throw new Error('EMIT_HEALTH_LOG must be one of true/false/1/0/yes/no/on/off');
}

export function buildConfig(env) {
  const canisterBaseUrl = normalizeBaseUrl(requiredEnv(env, 'CANISTER_BASE_URL'));
  const snapshotPath = String(env.SNAPSHOT_PATH ?? DEFAULT_SNAPSHOT_PATH).trim();
  if (!snapshotPath.startsWith('/')) {
    throw new Error('SNAPSHOT_PATH must start with /');
  }

  const ingestUrl = normalizeIngestEndpoint(requiredEnv(env, 'BETTERSTACK_INGESTING_HOST'));
  const sourceToken = requiredEnv(env, 'BETTERSTACK_SOURCE_TOKEN');

  return {
    canisterBaseUrl,
    snapshotUrl: `${canisterBaseUrl}${snapshotPath}`,
    ingestUrl,
    sourceToken,
    timeoutMs: parsePositiveInt(env.HTTP_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 'HTTP_TIMEOUT_MS'),
    dedupeTtlSecs: parsePositiveInt(
      env.ERROR_DEDUPE_TTL_SECS,
      DEFAULT_DEDUPE_TTL_SECS,
      'ERROR_DEDUPE_TTL_SECS',
    ),
    emitHealthLog: parseBool(env.EMIT_HEALTH_LOG, false),
    source: String(env.LOG_SOURCE ?? 'ic-automaton-monitor').trim() || 'ic-automaton-monitor',
  };
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function toSnakeCase(raw) {
  return String(raw ?? '')
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[\s-]+/g, '_')
    .toLowerCase();
}

function inferSurvivalOperationFromJobKind(jobKind) {
  switch (String(jobKind ?? '').trim()) {
    case 'PollInbox':
      return 'evm_poll';
    case 'AgentTurn':
      return 'inference';
    default:
      return null;
  }
}

function extractSurvivalOperation(message, jobKind) {
  if (!nonEmptyString(message)) {
    return null;
  }
  const match = message.match(/\boperation\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b/);
  if (match) {
    return toSnakeCase(match[1]);
  }
  if (message.toLowerCase().includes('blocked by survival policy')) {
    return inferSurvivalOperationFromJobKind(jobKind);
  }
  return null;
}

function parseToolExecutionFailureMessage(message) {
  if (!nonEmptyString(message) || !message.startsWith(TOOL_FAILURE_PREFIX)) {
    return null;
  }

  const payloadRaw = message.slice(TOOL_FAILURE_PREFIX.length).trim();
  if (!payloadRaw.startsWith('{')) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(payloadRaw);
  } catch {
    return null;
  }

  const failedTools = Array.isArray(payload?.failures)
    ? payload.failures
        .map((entry) => {
          const tool = nonEmptyString(entry?.tool) ? entry.tool.trim() : null;
          const reason = nonEmptyString(entry?.reason) ? entry.reason.trim() : null;
          if (!tool || !reason) {
            return null;
          }
          return { tool, reason };
        })
        .filter(Boolean)
    : [];

  const payloadCount =
    Number.isFinite(payload?.count) && payload.count >= 0
      ? Math.trunc(payload.count)
      : failedTools.length;

  return {
    failedToolCount: Math.max(payloadCount, failedTools.length),
    failedTools,
    failedToolNames: [...new Set(failedTools.map((entry) => entry.tool))],
  };
}

function summarizeToolFailureMessage(toolFailure) {
  if (!toolFailure || !Array.isArray(toolFailure.failedTools) || toolFailure.failedTools.length === 0) {
    return null;
  }
  return toolFailure.failedTools
    .map((entry) => `${entry.tool}: ${entry.reason}`)
    .join(' | ')
    .slice(0, 500);
}

function stableHash(raw) {
  let hash = 5381;
  for (let i = 0; i < raw.length; i += 1) {
    hash = ((hash << 5) + hash) ^ raw.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function dedupeIdentityForEvent(event) {
  switch (event.category) {
    case 'runtime_last_error':
      return `${event.category}|${event.runtime_state ?? 'unknown'}|${event.turn_counter ?? 'unknown'}|${event.message}`;
    case 'scheduler_last_tick_error':
      return `${event.category}|${event.last_tick_finished_ns ?? 'unknown'}|${event.survival_tier ?? 'unknown'}|${event.message}`;
    case 'recent_job_error':
      return `${event.category}|${event.job_id ?? 'unknown'}|${event.job_status ?? 'unknown'}|${event.message}`;
    case 'recent_turn_error':
      return `${event.category}|${event.turn_id ?? 'unknown'}|${event.message}`;
    case 'recent_transition_error':
      return `${event.category}|${event.transition_id ?? 'unknown'}|${event.message}`;
    default:
      return `${event.category}|${event.message}`;
  }
}

function dedupeStorageKey(event) {
  const identity = dedupeIdentityForEvent(event);
  return `${DEDUPE_KEY_PREFIX}${stableHash(identity)}`;
}

function resolveDedupeStore(env) {
  if (env?.MONITOR_STATE_KV && typeof env.MONITOR_STATE_KV.get === 'function') {
    return { kind: 'kv', store: env.MONITOR_STATE_KV };
  }
  return { kind: 'memory', store: IN_MEMORY_DEDUPE };
}

async function hasSeenEvent(dedupeStore, key, nowMs) {
  if (dedupeStore.kind === 'kv') {
    const existing = await dedupeStore.store.get(key);
    return typeof existing === 'string' && existing.length > 0;
  }
  const expiresAtMs = dedupeStore.store.get(key);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
    dedupeStore.store.delete(key);
    return false;
  }
  return true;
}

async function markEventSeen(dedupeStore, key, ttlSecs, nowMs) {
  if (dedupeStore.kind === 'kv') {
    await dedupeStore.store.put(key, String(nowMs), { expirationTtl: ttlSecs });
    return;
  }
  dedupeStore.store.set(key, nowMs + ttlSecs * 1000);
}

export async function dedupeEvents(events, env, ttlSecs = DEFAULT_DEDUPE_TTL_SECS) {
  const dedupeStore = resolveDedupeStore(env);
  const nowMs = Date.now();
  const freshEvents = [];

  for (const event of events) {
    const key = dedupeStorageKey(event);
    // eslint-disable-next-line no-await-in-loop
    const seen = await hasSeenEvent(dedupeStore, key, nowMs);
    if (seen) {
      continue;
    }
    // eslint-disable-next-line no-await-in-loop
    await markEventSeen(dedupeStore, key, ttlSecs, nowMs);
    freshEvents.push(event);
  }

  return freshEvents;
}

function baseEvent(level, category, message, context) {
  return {
    dt: new Date().toISOString(),
    level,
    category,
    message,
    ...context,
  };
}

export function extractLogEvents(snapshot, options) {
  const emitHealthLog = Boolean(options.emitHealthLog);
  const trigger = options.trigger ?? 'manual';
  const canisterBaseUrl = options.canisterBaseUrl;

  const events = [];

  const runtime = snapshot?.runtime ?? {};
  const scheduler = snapshot?.scheduler ?? {};
  const recentJobs = Array.isArray(snapshot?.recent_jobs) ? snapshot.recent_jobs : [];
  const recentTurns = Array.isArray(snapshot?.recent_turns) ? snapshot.recent_turns : [];
  const recentTransitions = Array.isArray(snapshot?.recent_transitions)
    ? snapshot.recent_transitions
    : [];

  if (nonEmptyString(runtime.last_error)) {
    events.push(
      baseEvent('error', 'runtime_last_error', runtime.last_error, {
        source: 'ic-automaton-monitor',
        trigger,
        canister_base_url: canisterBaseUrl,
        runtime_state: runtime.state ?? null,
        turn_counter: runtime.turn_counter ?? null,
      }),
    );
  }

  if (nonEmptyString(scheduler.last_tick_error)) {
    events.push(
      baseEvent('error', 'scheduler_last_tick_error', scheduler.last_tick_error, {
        source: 'ic-automaton-monitor',
        trigger,
        canister_base_url: canisterBaseUrl,
        survival_tier: scheduler.survival_tier ?? null,
        low_cycles_mode: scheduler.low_cycles_mode ?? null,
        last_tick_finished_ns: scheduler.last_tick_finished_ns ?? null,
      }),
    );
  }

  for (const job of recentJobs) {
    const hasError = nonEmptyString(job?.last_error);
    const failedStatus = TERMINAL_JOB_STATUSES.has(String(job?.status ?? ''));
    if (!hasError && !failedStatus) {
      continue;
    }
    const rawMessage = hasError
      ? job.last_error
      : `job ${job?.id ?? 'unknown'} has status ${job?.status ?? 'unknown'}`;
    const survivalOperation = extractSurvivalOperation(rawMessage, job?.kind);
    const survivalBlocked = rawMessage.toLowerCase().includes('blocked by survival policy');
    const message =
      survivalBlocked && survivalOperation && !/\boperation\s*=/.test(rawMessage)
        ? `${rawMessage} (operation=${survivalOperation})`
        : rawMessage;

    events.push(
      baseEvent(
        'error',
        'recent_job_error',
        message,
        {
          source: 'ic-automaton-monitor',
          trigger,
          canister_base_url: canisterBaseUrl,
          job_id: job?.id ?? null,
          job_kind: job?.kind ?? null,
          job_status: job?.status ?? null,
          job_attempts: job?.attempts ?? null,
          survival_policy_blocked: survivalBlocked,
          survival_operation: survivalOperation,
        },
      ),
    );
  }

  for (const turn of recentTurns) {
    if (!nonEmptyString(turn?.error)) {
      continue;
    }
    const toolFailure = parseToolExecutionFailureMessage(turn.error);
    const summarizedToolFailure = summarizeToolFailureMessage(toolFailure);
    const message = summarizedToolFailure
      ? `${TOOL_FAILURE_PREFIX} ${summarizedToolFailure}`
      : turn.error;
    events.push(
      baseEvent('error', 'recent_turn_error', message, {
        source: 'ic-automaton-monitor',
        trigger,
        canister_base_url: canisterBaseUrl,
        turn_id: turn?.id ?? null,
        state_from: turn?.state_from ?? null,
        state_to: turn?.state_to ?? null,
        turn_tool_call_count: turn?.tool_call_count ?? null,
        turn_inference_round_count: turn?.inference_round_count ?? null,
        turn_continuation_stop_reason: turn?.continuation_stop_reason ?? null,
        turn_error_kind: toolFailure ? 'tool_execution_failures' : null,
        failed_tool_count: toolFailure?.failedToolCount ?? null,
        failed_tool_names: toolFailure?.failedToolNames ?? null,
        failed_tools: toolFailure?.failedTools ?? null,
        turn_error_raw: turn.error,
      }),
    );
  }

  for (const transition of recentTransitions) {
    if (!nonEmptyString(transition?.error)) {
      continue;
    }
    events.push(
      baseEvent('error', 'recent_transition_error', transition.error, {
        source: 'ic-automaton-monitor',
        trigger,
        canister_base_url: canisterBaseUrl,
        transition_id: transition?.id ?? null,
        transition_event: transition?.event ?? null,
        to_state: transition?.to_state ?? null,
      }),
    );
  }

  if (events.length === 0 && emitHealthLog) {
    events.push(
      baseEvent('info', 'health_heartbeat', 'snapshot healthy: no errors detected', {
        source: 'ic-automaton-monitor',
        trigger,
        canister_base_url: canisterBaseUrl,
        runtime_state: runtime.state ?? null,
        survival_tier: scheduler.survival_tier ?? null,
        turn_counter: runtime.turn_counter ?? null,
      }),
    );
  }

  return events;
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
      signal: controller.signal,
      cf: {
        cacheEverything: false,
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchSnapshot(config) {
  const response = await fetchWithTimeout(config.snapshotUrl, config.timeoutMs);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `snapshot request failed with ${response.status} ${response.statusText}: ${body.slice(0, 400)}`,
    );
  }
  return response.json();
}

async function sendToBetterStack(events, config) {
  if (events.length === 0) {
    return { sent: 0, status: null };
  }

  const response = await fetch(config.ingestUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.sourceToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(events),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `better stack ingest failed with ${response.status} ${response.statusText}: ${body.slice(0, 400)}`,
    );
  }

  return { sent: events.length, status: response.status };
}

export async function runForwarder(env, trigger) {
  const config = buildConfig(env);
  const snapshot = await fetchSnapshot(config);
  const extractedEvents = extractLogEvents(snapshot, {
    canisterBaseUrl: config.canisterBaseUrl,
    trigger,
    emitHealthLog: config.emitHealthLog,
  }).map((event) => ({ ...event, source: config.source }));
  const events = await dedupeEvents(extractedEvents, env, config.dedupeTtlSecs);

  const ingest = await sendToBetterStack(events, config);

  return {
    ok: true,
    trigger,
    snapshot_url: config.snapshotUrl,
    events_extracted: extractedEvents.length,
    events_deduped: extractedEvents.length - events.length,
    events_sent: ingest.sent,
    ingest_status: ingest.status,
  };
}

async function emitWorkerFailureLog(env, trigger, errorMessage) {
  try {
    const config = buildConfig(env);
    const event = baseEvent('error', 'worker_failure', errorMessage, {
      source: config.source,
      trigger,
      canister_base_url: config.canisterBaseUrl,
    });
    await sendToBetterStack([event], config);
  } catch (emitError) {
    const message = emitError instanceof Error ? emitError.message : String(emitError);
    console.error('worker_failure_log_emit_failed', { trigger, message });
  }
}

async function runSafely(env, trigger) {
  try {
    return await runForwarder(env, trigger);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await emitWorkerFailureLog(env, trigger, message);
    return {
      ok: false,
      trigger,
      error: message,
    };
  }
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runSafely(env, `scheduled:${event.cron ?? 'unknown'}`).then((result) => {
        if (!result.ok) {
          console.error('scheduled_run_failed', result);
        } else {
          console.log('scheduled_run_ok', result);
        }
      }),
    );
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return Response.json({ ok: true });
    }

    if (url.pathname === '/run' && (request.method === 'GET' || request.method === 'POST')) {
      const result = await runSafely(env, 'manual');
      return Response.json(result, { status: result.ok ? 200 : 500 });
    }

    return Response.json(
      {
        ok: false,
        error: 'not found',
        routes: ['GET /health', 'GET|POST /run'],
      },
      { status: 404 },
    );
  },
};
