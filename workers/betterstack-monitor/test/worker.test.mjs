import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildConfig,
  dedupeEvents,
  extractLogEvents,
  normalizeBaseUrl,
  normalizeIngestEndpoint,
} from '../src/worker.js';

test('normalizeBaseUrl strips trailing slash and rejects non-http', () => {
  assert.equal(normalizeBaseUrl('https://example.com/'), 'https://example.com');
  assert.equal(normalizeBaseUrl('http://localhost:4943'), 'http://localhost:4943');
  assert.throws(() => normalizeBaseUrl('ftp://example.com'), /must start with http/);
});

test('normalizeIngestEndpoint accepts bare host and full URL', () => {
  assert.equal(
    normalizeIngestEndpoint('s123456.eu-nbg-2.betterstackdata.com'),
    'https://s123456.eu-nbg-2.betterstackdata.com',
  );
  assert.equal(
    normalizeIngestEndpoint('https://s123456.eu-nbg-2.betterstackdata.com/'),
    'https://s123456.eu-nbg-2.betterstackdata.com',
  );
});

test('buildConfig validates required env vars', () => {
  assert.throws(() => buildConfig({}), /CANISTER_BASE_URL/);
  assert.throws(
    () =>
      buildConfig({
        CANISTER_BASE_URL: 'https://example.com',
      }),
    /BETTERSTACK_INGESTING_HOST/,
  );
  assert.throws(
    () =>
      buildConfig({
        CANISTER_BASE_URL: 'https://example.com',
        BETTERSTACK_INGESTING_HOST: 'https://logs.example.com',
      }),
    /BETTERSTACK_SOURCE_TOKEN/,
  );
});

test('buildConfig sets defaults and keeps explicit overrides', () => {
  const config = buildConfig({
    CANISTER_BASE_URL: 'https://abcde-aaaaa-aaaab-qaxuq-cai.icp0.io/',
    BETTERSTACK_INGESTING_HOST: 's123456.eu-nbg-2.betterstackdata.com',
    BETTERSTACK_SOURCE_TOKEN: 'token-123',
    SNAPSHOT_PATH: '/custom/snapshot',
    HTTP_TIMEOUT_MS: '7000',
    EMIT_HEALTH_LOG: 'true',
  });

  assert.equal(config.snapshotUrl, 'https://abcde-aaaaa-aaaab-qaxuq-cai.icp0.io/custom/snapshot');
  assert.equal(config.ingestUrl, 'https://s123456.eu-nbg-2.betterstackdata.com');
  assert.equal(config.sourceToken, 'token-123');
  assert.equal(config.timeoutMs, 7000);
  assert.equal(config.emitHealthLog, true);
});

test('extractLogEvents returns structured errors from snapshot', () => {
  const snapshot = {
    runtime: {
      last_error: 'runtime failed to advance state',
      state: 'Faulted',
      turn_counter: 42,
    },
    scheduler: {
      last_tick_error: 'tick failed due to rpc timeout',
      survival_tier: 'Critical',
      low_cycles_mode: true,
    },
    recent_jobs: [
      {
        id: 'job-1',
        kind: 'PollInbox',
        status: 'Failed',
        last_error: 'eth_getLogs timeout',
        attempts: 3,
      },
      {
        id: 'job-2',
        kind: 'AgentTurn',
        status: 'Succeeded',
        last_error: null,
      },
    ],
    recent_turns: [
      {
        id: 'turn-1',
        error: 'inference failed',
      },
    ],
    recent_transitions: [
      {
        id: 'tr-1',
        event: 'TurnFailed',
        error: 'bad tool args',
      },
    ],
  };

  const events = extractLogEvents(snapshot, {
    canisterBaseUrl: 'https://abcde-aaaaa-aaaab-qaxuq-cai.icp0.io',
    trigger: 'scheduled',
    emitHealthLog: false,
  });

  assert.equal(events.length, 5);
  const categories = events.map((event) => event.category).sort();
  assert.deepEqual(categories, [
    'recent_job_error',
    'recent_transition_error',
    'recent_turn_error',
    'runtime_last_error',
    'scheduler_last_tick_error',
  ]);
});

test('extractLogEvents emits health log when enabled and no errors found', () => {
  const snapshot = {
    runtime: {
      last_error: null,
      state: 'Running',
      turn_counter: 7,
    },
    scheduler: {
      last_tick_error: null,
      survival_tier: 'Normal',
      low_cycles_mode: false,
    },
    recent_jobs: [],
    recent_turns: [],
    recent_transitions: [],
  };

  const events = extractLogEvents(snapshot, {
    canisterBaseUrl: 'https://abcde-aaaaa-aaaab-qaxuq-cai.icp0.io',
    trigger: 'scheduled',
    emitHealthLog: true,
  });

  assert.equal(events.length, 1);
  assert.equal(events[0].level, 'info');
  assert.equal(events[0].category, 'health_heartbeat');
});

test('extractLogEvents includes survival operation details for survival-policy blocks', () => {
  const snapshot = {
    runtime: { last_error: null },
    scheduler: { last_tick_error: null },
    recent_jobs: [
      {
        id: 'job-1',
        kind: 'PollInbox',
        status: 'Skipped',
        last_error: 'operation blocked by survival policy',
        attempts: 2,
      },
      {
        id: 'job-2',
        kind: 'AgentTurn',
        status: 'Skipped',
        last_error: 'operation blocked by survival policy (operation=Inference)',
        attempts: 1,
      },
    ],
    recent_turns: [],
    recent_transitions: [],
  };

  const events = extractLogEvents(snapshot, {
    canisterBaseUrl: 'https://abcde-aaaaa-aaaab-qaxuq-cai.icp0.io',
    trigger: 'scheduled',
    emitHealthLog: false,
  });

  assert.equal(events.length, 2);
  assert.equal(events[0].survival_policy_blocked, true);
  assert.equal(events[0].survival_operation, 'evm_poll');
  assert.equal(events[0].message, 'operation blocked by survival policy (operation=evm_poll)');
  assert.equal(events[1].survival_policy_blocked, true);
  assert.equal(events[1].survival_operation, 'inference');
});

test('extractLogEvents parses structured tool-failure details from turn errors', () => {
  const snapshot = {
    runtime: { last_error: null },
    scheduler: { last_tick_error: null },
    recent_jobs: [],
    recent_turns: [
      {
        id: 'turn-451',
        state_from: 'Sleeping',
        state_to: 'Faulted',
        tool_call_count: 2,
        inference_round_count: 1,
        continuation_stop_reason: 'None',
        error:
          'tool execution reported failures: {"count":2,"shown":2,"omitted":0,"failures":[{"tool":"evm_read","reason":"rpc timeout"},{"tool":"http_fetch","reason":"HTTP 404 from https://example.com/missing"}]}',
      },
    ],
    recent_transitions: [],
  };

  const events = extractLogEvents(snapshot, {
    canisterBaseUrl: 'https://abcde-aaaaa-aaaab-qaxuq-cai.icp0.io',
    trigger: 'scheduled',
    emitHealthLog: false,
  });

  assert.equal(events.length, 1);
  assert.equal(events[0].category, 'recent_turn_error');
  assert.equal(
    events[0].message,
    'tool execution reported failures: evm_read: rpc timeout | http_fetch: HTTP 404 from https://example.com/missing',
  );
  assert.equal(events[0].turn_error_kind, 'tool_execution_failures');
  assert.equal(events[0].failed_tool_count, 2);
  assert.equal(events[0].turn_tool_call_count, 2);
  assert.equal(events[0].turn_inference_round_count, 1);
  assert.equal(events[0].turn_continuation_stop_reason, 'None');
  assert.deepEqual(events[0].failed_tool_names, ['evm_read', 'http_fetch']);
  assert.deepEqual(events[0].failed_tools, [
    { tool: 'evm_read', reason: 'rpc timeout' },
    { tool: 'http_fetch', reason: 'HTTP 404 from https://example.com/missing' },
  ]);
});

test('dedupeEvents suppresses repeated event payloads across runs via KV store', async () => {
  const kvBacking = new Map();
  const env = {
    MONITOR_STATE_KV: {
      async get(key) {
        return kvBacking.has(key) ? kvBacking.get(key) : null;
      },
      async put(key, value) {
        kvBacking.set(key, value);
      },
    },
  };
  const events = [
    {
      category: 'recent_turn_error',
      message: 'tool execution reported failures: http_fetch: HTTP 404',
      turn_id: 'turn-461',
    },
    {
      category: 'recent_turn_error',
      message: 'tool execution reported failures: http_fetch: timeout',
      turn_id: 'turn-489',
    },
  ];

  const first = await dedupeEvents(events, env, 60);
  assert.equal(first.length, 2);

  const second = await dedupeEvents(events, env, 60);
  assert.equal(second.length, 0);

  const changed = await dedupeEvents(
    [
      {
        category: 'recent_turn_error',
        message: 'tool execution reported failures: http_fetch: timeout',
        turn_id: 'turn-490',
      },
    ],
    env,
    60,
  );
  assert.equal(changed.length, 1);
});
