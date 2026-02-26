# Better Stack Monitor Worker

Cloudflare Worker that polls `ic-automaton` HTTP snapshot endpoint and forwards structured error logs to Better Stack Logs.

## What it does

- Fetches `GET /api/snapshot` from your canister.
- Extracts error signals from:
  - `runtime.last_error`
  - `scheduler.last_tick_error`
  - `recent_jobs` with terminal failure states or `last_error`
  - `recent_turns` with `error`
  - `recent_transitions` with `error`
- Sends extracted records to Better Stack log ingest.
- For structured turn tool failures (`tool execution reported failures: {...}`), forwards parsed fields:
  - `failed_tool_count`
  - `failed_tool_names`
  - `failed_tools` (`[{ tool, reason }]`)
- Supports cron runs and manual run endpoint.

## Routes

- `GET /health` -> returns `{ "ok": true }`
- `GET|POST /run` -> runs one poll/forward cycle immediately

## Configuration

Set these in `wrangler.toml` / Cloudflare dashboard:

- `CANISTER_BASE_URL` (required)
  - Example: `https://<canister-id>.icp0.io`
- `BETTERSTACK_INGESTING_HOST` (required)
  - Example: `s123456.eu-nbg-2.betterstackdata.com`
- `BETTERSTACK_SOURCE_TOKEN` (required secret)
- `SNAPSHOT_PATH` (optional, default `/api/snapshot`)
- `HTTP_TIMEOUT_MS` (optional, default `10000`)
- `EMIT_HEALTH_LOG` (optional, default `false`)
- `LOG_SOURCE` (optional, default `ic-automaton-monitor`)
- `ERROR_DEDUPE_TTL_SECS` (optional, default `86400`)
  - Dedupe retention window for already-forwarded error events.

Optional but recommended:
- `MONITOR_STATE_KV` (Workers KV binding)
  - Enables cross-run dedupe by event identity (`turn_id`, `job_id`, `transition_id`, message hash).
  - Without KV, the worker falls back to in-memory dedupe per isolate.

## Deploy

```bash
cd workers/betterstack-monitor

# Set secret once (token only)
wrangler secret put BETTERSTACK_SOURCE_TOKEN

# Recommended: create + bind KV for cross-run dedupe
wrangler kv namespace create MONITOR_STATE
wrangler kv namespace create MONITOR_STATE --preview

# Deploy
wrangler deploy
```

## Local tests

```bash
cd workers/betterstack-monitor
npm test
```

## Recommended production setup

- Keep cron at `*/1 * * * *` initially.
- Add Better Stack alerts for:
  - `category = runtime_last_error`
  - `category = scheduler_last_tick_error`
  - `category = recent_job_error`
- If logs are too noisy, disable `EMIT_HEALTH_LOG` (already false by default).
