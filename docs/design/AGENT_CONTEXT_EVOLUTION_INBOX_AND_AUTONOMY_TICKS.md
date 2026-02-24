# Agent Context Evolution: Inbox Messages vs Autonomy Ticks

**Date:** 2026-02-23  
**Status:** Implementation-aligned reference  
**Scope:** Show, visually and concretely, how per-turn context changes over time as inbox messages move through `Pending -> Staged -> Consumed` and as scheduler-driven `autonomy_tick` turns run.

## Why this matters

The agent only reasons over what is staged for the current turn plus durable memory/state.  
Understanding this timeline is critical for autonomy behavior, response latency, and debugging "why did the model see this context now vs later?".

## Core model (at a glance)

```text
External input arrives
  -> inbox message stored as Pending
  -> PollInbox job stages Pending -> Staged
  -> AgentTurn reads Staged and builds Layer 10
  -> Agent may reply, then marks Staged -> Consumed
  -> Next turns use durable artifacts (memory/tools/turn records), not consumed raw inbox
```

## Scheduler ordering that shapes context timing

```text
Within one scheduler tick, due jobs are processed by priority:

1. AgentTurn (priority 0)
2. PollInbox  (priority 1)
3. CheckCycles
4. TopUpCycles
5. Reconcile
```

Practical consequence:

- If both `AgentTurn` and `PollInbox` are due in the same tick, `AgentTurn` runs first.
- Messages discovered/staged by `PollInbox` in that tick are typically visible to the **next** `AgentTurn`, not the one that already ran.

## Visual timeline

### Scenario A: One sender message arrives, then autonomy continues

```text
Time --->

T0
  Inbox receives "hello" from 0xAAA
  Storage:
    inbox:0001 = Pending
  Agent context impact: none yet

T1 (scheduler tick runs PollInbox)
  PollInbox stages pending messages
  Storage:
    inbox:0001 = Staged
  Agent context impact: available for next AgentTurn

T2 (scheduler tick runs AgentTurn)
  AgentTurn loads staged messages [inbox:0001]
  Inference input:
    input = "inbox:hello"
  Layer 10 includes:
    - Pending Obligations: staged_count=1, sender=0xAAA, preview=hello
    - Conversation History: prior entries for active sender 0xAAA (if any)
    - Recent Memory / wallet / tools / survival state
  If reply is produced:
    - outbox message created with source_inbox_ids=[inbox:0001]
    - conversation entry appended for sender 0xAAA
    - inbox:0001 marked Consumed

T3 (next AgentTurn, no staged input)
  Inference input:
    input = "autonomy_tick"
  Layer 10 includes:
    - Pending Obligations: staged_count=0
    - Conversation History: none (no active staged senders this turn)
    - Recent Memory / wallet / tools / survival state still present
```

### Scenario B: Poll and turn due together

```text
Tick N start
  AgentTurn runs first -> builds context from already-staged messages only
  PollInbox runs second -> ingests new events and stages new pending messages
Tick N end

Tick N+1
  AgentTurn now sees those newly staged messages in Layer 10
```

## What changes in context between turn types

| Turn type | `InferenceInput.input` | Layer 10 Pending Obligations | Layer 10 Conversation History |
|---|---|---|---|
| Inbox-driven turn | `inbox:<joined staged bodies>` | Lists staged message ids/senders/previews | Included for active staged senders only |
| Autonomy tick | `autonomy_tick` | `staged_count: 0` + `none` | `none` |

## Context composition (current implementation)

Each turn builds Layer 10 with these stable sections:

1. `Current State` (cycles, survival tier, wallet balances/freshness, state, turn metadata)
2. `Pending Obligations` (derived from staged inbox messages)
3. `Conversation History` (scoped to staged-message senders for this turn)
4. `Recent Memory` (raw facts, then rollups when raw budget is filled)
5. `Available Tools` (with per-turn call counts)

So "context evolution" is mostly:

- immediate change: staged inbox set for the turn,
- plus durable accumulation: conversation log entries, memory facts/rollups, and prior tool usage records.

## Storage-state evolution map

```text
Message lifecycle (single id):

post_inbox_message()
  -> INBOX_MAP[id].status = Pending
  -> INBOX_PENDING_QUEUE_MAP += id

stage_pending_inbox_messages()
  -> status Pending -> Staged
  -> staged_at_ns set
  -> INBOX_PENDING_QUEUE_MAP -= id
  -> INBOX_STAGED_QUEUE_MAP += id

consume_staged_inbox_messages()
  -> status Staged -> Consumed
  -> consumed_at_ns set
  -> INBOX_STAGED_QUEUE_MAP -= id
```

## Mental model for operators/builders

```text
The agent does not read "all inbox history" each turn.
It reads only currently staged inbox messages as active obligations.
Everything else influences behavior through durable summaries:
memory, conversation logs (when sender is active), and runtime telemetry.
```

## Code pointers

- Turn context build and `inbox` vs `autonomy_tick` input: `src/agent.rs`
- Polling/staging flow and job ordering: `src/scheduler.rs`
- Inbox status transitions and queues: `src/storage/stable.rs`
- State transition graph for each turn: `src/domain/state_machine.rs`
