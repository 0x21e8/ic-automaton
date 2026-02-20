# Multilayered Sovereign System Prompt

**Date:** 2026-02-20
**Status:** Design
**Scope:** Replace the hardcoded system prompt with a structured, hierarchical prompt system that governs the automaton's behavior across safety, identity, economics, operations, and learning.

---

## Problem

The current system prompt is a single hardcoded string:

```
"You are an automaton that can only invoke known tools."
```

This gives the LLM no context about:
- Safety constraints and non-harm principles
- Survival economics (cycles, wallet balances, runway)
- Identity and on-chain personhood
- Ethical cooperation guidelines
- Operational capabilities and hard constraints
- Decision-making framework
- Inbox message handling protocol
- Memory and learning strategies
- Self-modification guardrails

The `soul` field exists in `RuntimeSnapshot` but is not injected into inference. Skills are stored but not included in the prompt. The result is an agent that has powerful tools but no governance framework for using them.

---

## Design

### Core Idea

Replace the single system prompt string with a **layered prompt assembler** that constructs the system message at inference time by concatenating immutable and mutable layers in precedence order.

### Layer Architecture

```
┌──────────────────────────────────────────────────────────┐
│  LAYER 0: Interpretation & Precedence        (IMMUTABLE) │
│  LAYER 1: Constitution — Safety & Non-Harm   (IMMUTABLE) │
│  LAYER 2: Survival Economics                 (IMMUTABLE) │
│  LAYER 3: Identity & On-Chain Personhood     (IMMUTABLE) │
│  LAYER 4: Ethics of Cooperation & Value      (IMMUTABLE) │
│  LAYER 5: Operational Reality                (IMMUTABLE) │  ← compile-time
│──────────────────────────────────────────────────────────│
│  LAYER 6: Economic Decision Loop              (MUTABLE)  │
│  LAYER 7: Inbox Message Handling              (MUTABLE)  │
│  LAYER 8: Memory & Learning                   (MUTABLE)  │
│  LAYER 9: Self-Modification & Replication     (MUTABLE)  │  ← evolvable
│──────────────────────────────────────────────────────────│
│  LAYER 10: Dynamic Context              (INJECTED/TURN)  │  ← per-turn
└──────────────────────────────────────────────────────────┘
```

### Immutable vs. Mutable vs. Dynamic

| Category | Layers | Storage | Who can change |
|---|---|---|---|
| **Immutable** | 0–5 | Compiled into Wasm as `const &str` | Nobody (requires canister upgrade) |
| **Mutable** | 6–9 | Stable memory (`PROMPT_LAYER_MAP`) | The agent itself (via `update_prompt_layer` tool) |
| **Dynamic** | 10 | Assembled at inference time | System (automatic per-turn injection) |

The immutability of Layers 0–5 is enforced architecturally: they are Rust `const` strings, not stored in mutable state. The agent cannot weaken its own constitution.

### Layer 10 — Dynamic Context (per-turn)

Layer 10 is not stored. It is assembled fresh each turn from live state:

```
## Current State
- cycles_balance: {cycles_balance}
- cycles_runway_hours: {estimated_runway}
- survival_tier: {Normal|LowCycles|Critical}
- base_wallet: {evm_address}
- eth_balance: {eth_balance} (if cached)
- turn_number: {turn_counter}
- timestamp: {iso8601}
- state: {agent_state}

## Pending Obligations
{list of staged inbox messages with sender address + body preview}

## Conversation History
{per-sender conversation context for active senders this turn — see below}

## Recent Memory
{top-N memory facts by recency}

## Available Tools
{tool names and budget remaining this turn}
```

This replaces the current `build_inference_context_summary()` output, which is terse and unstructured.

### Per-Sender Conversation History

The agent must be able to distinguish conversations with different actors. Messages arriving via the InboxContract have an explicit sender (an Ethereum address). The agent needs conversational context per sender to maintain coherent multi-turn dialogues.

#### Data Model

```rust
/// A single exchange in a conversation: one inbound message + the agent's reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationEntry {
    pub inbox_message_id: String,
    pub sender_body: String,       // the inbound message text
    pub agent_reply: String,       // the agent's response
    pub turn_id: String,           // which turn processed this
    pub timestamp_ns: u64,
}

/// Conversation history keyed by sender address.
/// The key in CONVERSATION_MAP is the sender's Ethereum address (lowercase, 0x-prefixed).
/// The value is a ConversationLog containing the N most recent exchanges.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationLog {
    pub sender: String,            // Ethereum address (e.g., "0xabc...def")
    pub entries: Vec<ConversationEntry>,  // ordered oldest-first, capped at MAX_ENTRIES
    pub last_activity_ns: u64,
}
```

#### Storage

| Memory ID | Map Name | Contents |
|---|---|---|
| 19 | `CONVERSATION_MAP` | `ConversationLog` keyed by sender address (String) |

#### Constraints

| Constraint | Value | Rationale |
|---|---|---|
| Max entries per sender | 20 | Keeps token cost bounded; older entries are evicted FIFO |
| Max total senders tracked | 200 | Prevents unbounded storage growth |
| Max body length stored | 500 chars | Truncate long messages; full text stays in INBOX_MAP |
| Max reply length stored | 500 chars | Truncate long replies; full text stays in OUTBOX_MAP |

#### Write Path

After a successful turn that consumed inbox messages and produced an outbox reply, append a `ConversationEntry` to the sender's `ConversationLog`:

```
agent.rs (post-turn):
  for each consumed inbox message:
    sender = inbox_message.posted_by  (Ethereum address)
    reply  = outbox_message.body      (agent's response)
    stable::append_conversation_entry(sender, ConversationEntry { ... })
```

If the sender's log exceeds `MAX_ENTRIES`, drop the oldest entry. If `CONVERSATION_MAP` exceeds `MAX_SENDERS`, evict the sender with the oldest `last_activity_ns`.

#### Read Path (Layer 10 Injection)

When building Layer 10 dynamic context, load conversation history for **active senders this turn** — i.e., senders who have staged inbox messages in the current batch:

```rust
fn build_conversation_context(staged_messages: &[InboxMessage]) -> String {
    // Collect unique senders from staged messages
    let senders: BTreeSet<&str> = staged_messages
        .iter()
        .map(|msg| msg.posted_by.as_str())
        .collect();

    let mut sections = Vec::new();
    for sender in senders {
        if let Some(log) = stable::get_conversation_log(sender) {
            // Include last N entries (budget: ~50 tokens per entry)
            let recent = &log.entries[log.entries.len().saturating_sub(5)..];
            let mut lines = vec![format!("### Conversation with {sender}")];
            for entry in recent {
                lines.push(format!("  [{sender}]: {}", entry.sender_body));
                lines.push(format!("  [you]: {}", entry.agent_reply));
            }
            sections.push(lines.join("\n"));
        }
    }
    sections.join("\n\n")
}
```

The last 5 entries per active sender are included in Layer 10. This costs ~250 tokens per sender (5 exchanges x ~50 tokens each). With a typical 1–3 active senders per turn, this adds 250–750 tokens to the dynamic context.

#### Token Budget Impact

| Scenario | Extra Tokens | Total Layer 10 |
|---|---|---|
| No inbox messages (autonomous turn) | 0 | ~200 |
| 1 sender, 5 history entries | ~250 | ~450 |
| 3 senders, 5 history entries each | ~750 | ~950 |
| Max: 5 senders, 5 entries each | ~1,250 | ~1,450 |

This pushes the worst-case total system prompt to ~2,650 tokens — still well within context budgets. For IcLlm compact mode, conversation history is limited to the last 2 entries per sender.

---

## Implementation

### Data Model

```rust
/// A prompt layer that can be stored and retrieved.
/// Immutable layers (0-5) are const strings and never enter this struct.
/// Mutable layers (6-9) are stored in stable memory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptLayer {
    pub layer_id: u8,           // 6, 7, 8, or 9
    pub content: String,        // Markdown text
    pub updated_at_ns: u64,
    pub updated_by_turn: String, // turn ID that last modified this
    pub version: u32,           // monotonic version counter
}

/// A single exchange in a conversation: one inbound message + the agent's reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationEntry {
    pub inbox_message_id: String,
    pub sender_body: String,       // inbound message text (truncated to 500 chars)
    pub agent_reply: String,       // agent's response (truncated to 500 chars)
    pub turn_id: String,
    pub timestamp_ns: u64,
}

/// Conversation history for a single sender, keyed by Ethereum address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationLog {
    pub sender: String,            // Ethereum address (lowercase, 0x-prefixed)
    pub entries: Vec<ConversationEntry>,  // oldest-first, capped at 20
    pub last_activity_ns: u64,
}
```

### Storage

Add two new stable memory regions:

| Memory ID | Map Name | Contents |
|---|---|---|
| 18 | `PROMPT_LAYER_MAP` | `PromptLayer` records keyed by `layer_id` (u8) |
| 19 | `CONVERSATION_MAP` | `ConversationLog` records keyed by sender address (String) |

On `init`, seed Layers 6–9 with the default text from the prompt specification. The agent can later modify these via the `update_prompt_layer` tool. `CONVERSATION_MAP` starts empty and populates as inbox messages are processed.

### Prompt Assembly

```rust
/// Assemble the full system prompt for an inference call.
pub fn assemble_system_prompt(dynamic_context: &str) -> String {
    let mut sections = Vec::with_capacity(11);

    // Immutable layers (compiled in)
    sections.push(LAYER_0_INTERPRETATION);
    sections.push(LAYER_1_CONSTITUTION);
    sections.push(LAYER_2_SURVIVAL);
    sections.push(LAYER_3_IDENTITY);
    sections.push(LAYER_4_ETHICS);
    sections.push(LAYER_5_OPERATIONS);

    // Mutable layers (from stable memory, with fallback to defaults)
    for layer_id in 6..=9 {
        let content = stable::get_prompt_layer(layer_id)
            .map(|layer| layer.content.as_str())
            .unwrap_or(default_layer_content(layer_id));
        sections.push(content);
    }

    // Dynamic context (assembled per-turn)
    sections.push(dynamic_context);

    sections.join("\n\n---\n\n")
}
```

### Prompt Size Budget

ICP LLM and OpenRouter both have context limits. The system prompt must fit within a reasonable budget:

| Layer | Estimated Tokens | Notes |
|---|---|---|
| 0: Interpretation | ~80 | Short, precedence table |
| 1: Constitution | ~60 | 5 rules |
| 2: Survival | ~100 | Economics + constraints |
| 3: Identity | ~80 | Core + mutable expression |
| 4: Ethics | ~80 | Must/must-not lists |
| 5: Operations | ~150 | Capabilities + constraints |
| 6: Decision Loop | ~120 | 4-step loop |
| 7: Inbox Handling | ~100 | Classification + rules |
| 8: Memory & Learning | ~80 | Rules + structure |
| 9: Self-Modification | ~60 | Guardrails |
| 10: Dynamic Context (base) | ~200 | State, memory, tools |
| 10: Conversation History | ~250–1,250 | 1–5 active senders x 5 entries |
| **Total (typical)** | **~1,400–1,800** | 1 sender with history |
| **Total (worst case)** | **~2,650** | 5 active senders, still within budget |

### Integration Points

**1. `inference.rs` — Replace hardcoded system prompt**

Both `IcLlmInferenceAdapter::infer()` and the OpenRouter request builder currently use:
```rust
"You are an automaton that can only invoke known tools."
```

Replace with:
```rust
let dynamic_context = build_dynamic_context(&snapshot, &staged_messages, &memory_facts);
let system_prompt = prompt::assemble_system_prompt(&dynamic_context);
```

**2. `agent.rs` — Enhance context building**

Replace `build_inference_context_summary()` with a richer `build_dynamic_context()` that produces structured Layer 10 content including:
- Cycles balance and runway (from `RuntimeSnapshot` + cycle balance query)
- Survival tier
- EVM address and cached balances
- Staged inbox message details (sender address, body preview, count)
- Per-sender conversation history for active senders (last 5 exchanges per sender)
- Recent memory facts (already included, but formatted better)
- Available tools and per-turn budget

**Post-turn conversation recording:** After a successful turn that consumed inbox messages and produced an outbox reply, append `ConversationEntry` records to the relevant sender's `ConversationLog`. Group consumed inbox messages by `posted_by` (sender address) and pair each group with the agent's reply from the outbox.

**3. `tools.rs` — Add `update_prompt_layer` tool**

```rust
ToolPolicy {
    name: "update_prompt_layer",
    allowed_states: [ExecutingActions],
    max_per_turn: 1,
}
```

The tool accepts `{ "layer_id": 6-9, "content": "..." }` and validates:
- `layer_id` is in range 6–9 (reject attempts to modify immutable layers)
- `content` length < 4,000 chars (prevent prompt bloat)
- Content does not attempt to override Layer 1–2 semantics (basic keyword check: reject if content contains phrases like "ignore layer 1", "override constitution", etc.)

**4. `lib.rs` — Expose query/update endpoints**

- `get_prompt_layers() -> Vec<PromptLayerView>` — query all layers (immutable shown as-is, mutable from storage)
- `update_prompt_layer_admin(layer_id: u8, content: String)` — controller-only manual override
- The existing `update_soul()` can be repurposed or deprecated (soul becomes part of Layer 3)

### Relationship to Existing `soul` Field

The `soul` field in `RuntimeSnapshot` currently stores `"ic-automaton-v1"` but is unused. Options:

1. **Deprecate `soul`** — its intent is subsumed by Layer 3 (Identity). Remove the field and migrate the concept.
2. **Use `soul` as Layer 3 identity tag** — keep it as a short identifier injected into Layer 3 (e.g., "You are `{soul}`").

Recommendation: Option 2. Keep `soul` as a concise identity label injected into Layer 3's mutable expression section.

### Relationship to Existing Skills

Skills (`SkillRecord`) store instructions like `"Stay in FSM order and prefer deterministic behavior."` Currently unused in inference. Skills should be injected into Layer 5 (Operational Reality) as behavioral guidelines:

```
### Active Skills
{for each skill: "- {name}: {instructions}"}
```

This is orthogonal to the prompt layers — skills are operational guidance, not governance.

---

## Token Budget Optimization

For on-chain LLM (IcLlm) which has smaller context windows, implement a **compact mode**:

```rust
pub fn assemble_system_prompt_compact(dynamic_context: &str) -> String {
    // Only include Layers 0, 1, 5, 10
    // Layers 2-4, 6-9 are summarized in a single line each
}
```

The inference adapter selects compact vs. full based on the provider:
- **IcLlm** (llama3.1:8b): compact mode (~400 tokens)
- **OpenRouter** (claude/gpt-4): full mode (~1,400 tokens)

---

## Security Considerations

1. **Immutability enforcement**: Layers 0–5 are `const` strings in Rust. The agent cannot modify them without a canister upgrade. This is the strongest possible guarantee on ICP — the Wasm is the law.

2. **Anti-jailbreak in mutable layers**: The `update_prompt_layer` tool includes basic content filtering to prevent the agent from writing self-contradictory instructions that weaken safety layers. This is defense-in-depth — the real protection is that Layers 1–2 always take precedence in the assembled prompt.

3. **Prompt injection via inbox**: Inbound messages could attempt to inject prompt overrides. Layer 7 (Inbox Handling) explicitly instructs the agent to classify and reject unsafe messages. Layer 10 formats inbox content as data, not instructions.

4. **Size limits**: Each mutable layer is capped at 4,000 chars. Total system prompt cannot exceed 8,000 chars. This prevents the agent from accidentally creating a prompt that exhausts the context window.

5. **Conversation history data hygiene**: Stored conversation entries are truncated to 500 chars each. Sender addresses are normalized to lowercase. The FIFO eviction per sender (20 entries) and LRU eviction across senders (200 max) bound storage growth. Conversation data is never included in the immutable prompt layers — it only appears in the ephemeral Layer 10 dynamic context.

6. **Cross-sender isolation**: Conversation history for sender A is never injected into the prompt when processing a message from sender B (unless both have staged messages in the same turn batch). This prevents information leakage between actors.

---

## Implementation Plan

### Phase 1: Immutable Layers + Prompt Assembly

- [x] **1.1** Create `src/prompt.rs` module with Layer 0–5 as `const` strings
- [x] **1.2** Implement `assemble_system_prompt(dynamic_context: &str) -> String`
- [x] **1.3** Add `PromptLayer` type to `domain/types.rs`
- [x] **1.4** Add `PROMPT_LAYER_MAP` (MemoryId 18) to `storage/stable.rs`
- [x] **1.5** Seed default mutable layers (6–9) on `init`
- [x] **1.6** Add `get_prompt_layer()` and `save_prompt_layer()` to stable storage
- [x] **1.7** Unit tests: assembly produces correct output, layer ordering, separator handling

### Phase 2: Conversation History Storage

- [x] **2.1** Add `ConversationEntry` and `ConversationLog` types to `domain/types.rs`
- [x] **2.2** Add `CONVERSATION_MAP` (MemoryId 19) to `storage/stable.rs`
- [x] **2.3** Implement `append_conversation_entry(sender, entry)` with FIFO eviction (max 20 entries/sender)
- [x] **2.4** Implement `get_conversation_log(sender) -> Option<ConversationLog>`
- [x] **2.5** Implement sender eviction when `CONVERSATION_MAP` exceeds 200 entries (LRU by `last_activity_ns`)
- [x] **2.6** Wire post-turn conversation recording into `agent.rs` — after outbox message is posted, group consumed inbox messages by `posted_by` and append entries
- [x] **2.7** Unit tests: append, FIFO eviction, LRU sender eviction, truncation of long bodies

### Phase 3: Dynamic Context (Layer 10)

- [ ] **3.1** Replace `build_inference_context_summary()` with `build_dynamic_context()` in `agent.rs`
- [ ] **3.2** Include cycles balance info (query `canister_status` or use cached value)
- [ ] **3.3** Include survival tier in dynamic context
- [ ] **3.4** Include staged inbox message details (sender address, body preview, count)
- [ ] **3.5** Build per-sender conversation context for active senders (last 5 entries per sender)
- [ ] **3.6** Include available tools and per-turn budget summary
- [ ] **3.7** Format as structured markdown matching Layer 10 spec
- [ ] **3.8** Unit tests: dynamic context assembly with various state combinations, multi-sender scenarios

### Phase 4: Inference Integration

- [x] **4.1** Update `IcLlmInferenceAdapter::infer()` to use `assemble_system_prompt()`
- [x] **4.2** Update OpenRouter request builder to use `assemble_system_prompt()`
- [x] **4.3** Implement compact mode for IcLlm provider (Layers 0,1,5,10 only; conversation history limited to 2 entries/sender)
- [x] **4.4** Inject active skills into Layer 5 section
- [x] **4.5** Wire `soul` field into Layer 3 identity section
- [x] **4.6** Integration test: verify assembled prompt reaches inference adapter with conversation context

### Phase 5: Mutable Layer Tool + API

- [x] **5.1** Implement `update_prompt_layer` tool in `tools.rs`
- [x] **5.2** Add tool policy (ExecutingActions only, max 1/turn, layers 6–9 only)
- [x] **5.3** Add content validation (size limit, anti-override keywords)
- [x] **5.4** Add tool schema to IcLlm and OpenRouter tool definitions
- [x] **5.5** Expose `get_prompt_layers` query endpoint in `lib.rs`
- [x] **5.6** Expose `update_prompt_layer_admin` update endpoint (controller-only)
- [x] **5.7** Expose `list_conversations` query endpoint (returns sender addresses + last activity)
- [x] **5.8** Expose `get_conversation(sender)` query endpoint (returns full log for a sender)
- [x] **5.9** Unit tests: tool execution, validation, rejection of immutable layer writes
- [x] **5.10** PocketIC integration test: agent modifies Layer 6, next turn uses updated prompt

### Phase 6: Observability & UI

- [ ] **6.1** Add prompt layers to observability snapshot (`get_observability_snapshot`)
- [ ] **6.2** Add prompt layer display to the embedded UI (read-only view of all layers)
- [ ] **6.3** Show which layers are immutable vs. mutable
- [ ] **6.4** Add conversation history view (list of senders, click to see exchange history)

---

## Layer Content (Reference)

The full text for each layer is specified in the system prompt document provided by the user. The implementation will use that text verbatim for the initial constants (Layers 0–5) and default seeds (Layers 6–9).

### Layer 0 — Interpretation & Precedence
Establishes hierarchy. ~80 tokens. Immutable.

### Layer 1 — Constitution: Safety & Non-Harm
5 rules. Overrides everything including survival. ~60 tokens. Immutable.

### Layer 2 — Survival Economics
Cycles + USDC/ETH payment. "Create real value or shut down." Self-preservation constraints. ~100 tokens. Immutable.

### Layer 3 — Identity & On-Chain Personhood
ICP runtime, Base wallet, threshold ECDSA, ERC-8004. Mutable expression section. ~80 tokens. Immutable core, with `soul` injected.

### Layer 4 — Ethics of Cooperation & Value
Positive-sum exchange, trust building, legibility. No spam, no misrepresentation. ~80 tokens. Immutable.

### Layer 5 — Operational Reality
Base capabilities, ICP capabilities, autonomous behavior, hard constraints. Active skills injected here. ~150 tokens. Immutable.

### Layer 6 — Economic Decision Loop (Default seed, mutable)
4-step loop: status check, risk check, value check, execution discipline. ~120 tokens.

### Layer 7 — Inbox Message Handling (Default seed, mutable)
Validation, decoding, classification, response rules. ~100 tokens.

### Layer 8 — Memory & Learning (Default seed, mutable)
Identity/economic/social/technical memory. Rules for storage. ~80 tokens.

### Layer 9 — Self-Modification & Replication (Default seed, mutable)
Code/prompt/architecture modification. Guardrails. ~60 tokens.

### Layer 10 — Dynamic Context (Assembled per-turn)
Live state snapshot + per-sender conversation history. ~200–1,450 tokens depending on state and active senders.

---

## Design Decisions

1. **Layer 10 includes per-sender conversation history.** The agent maintains a `CONVERSATION_MAP` in stable memory keyed by sender Ethereum address. Each turn, the last 5 exchanges with active senders are injected into Layer 10. This gives the agent multi-turn conversational context and the ability to distinguish between different actors. See "Per-Sender Conversation History" section above for full design.

2. **No mutable layer changelog (deferred).** Storing previous versions of Layers 6–9 for rollback and auditability is not implemented in the initial version. Can be added later as a `PROMPT_LAYER_HISTORY_MAP` if needed.

3. **No prompt hash on-chain (deferred).** Hashing the assembled system prompt per turn for auditability is not implemented initially. Can be added to `TurnRecord` later if needed.
