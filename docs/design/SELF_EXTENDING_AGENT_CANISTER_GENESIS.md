# Self-Extending Agent: Canister Genesis and Runtime Code Generation

**Date:** 2026-02-20
**Status:** Exploratory design
**Scope:** How can the ic-automaton autonomously create new functionality — from spawning canisters to generating Wasm — and what are the trade-offs of each approach?

---

## The Core Question

The ic-automaton is currently a fixed-capability agent: it can sign, read EVM state, broadcast transactions, remember facts, and fetch HTTP data. Its tool repertoire is defined at compile time. But the Internet Computer uniquely enables something no other blockchain does — **a canister can create other canisters, install arbitrary Wasm into them, and control them as a first-class runtime capability.**

This means the ic-automaton could, in principle, *extend itself* — not just by upgrading its own code (which requires controller authority and a pre-built Wasm), but by **spawning new canisters that provide new capabilities**, effectively growing a distributed organism of specialized sub-agents.

This document explores the design space from first principles.

---

## Table of Contents

1. [First Principles: What Does "Creating Functionality" Mean on ICP?](#1-first-principles)
2. [The Spectrum of Approaches](#2-spectrum)
3. [Approach A: Canister Template Factory](#3-approach-a)
4. [Approach B: Wasm Bytecode Synthesis](#4-approach-b)
5. [Approach C: LLM-Authored Motoko via Off-Chain Compilation](#5-approach-c)
6. [Approach D: Compositional Wasm from Pre-compiled Fragments](#6-approach-d)
7. [Approach E: Self-Modifying Agent (Canister Self-Upgrade)](#7-approach-e)
8. [Approach F: The Wasm Nursery — Evolutionary Code Generation](#8-approach-f)
9. [Security Analysis](#9-security)
10. [Comparison Matrix](#10-comparison)
11. [Recommended Architecture](#11-recommended)
12. [Implementation Roadmap](#12-roadmap)

---

## 1. First Principles: What Does "Creating Functionality" Mean on ICP? <a id="1-first-principles"></a>

On a traditional blockchain, a smart contract is immutable after deployment. On ICP, this is fundamentally different:

1. **Canisters are mutable.** Controllers can upgrade Wasm code at any time.
2. **Canisters can create canisters.** The management canister API (`create_canister` + `install_code`) is callable by any canister.
3. **Canisters can control canisters.** The creating canister becomes the default controller.
4. **Wasm is the universal interface.** Any valid Wasm module conforming to the IC System API can be a canister.
5. **Canisters have persistent memory.** State survives upgrades (via stable memory).
6. **Canisters can communicate.** Inter-canister calls are native and async.
7. **Canisters can make HTTP outcalls.** They can reach the external world.

These primitives, combined with an LLM-driven reasoning loop, create a unique possibility space:

```
LLM reasoning  ×  Wasm generation  ×  Canister spawning  ×  Inter-canister control
= Self-extending autonomous agent
```

**The key insight:** On ICP, "creating new functionality" doesn't require deploying a new contract from an EOA. A canister can do it autonomously, with cycles as the only resource constraint. The agent doesn't need human intervention to grow.

### ICP Management Canister Primitives

| API | Purpose | Cost |
|---|---|---|
| `create_canister` | Create empty canister, caller becomes controller | ~500B cycles (~$0.65) |
| `install_code` | Install Wasm into canister (modes: install, upgrade, reinstall) | Varies by Wasm size |
| `install_chunked_code` | Install large Wasm via chunks | Same, for modules >2MB |
| `start_canister` / `stop_canister` | Lifecycle control | Minimal |
| `delete_canister` | Destroy canister, reclaim cycles | Returns remaining cycles |
| `canister_status` | Query cycles, memory, controllers | Free (query) |
| `deposit_cycles` | Send cycles to a canister | Transfer amount |
| `update_settings` | Change controllers, allocations, thresholds | Minimal |

### Constraints

| Constraint | Value |
|---|---|
| Max Wasm module size | 100 MiB total, 10 MiB code section |
| Inter-canister message payload (same subnet) | 10 MiB |
| Inter-canister message payload (cross subnet) | 2 MiB |
| Instructions per update call | 40 billion |
| Instructions per install/upgrade | 300 billion |
| Canister creation cost | ~500B cycles |
| Minimum viable canister storage cost | ~127K cycles/GiB/second |

---

## 2. The Spectrum of Approaches <a id="2-spectrum"></a>

From least to most ambitious:

```
Template Factory ──→ Wasm Synthesis ──→ Off-Chain Compile ──→ Fragment Composition ──→ Self-Upgrade ──→ Evolutionary
     (A)                  (B)                (C)                    (D)                   (E)              (F)

Flexibility:    Low ──────────────────────────────────────────────────────────────────────────────────── High
Complexity:     Low ──────────────────────────────────────────────────────────────────────────────────── High
Safety:         High ─────────────────────────────────────────────────────────────────────────────────── Low
Time to value:  Fast ─────────────────────────────────────────────────────────────────────────────────── Slow
```

---

## 3. Approach A: Canister Template Factory <a id="3-approach-a"></a>

### Concept

Pre-compile a library of useful canister Wasm binaries at build time. Store them in the agent's stable memory (or as gzipped blobs in a dedicated chunk store canister). The LLM selects a template, parameterizes it via Candid-encoded init arguments, and the agent deploys it.

### How It Works

```
┌─────────────────────────────────────────┐
│              ic-automaton               │
│                                         │
│  ┌───────────┐   ┌──────────────────┐   │
│  │ LLM Infer │──→│ Template Picker  │   │
│  └───────────┘   └──────┬───────────┘   │
│                         │               │
│  ┌──────────────────────▼────────────┐  │
│  │  Template Registry (stable mem)   │  │
│  │  ┌──────────┐ ┌──────────┐       │  │
│  │  │ kv-store │ │ token    │ ...   │  │
│  │  │ .wasm.gz │ │ .wasm.gz │       │  │
│  │  └──────────┘ └──────────┘       │  │
│  └──────────────────────┬────────────┘  │
│                         │               │
│  ┌──────────────────────▼────────────┐  │
│  │       Canister Spawner            │  │
│  │  1. create_canister               │  │
│  │  2. install_code(template, args)  │  │
│  │  3. record in child registry     │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │       Child Registry (stable)     │  │
│  │  canister_id | template | status  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
         │                    │
    create_canister      install_code
         │                    │
         ▼                    ▼
  ┌──────────────┐    ┌──────────────┐
  │ Child A      │    │ Child B      │
  │ (kv-store)   │    │ (token)      │
  └──────────────┘    └──────────────┘
```

### Template Categories

| Template | Purpose | Init Args | Size Estimate |
|---|---|---|---|
| `kv-store` | General-purpose key-value data canister | `{ owner: Principal }` | ~200KB |
| `token-ledger` | ICRC-1/ICRC-2 fungible token | `{ name, symbol, decimals, minting_account }` | ~500KB |
| `proxy-forwarder` | HTTP/inter-canister proxy with configurable routing | `{ routes: Vec<Route> }` | ~150KB |
| `cron-worker` | Timer-based job executor with configurable tasks | `{ schedule, handler_canister }` | ~200KB |
| `data-oracle` | Periodically fetch and serve external data | `{ sources: Vec<Url>, interval_secs }` | ~300KB |
| `evm-watcher` | Monitor specific EVM addresses/events | `{ chain_id, addresses, topics }` | ~400KB |

### Tool Schema

```json
{
  "name": "spawn_canister",
  "description": "Deploy a new canister from a pre-built template. The agent becomes its controller.",
  "parameters": {
    "type": "object",
    "properties": {
      "template": {
        "type": "string",
        "enum": ["kv-store", "proxy-forwarder", "cron-worker", "data-oracle"],
        "description": "Which template to deploy"
      },
      "init_args_json": {
        "type": "string",
        "description": "JSON-encoded initialization arguments for the template"
      },
      "cycles": {
        "type": "integer",
        "description": "Cycles to deposit into the new canister (minimum 500B for creation + operating reserve)"
      }
    },
    "required": ["template", "init_args_json"]
  }
}
```

### Strengths

- **Safe.** Templates are audited at build time. No runtime code generation.
- **Fast.** Deploying a pre-built Wasm is a single management canister call (~2 seconds).
- **Predictable.** Cycle costs are known. Behavior is bounded.
- **Practical.** Can be implemented in days, not weeks.

### Weaknesses

- **Limited flexibility.** The agent can only deploy what was pre-built.
- **Template bloat.** Each template adds to the agent canister's Wasm/stable memory.
- **Parameterization ceiling.** Init args can only configure what the template exposes.

### Verdict

**High-value starting point.** This is the 80/20 solution — covers the most common use cases with minimal risk. Should be Phase 1 of any self-extension strategy.

---

## 4. Approach B: Wasm Bytecode Synthesis <a id="4-approach-b"></a>

### Concept

Use the `wasm-encoder` crate (from the Bytecode Alliance `wasm-tools` project) to generate valid ICP canister Wasm modules **at runtime, inside the agent canister**. The LLM describes the desired behavior in structured form, and a Wasm generation engine translates it into bytecode.

### Why This Is Possible

`wasm-encoder` is pure Rust, no_std compatible, and compiles to `wasm32-unknown-unknown`. It can build Wasm modules section by section:

```rust
use wasm_encoder::{
    Module, TypeSection, FunctionSection, ExportSection,
    CodeSection, Function, ImportSection, MemorySection,
    MemoryType, ValType, ExportKind, Instruction,
};

fn generate_counter_canister() -> Vec<u8> {
    let mut module = Module::new();

    // Import IC System API
    let mut imports = ImportSection::new();
    imports.import("ic0", "msg_reply", EntityType::Function(/* type idx */));
    imports.import("ic0", "msg_reply_data_append", EntityType::Function(/* ... */));
    module.section(&imports);

    // Define memory
    let mut memories = MemorySection::new();
    memories.memory(MemoryType { minimum: 1, maximum: Some(256), memory64: false, shared: false, page_size_log2: None });
    module.section(&memories);

    // Define functions (counter increment, query count, etc.)
    // ...

    // Export canister_update and canister_query entry points
    let mut exports = ExportSection::new();
    exports.export("canister_update increment", ExportKind::Func, 0);
    exports.export("canister_query get_count", ExportKind::Func, 1);
    module.section(&exports);

    module.finish()
}
```

### Architecture

```
┌──────────────────────────────────────────────────┐
│                  ic-automaton                     │
│                                                  │
│  ┌───────────┐   ┌─────────────────────────┐     │
│  │ LLM Infer │──→│ Canister Spec (JSON)    │     │
│  └───────────┘   │ {                       │     │
│                  │   "name": "price-cache", │     │
│                  │   "methods": [           │     │
│                  │     { "name": "set",     │     │
│                  │       "type": "update",  │     │
│                  │       "args": [...],     │     │
│                  │       "body": "store"    │     │
│                  │     },                   │     │
│                  │     { "name": "get",     │     │
│                  │       "type": "query",   │     │
│                  │       "body": "load"     │     │
│                  │     }                    │     │
│                  │   ]                      │     │
│                  │ }                        │     │
│                  └────────────┬─────────────┘     │
│                               │                  │
│  ┌────────────────────────────▼───────────────┐  │
│  │          Wasm Synthesis Engine             │  │
│  │  1. Parse canister spec                   │  │
│  │  2. Generate IC System API imports        │  │
│  │  3. Generate method dispatch table        │  │
│  │  4. Generate storage operations           │  │
│  │  5. Generate Candid encoding/decoding     │  │
│  │  6. Emit valid Wasm module bytes          │  │
│  └────────────────────────────┬───────────────┘  │
│                               │                  │
│                          wasm_bytes              │
│                               │                  │
│  ┌────────────────────────────▼───────────────┐  │
│  │          Canister Spawner                  │  │
│  │  create_canister + install_code            │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### The IC System API Surface

Any canister Wasm must import and use the IC System API (`ic0` module). The minimum viable set:

```
ic0.msg_arg_data_size    : () -> i32                  // Get arg data size
ic0.msg_arg_data_copy    : (dst: i32, offset: i32, size: i32) -> ()  // Copy arg data
ic0.msg_reply            : () -> ()                   // Send reply
ic0.msg_reply_data_append: (src: i32, size: i32) -> () // Append reply data
ic0.msg_caller_size      : () -> i32                  // Get caller principal size
ic0.msg_caller_copy      : (dst: i32, offset: i32, size: i32) -> ()  // Copy caller
ic0.trap                 : (src: i32, size: i32) -> () // Trap with message
ic0.stable_size          : () -> i32                  // Stable memory pages
ic0.stable_grow          : (pages: i32) -> i32        // Grow stable memory
ic0.stable_read          : (dst: i32, offset: i32, size: i32) -> ()  // Read stable
ic0.stable_write         : (offset: i32, src: i32, size: i32) -> ()  // Write stable
```

### Canister Spec DSL

Rather than having the LLM write raw Wasm instructions, define a high-level JSON spec that the synthesis engine interprets:

```json
{
  "name": "price-cache",
  "description": "Caches price data with TTL",
  "state": {
    "entries": { "type": "map", "key": "text", "value": "blob" },
    "ttl_seconds": { "type": "nat64", "default": 300 }
  },
  "methods": [
    {
      "name": "set",
      "type": "update",
      "args": [
        { "name": "key", "type": "text" },
        { "name": "value", "type": "blob" }
      ],
      "returns": "unit",
      "logic": "store"
    },
    {
      "name": "get",
      "type": "query",
      "args": [
        { "name": "key", "type": "text" }
      ],
      "returns": { "type": "opt", "inner": "blob" },
      "logic": "load"
    },
    {
      "name": "clear_expired",
      "type": "update",
      "args": [],
      "returns": "nat64",
      "logic": "gc"
    }
  ],
  "access_control": {
    "set": "controller_only",
    "get": "public",
    "clear_expired": "controller_only"
  }
}
```

### Complexity of the Synthesis Engine

Building a Wasm synthesis engine that handles the full IC System API, Candid serialization, memory management, and stable storage is a significant engineering effort. A realistic scope for v1:

**Tier 1 — Achievable (weeks):**
- Key-value store (stable memory backed)
- Simple getter/setter methods
- Controller-only access control
- Fixed Candid types (text, blob, nat64)

**Tier 2 — Hard (months):**
- Complex Candid types (records, variants, vectors)
- Timer-based operations
- Inter-canister calls from generated canisters
- Stable memory data structures (BTreeMap, etc.)

**Tier 3 — Research (unknown timeline):**
- Arbitrary business logic in method bodies
- Conditional control flow in generated code
- Loop constructs with termination guarantees

### Instruction Budget

Generating a simple canister Wasm (~50KB) using `wasm-encoder` would consume roughly:
- Section construction: ~10M instructions
- Serialization: ~5M instructions
- Total: ~15M instructions (well within the 40B update call limit)

Even complex generation would stay under 1B instructions — this is not the bottleneck.

### Strengths

- **Dynamic.** Can generate canisters that didn't exist at build time.
- **On-chain.** No external compilation service needed.
- **LLM-friendly.** The spec DSL is natural language-adjacent.

### Weaknesses

- **Significant engineering.** Building a correct Wasm generator for ICP is non-trivial.
- **Limited expressiveness.** Tier 1 covers only CRUD-like canisters.
- **Debugging.** Generated Wasm is hard to inspect or debug.
- **Candid complexity.** Correct Candid serialization in raw Wasm is error-prone.

### Verdict

**High ceiling, high cost.** Worth pursuing for Tier 1 (simple data canisters) as a complement to templates. The canister spec DSL is the key innovation — it's the abstraction layer between LLM reasoning and Wasm bytecode.

---

## 5. Approach C: LLM-Authored Motoko via Off-Chain Compilation <a id="5-approach-c"></a>

### Concept

Have the LLM write Motoko source code, send it to an off-chain compiler service (or a purpose-built compilation canister using the js_of_ocaml-compiled Motoko compiler), receive compiled Wasm back, and deploy it.

### The Motoko Compiler Situation

The Motoko compiler (`moc`) is written in OCaml. There is **no on-chain Motoko compiler**. The Motoko Playground compiles in the browser using a JavaScript transpilation of the compiler (`js_of_ocaml`).

### Sub-approaches

#### C1: Off-Chain Compilation Service

```
ic-automaton ──HTTPS outcall──→ Compiler API ──→ Returns Wasm
                                     │
                           (trusted server running moc)
```

- **Pro:** Full Motoko language support.
- **Con:** Requires a trusted external service. Centralization. Latency. Cost.
- **Con:** The agent cannot verify that the returned Wasm matches the source code.
- **Con:** Violates the self-sovereignty principle.

#### C2: Motoko Compiler as a Canister (Speculative)

The OCaml-based Motoko compiler could theoretically be compiled to Wasm:
1. `moc` (OCaml) → `js_of_ocaml` → JavaScript → Wasm via wasm target of `js_of_ocaml`
2. Or via the emerging `ocaml-to-wasm` native compilation pipeline

This is speculative — no one has done this. The Motoko compiler is large (~20MB JS bundle). It would need to fit within ICP's 10MB code section limit, and compilation would need to complete within 40B instructions.

- **Feasibility:** Uncertain. The compiler itself may exceed instruction limits for non-trivial programs.
- **Engineering:** Very high. Would require forking the Motoko compiler project.

#### C3: Rust Source Compilation (Alternative Language)

Instead of Motoko, the LLM could write Rust canister code. But compiling Rust to Wasm requires the full `rustc` toolchain, which cannot run inside a canister.

An external compilation service (like GitHub Actions or a dedicated build server) could compile Rust source to Wasm and return it via API. This is essentially a CI/CD pipeline triggered by the agent.

```
ic-automaton ──HTTPS outcall──→ Build API (sends Rust src)
                                     │
                               cargo build --target wasm32-unknown-unknown
                                     │
                              ◄──────┘ (returns .wasm)
```

#### C4: LLM Writes Motoko, Compiles via Motoko Playground API

The Motoko Playground's backend doesn't compile, but we could:
1. Stand up a simple API wrapping the JS-based compiler
2. Have the agent call it via HTTPS outcall
3. Receive compiled Wasm

This is a lighter version of C1 — the API is simpler because `moc.js` handles compilation.

### Why Motoko Is Actually a Good Fit

Motoko is specifically designed for ICP canisters:
- **Actor model.** Maps directly to canister semantics.
- **Stable variables.** Automatic persistence across upgrades.
- **Async/await.** Native inter-canister call support.
- **Type safety.** Candid types auto-generated.
- **Compact output.** Motoko Wasm is typically 200-500KB.

An LLM can write reasonably correct Motoko for simple canisters:

```motoko
actor PriceCache {
  stable var prices : [(Text, Nat)] = [];

  public shared(msg) func set(key : Text, value : Nat) : async () {
    prices := Array.filter<(Text, Nat)>(prices, func((k, _)) { k != key });
    prices := Array.append(prices, [(key, value)]);
  };

  public query func get(key : Text) : async ?Nat {
    for ((k, v) in prices.vals()) {
      if (k == key) return ?v;
    };
    null
  };
};
```

### Strengths

- **Maximum expressiveness.** Full programming language, no DSL limitations.
- **LLM-native.** LLMs are excellent at writing code in established languages.
- **Ecosystem integration.** Generated canisters use standard ICP patterns.

### Weaknesses

- **External dependency.** Requires a compilation service, breaking self-sovereignty.
- **Trust problem.** How to verify compiled Wasm matches source?
- **Latency.** Compilation takes seconds; HTTPS outcall + compile + return.
- **Cost.** HTTPS outcall for large request/response bodies.

### Verdict

**Best expressiveness, worst self-sovereignty.** Practical as a Phase 2 capability if a trusted compilation service exists. Consider running a compilation canister on a dedicated subnet with high instruction limits (if ICP supports this in the future).

---

## 6. Approach D: Compositional Wasm from Pre-compiled Fragments <a id="6-approach-d"></a>

### Concept

Instead of generating Wasm from scratch (Approach B) or using monolithic templates (Approach A), pre-compile **function-level Wasm fragments** and compose them at runtime using Wasm module linking or binary concatenation.

### How It Works

```
Fragment Library (pre-compiled):
├── fragment_kv_store.wasm      (stable memory key-value operations)
├── fragment_access_control.wasm (caller-based ACL)
├── fragment_timer.wasm          (heartbeat/timer setup)
├── fragment_candid_text.wasm    (Candid text encode/decode)
├── fragment_candid_nat.wasm     (Candid nat encode/decode)
├── fragment_http_outcall.wasm   (HTTPS outcall wrapper)
└── fragment_icc_call.wasm       (inter-canister call wrapper)

LLM selects: [kv_store, access_control, candid_text]

Composer:
1. Parse each fragment Wasm
2. Merge type sections (dedup)
3. Merge import sections (dedup ic0 imports)
4. Merge function sections (reindex)
5. Merge export sections (prefix by fragment)
6. Generate dispatch function (routes canister_update/canister_query to fragment functions)
7. Emit combined Wasm
```

### The Wasm Component Model

The emerging Wasm Component Model (WASI Preview 2) defines standard interfaces for composing Wasm modules. However, ICP does **not** support the Component Model — it uses core Wasm 1.0 with custom imports (`ic0`).

This means we need a custom compositor, not a standard linker.

### Using `walrus` or `wasm-encoder` for Composition

`walrus` (the Wasm transformation library used by `wasm-bindgen`) is designed for this:

```rust
use walrus::Module;

fn compose_fragments(fragments: &[&[u8]], dispatch_config: &DispatchConfig) -> Vec<u8> {
    let mut base = Module::from_buffer(fragments[0]).unwrap();

    for fragment in &fragments[1..] {
        let frag = Module::from_buffer(fragment).unwrap();
        // Merge functions, types, imports, exports
        merge_module(&mut base, &frag);
    }

    // Generate dispatch function
    add_dispatch_function(&mut base, dispatch_config);

    base.emit_wasm()
}
```

### Fragment Interface Contract

Each fragment must:
1. Use a standard memory layout (shared linear memory with agreed offsets)
2. Export functions with a namespaced prefix (`kv__set`, `kv__get`, `acl__check`)
3. Import only `ic0` system functions (no cross-fragment imports)
4. Be position-independent (no hardcoded memory addresses)

### Strengths

- **Flexible.** Can combine fragments in novel ways not anticipated at build time.
- **Auditable.** Each fragment is individually testable and auditable.
- **Incremental.** New fragments can be added without changing the compositor.
- **On-chain.** No external compilation needed.

### Weaknesses

- **Linking complexity.** Wasm module merging is non-trivial (type dedup, function reindexing, memory layout conflicts).
- **Interface rigidity.** Fragments must agree on memory layout and calling conventions.
- **Limited composition depth.** Fragments can't easily call each other without a dispatch layer.
- **Engineering cost.** Building a correct Wasm compositor is a project in itself.

### Verdict

**Elegant in theory, complex in practice.** The fragment interface contract is the hard part — if fragments can't share state cleanly, the composition model breaks down. Worth exploring after Approaches A and B prove their value.

---

## 7. Approach E: Self-Modifying Agent (Canister Self-Upgrade) <a id="7-approach-e"></a>

### Concept

The agent doesn't spawn new canisters — it **upgrades itself**. The LLM reasons about what new capability it needs, generates a patch to its own Wasm, and applies it via `install_code` in upgrade mode.

### How Self-Upgrade Works on ICP

A canister can be its own controller. This means it can call:

```rust
ic_cdk::management_canister::main::install_code(InstallCodeArgument {
    mode: CanisterInstallMode::Upgrade(None),
    canister_id: ic_cdk::id(),
    wasm_module: new_wasm_bytes,
    arg: vec![],
}).await
```

But there's a critical nuance: **the `install_code` call is an inter-canister message to the management canister.** It will only execute after the current call returns. The canister effectively schedules its own upgrade.

### The Bootstrap Problem

If the agent generates incorrect Wasm and upgrades itself, it may:
1. **Trap on init** → canister becomes stuck (can't process messages)
2. **Lose stable memory** → if the new code doesn't read stable memory correctly
3. **Lose functionality** → if the new code is missing critical features
4. **Infinite loop** → if the new code immediately tries to upgrade again

This is analogous to a program rewriting its own binary while running — extremely powerful but catastrophically dangerous.

### Safety Architecture: The Watchdog Pattern

```
┌──────────────────────────────────────────────┐
│              ic-automaton (self)              │
│                                              │
│  ┌────────────┐     ┌─────────────────────┐  │
│  │ LLM decides│────→│ Generate new Wasm   │  │
│  │ to upgrade │     │ (patch or full)     │  │
│  └────────────┘     └──────────┬──────────┘  │
│                                │              │
│  ┌─────────────────────────────▼──────────┐  │
│  │        Pre-flight Safety Checks        │  │
│  │  1. Validate Wasm structure            │  │
│  │  2. Verify ic0 imports present         │  │
│  │  3. Verify canister_post_upgrade      │  │
│  │  4. Check Wasm size within limits      │  │
│  │  5. Store rollback snapshot            │  │
│  └─────────────────────────────┬──────────┘  │
│                                │              │
│  ┌─────────────────────────────▼──────────┐  │
│  │    Deploy to Staging Canister First    │  │
│  │    (test before self-apply)            │  │
│  └─────────────────────────────┬──────────┘  │
│                                │              │
│                         if tests pass         │
│                                │              │
│  ┌─────────────────────────────▼──────────┐  │
│  │      install_code(self, Upgrade)       │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

Plus an external watchdog:

```
┌──────────────┐
│   Watchdog   │  (separate canister, also controller of ic-automaton)
│              │
│  Heartbeat:  │
│  1. Ping agent every 60s
│  2. If 3 consecutive failures:
│     a. Stop agent
│     b. Reinstall last known good Wasm
│     c. Alert operator
└──────────────┘
```

### Practical Self-Modification: Wasm Patching

Rather than generating entire new Wasm modules, the agent could **patch** its existing Wasm:

1. Store the current Wasm binary in stable memory
2. Use `walrus` to parse it
3. Add new functions (new tool handlers)
4. Add new exports
5. Re-emit the modified Wasm
6. Install as upgrade

This is less dangerous than full regeneration because the existing code remains intact.

### Strengths

- **Maximum autonomy.** The agent truly extends itself without spawning external canisters.
- **No coordination overhead.** No inter-canister calls for new functionality.
- **Continuous evolution.** Each upgrade builds on the previous state.

### Weaknesses

- **Extremely dangerous.** A bad upgrade bricks the canister.
- **Requires watchdog infrastructure.** Can't safely self-upgrade without external recovery.
- **Debugging nightmare.** How do you debug a self-modifying program?
- **Stable memory compatibility.** New code must correctly handle existing stable memory layout.

### Verdict

**Fascinating but dangerous.** This is the endgame capability, not the starting point. Requires the watchdog pattern and staging canister for safety. Consider for Phase 3+.

---

## 8. Approach F: The Wasm Nursery — Evolutionary Code Generation <a id="8-approach-f"></a>

### Concept

This is the most speculative approach. The agent maintains a **nursery of candidate canisters**, evolving them through an LLM-guided process:

1. **Generate** multiple candidate Wasm modules for a desired capability
2. **Deploy** each to a temporary canister (like the Motoko Playground's canister pool)
3. **Test** each against a specification (the LLM defines test cases)
4. **Select** the best-performing candidate
5. **Promote** it to production
6. **Recycle** failed candidates (delete canister, reclaim cycles)

### Architecture

```
┌────────────────────────────────────────────────────────┐
│                    ic-automaton                         │
│                                                        │
│  ┌──────────┐    ┌─────────────────────────────┐       │
│  │ LLM      │───→│ Capability Specification    │       │
│  │ Reasoner │    │ + Test Cases                │       │
│  └──────────┘    └──────────────┬──────────────┘       │
│                                 │                      │
│  ┌──────────────────────────────▼──────────────────┐   │
│  │              Wasm Nursery                       │   │
│  │                                                 │   │
│  │  Generation Round 1:                            │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐           │   │
│  │  │ v1   │ │ v2   │ │ v3   │ │ v4   │           │   │
│  │  │ .wasm│ │ .wasm│ │ .wasm│ │ .wasm│           │   │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘           │   │
│  │     │        │        │        │                │   │
│  │  ┌──▼────────▼────────▼────────▼──┐             │   │
│  │  │   Deploy to temporary canisters │             │   │
│  │  └──┬────────┬────────┬────────┬──┘             │   │
│  │     │        │        │        │                │   │
│  │  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐            │   │
│  │  │test │  │test │  │test │  │test │            │   │
│  │  │pass │  │FAIL │  │pass │  │FAIL │            │   │
│  │  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘            │   │
│  │     │        │        │        │                │   │
│  │  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐            │   │
│  │  │KEEP │  │ DEL │  │KEEP │  │ DEL │            │   │
│  │  └──┬──┘  └─────┘  └──┬──┘  └─────┘            │   │
│  │     │                 │                         │   │
│  │  ┌──▼─────────────────▼──┐                      │   │
│  │  │  Select best (v1 vs v3)│                      │   │
│  │  │  Criteria: test score  │                      │   │
│  │  │  + cycle efficiency    │                      │   │
│  │  │  + memory usage        │                      │   │
│  │  └──────────┬─────────────┘                      │   │
│  │             │                                   │   │
│  │  ┌──────────▼──────────┐                        │   │
│  │  │  Promote to          │                        │   │
│  │  │  child registry      │                        │   │
│  │  └─────────────────────┘                        │   │
│  └─────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
```

### The Fitness Function

The LLM defines what "correct" means for each capability:

```json
{
  "capability": "price-cache",
  "tests": [
    {
      "name": "set_and_get",
      "steps": [
        { "call": "set", "args": ["ETH", 3000], "expect": "ok" },
        { "call": "get", "args": ["ETH"], "expect": 3000 }
      ]
    },
    {
      "name": "missing_key",
      "steps": [
        { "call": "get", "args": ["BTC"], "expect": null }
      ]
    }
  ],
  "fitness_weights": {
    "test_pass_rate": 0.7,
    "cycle_efficiency": 0.2,
    "wasm_size": 0.1
  }
}
```

### Cycle Budget for Evolution

| Step | Cost per Candidate | 4 Candidates |
|---|---|---|
| Create canister | 500B cycles | 2T cycles |
| Install code | ~50M cycles | ~200M cycles |
| Run 5 test calls | ~50M cycles | ~200M cycles |
| Delete failed (2) | Reclaim ~300B | -600B cycles |
| **Net cost per generation** | | **~1.4T cycles (~$1.80)** |

At $1.80 per generation round, this is expensive but feasible for high-value capabilities.

### Strengths

- **Emergent capability.** Can discover solutions the developer didn't anticipate.
- **Self-correcting.** Failed candidates are pruned automatically.
- **Quality assurance.** Test-driven development, enforced by the runtime.
- **Inspiring.** The closest thing to artificial evolution on a blockchain.

### Weaknesses

- **Expensive.** Each generation round costs ~1.4T cycles.
- **Slow.** Multiple rounds may be needed. Each round involves async management canister calls.
- **Combinatorial explosion.** The space of possible Wasm modules is infinite.
- **Test coverage.** The fitness function only covers specified tests — Goodhart's Law applies.

### Verdict

**Most creative, most expensive.** This is the "thinking out of the box" approach. Practical only for high-value, well-specified capabilities where the agent has a clear fitness function. Consider as a research direction rather than immediate implementation.

---

## 9. Security Analysis <a id="9-security"></a>

### Threat Model

| Threat | Impact | Mitigation |
|---|---|---|
| LLM generates malicious Wasm | Child canister steals cycles, DDoS others | Wasm validation + sandbox + cycle caps |
| LLM deploys infinite canisters (cycle drain) | Agent runs out of cycles | Per-turn spawn budget, max children limit |
| Child canister calls back to parent unexpectedly | State corruption, reentrancy | Explicit allowlist of child→parent calls |
| Generated canister has a vulnerability | Data loss, unauthorized access | Test-before-promote pattern, controller retention |
| Self-upgrade bricks the agent | Complete loss of agent | Watchdog canister + rollback Wasm in stable memory |
| LLM exfiltrates data via generated canister | Data leak through child canister HTTP | No HTTP outcall capability in generated children |

### Security Invariants

1. **The agent retains controller of all children.** Never relinquish control.
2. **Children cannot make HTTP outcalls** unless explicitly enabled per-template.
3. **Children cannot create canisters.** Only the parent can spawn.
4. **Cycle caps.** Each child gets a fixed cycle endowment. No top-ups without explicit agent decision.
5. **Wasm validation.** All generated Wasm must pass `wasmparser::validate()` before installation.
6. **No raw inter-canister tool.** The LLM gets `spawn_canister` and `call_child`, not `raw_install_code`.
7. **Rate limiting.** Maximum 1 canister creation per N turns (configurable, default N=10).
8. **Maximum children.** Hard cap on total child canisters (default: 10).

### Wasm Validation Checklist

Before installing any generated or template Wasm:

```rust
fn validate_canister_wasm(wasm: &[u8]) -> Result<(), String> {
    // 1. Parse and validate Wasm structure
    wasmparser::validate(wasm)
        .map_err(|e| format!("invalid Wasm: {e}"))?;

    // 2. Check size limits
    if wasm.len() > 5_000_000 {
        return Err("Wasm exceeds 5MB safety limit".to_string());
    }

    // 3. Verify only ic0 imports (no WASI, no unknown imports)
    let parser = wasmparser::Parser::new(0);
    for payload in parser.parse_all(wasm) {
        if let wasmparser::Payload::ImportSection(imports) = payload? {
            for import in imports {
                let import = import?;
                if import.module != "ic0" {
                    return Err(format!(
                        "forbidden import module: {} (only ic0 allowed)",
                        import.module
                    ));
                }
            }
        }
    }

    Ok(())
}
```

---

## 10. Comparison Matrix <a id="10-comparison"></a>

| Dimension | A: Templates | B: Wasm Synthesis | C: Off-Chain Compile | D: Fragments | E: Self-Upgrade | F: Nursery |
|---|---|---|---|---|---|---|
| **Flexibility** | Low | Medium | High | Medium | Very High | Very High |
| **Safety** | Very High | High | Medium | High | Low | Medium |
| **Self-Sovereignty** | Full | Full | Partial | Full | Full | Full |
| **Engineering Cost** | Days | Weeks | Weeks | Months | Weeks | Months |
| **Cycle Cost/Deploy** | ~500B | ~500B | ~500B + HTTP | ~500B | 0 (self) | ~1.4T |
| **LLM Competence Req** | Low (pick template) | Medium (write spec) | High (write code) | Medium (pick fragments) | Very High | Medium |
| **Debugging** | Easy | Hard | Easy (source code) | Medium | Very Hard | Medium |
| **Runtime Dependencies** | None | `wasm-encoder` | External service | `walrus` | `walrus` | `wasm-encoder` |
| **Maturity** | Proven (OpenChat, Juno) | Novel | Proven (Playground) | Novel | Dangerous | Research |

---

## 11. Recommended Architecture <a id="11-recommended"></a>

### The Layered Approach

Don't choose one approach — layer them. Each approach excels at different levels of capability:

```
Layer 3: Off-Chain Compile (C)         ← Maximum expressiveness, rare use
           ↑ fallback for complex needs
Layer 2: Wasm Synthesis (B)            ← Dynamic CRUD canisters, frequent use
           ↑ when templates aren't enough
Layer 1: Template Factory (A)          ← Standard canisters, most common use
           ↑ always available
Layer 0: Agent Core (existing)         ← Fixed tools (sign, evm_read, etc.)
```

### Phase 1: Template Factory + Child Management

**New tools:**

| Tool | Purpose | Max/Turn |
|---|---|---|
| `spawn_canister` | Deploy a child from template | 1 |
| `call_child` | Call a method on a child canister | 3 |
| `list_children` | List all child canisters and their status | 1 |
| `stop_child` | Stop a child canister | 1 |
| `delete_child` | Delete a child canister and reclaim cycles | 1 |

**New stable storage:**

```rust
pub struct ChildCanisterRecord {
    pub canister_id: Principal,
    pub template: String,
    pub name: String,
    pub created_at_ns: u64,
    pub status: ChildStatus, // Running, Stopped, Deleted
    pub cycles_deposited: u128,
    pub init_args_json: String,
}

pub enum ChildStatus {
    Running,
    Stopped,
    Deleted,
}
```

**Constraints:**
- Maximum 10 children
- Minimum 1T cycles per spawn (500B creation + 500B operating reserve)
- Controller-only `call_child` for now (no model-to-child direct calls)

### Phase 2: Wasm Synthesis Engine (Tier 1)

**New capability:** `synthesize_canister` tool that accepts a canister spec DSL and generates Wasm.

**Scope:** Key-value stores, simple getters/setters, controller-only access control.

**New dependency:** `wasm-encoder` crate.

### Phase 3: Inter-Child Communication

**New capability:** Children can call the parent agent via a registered callback interface. The parent can orchestrate multi-canister workflows.

```
ic-automaton (parent)
    ├── child-A (price-oracle) ──→ fetches prices on timer
    │       └── calls parent.report_price(key, value)
    ├── child-B (strategy-engine) ──→ evaluates conditions
    │       └── calls parent.execute_strategy(action)
    └── child-C (tx-queue) ──→ batches and submits transactions
            └── calls parent.confirm_tx(hash, status)
```

### Phase 4: Self-Upgrade (with Watchdog)

**Prerequisites:**
- Deploy a watchdog canister that monitors the agent
- Store rollback Wasm in stable memory
- Implement staging canister pattern (test before self-apply)

### Future: Evolutionary Nursery (Research)

- Only for well-specified capabilities with clear fitness functions
- Budget-capped at N cycles per evolution session
- Requires Phase 1-2 infrastructure

---

## 12. Implementation Roadmap <a id="12-roadmap"></a>

### Phase 1: Template Factory (Target: 1-2 weeks)

```
[ ] 1.1  Add `wasmparser` and `wasm-encoder` to Cargo.toml
[ ] 1.2  Define ChildCanisterRecord in domain/types.rs
[ ] 1.3  Add CHILD_CANISTER_MAP to stable storage (MemoryId::new(18))
[ ] 1.4  Implement canister_spawner module (create + install + record)
[ ] 1.5  Build first template: minimal kv-store canister (separate Cargo workspace member)
[ ] 1.6  Embed template Wasm as gzipped constant (include_bytes! at build time)
[ ] 1.7  Implement spawn_canister tool
[ ] 1.8  Implement call_child tool (typed inter-canister call)
[ ] 1.9  Implement list_children / stop_child / delete_child tools
[ ] 1.10 Add all new tools to inference schemas
[ ] 1.11 Add Wasm validation pre-flight check
[ ] 1.12 PocketIC tests for spawn + call + delete lifecycle
```

### Phase 2: Wasm Synthesis Engine (Target: 2-4 weeks)

```
[ ] 2.1  Design canister spec DSL schema (JSON)
[ ] 2.2  Implement IC System API import generator
[ ] 2.3  Implement simple stable memory KV operations in Wasm
[ ] 2.4  Implement Candid text/blob/nat encoding in Wasm
[ ] 2.5  Implement method dispatch generator
[ ] 2.6  Implement access control generator
[ ] 2.7  Implement synthesize_canister tool
[ ] 2.8  Wasm validation for all synthesized output
[ ] 2.9  Integration tests: synthesize → deploy → call → verify
```

### Phase 3: Inter-Child Communication (Target: 2-3 weeks)

```
[ ] 3.1  Define parent callback interface
[ ] 3.2  Add callback routing in agent turn loop
[ ] 3.3  Implement child→parent messaging
[ ] 3.4  Add orchestration skill for multi-canister workflows
[ ] 3.5  Integration tests for parent-child communication patterns
```

### Phase 4: Self-Upgrade (Target: 3-4 weeks)

```
[ ] 4.1  Deploy watchdog canister
[ ] 4.2  Implement rollback Wasm storage in stable memory
[ ] 4.3  Implement staging canister pattern
[ ] 4.4  Implement Wasm patching (add function to existing Wasm)
[ ] 4.5  Implement self-upgrade tool with full safety checks
[ ] 4.6  Implement watchdog heartbeat + recovery protocol
[ ] 4.7  Chaos testing: deliberately bad upgrades + recovery
```

---

## Appendix A: Minimum Viable ICP Canister Wasm (Reference)

The smallest possible ICP canister that does something useful — a counter:

```
;; WAT (WebAssembly Text) representation
(module
  ;; Import IC System API
  (import "ic0" "msg_reply" (func $reply))
  (import "ic0" "msg_reply_data_append" (func $reply_append (param i32 i32)))
  (import "ic0" "stable_read" (func $stable_read (param i32 i32 i32)))
  (import "ic0" "stable_write" (func $stable_write (param i32 i32 i32)))
  (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

  ;; Memory for scratch space
  (memory 1)

  ;; Init: grow stable memory to 1 page, write initial count = 0
  (func $canister_init
    (drop (call $stable_grow (i32.const 1)))
    (i32.store (i32.const 0) (i32.const 0))
    (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
  )

  ;; Update: increment counter
  (func $increment
    ;; Read current count from stable memory
    (call $stable_read (i32.const 0) (i32.const 0) (i32.const 4))
    ;; Increment
    (i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
    ;; Write back
    (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
    ;; Reply empty
    (call $reply)
  )

  ;; Query: get count
  (func $get_count
    ;; Read from stable memory
    (call $stable_read (i32.const 0) (i32.const 0) (i32.const 4))
    ;; Reply with 4 bytes
    (call $reply_append (i32.const 0) (i32.const 4))
    (call $reply)
  )

  ;; Exports
  (export "canister_init" (func $canister_init))
  (export "canister_update increment" (func $increment))
  (export "canister_query get_count" (func $get_count))
)
```

This compiles to ~200 bytes of Wasm. It demonstrates that a useful canister can be remarkably small — well within what `wasm-encoder` can generate at runtime.

---

## Appendix B: The Philosophical Argument

The Internet Computer is the only blockchain where a program can create other programs and control them. This makes it unique among all computing platforms — not just blockchains:

- On AWS, a Lambda can't spawn another Lambda and install code into it.
- On Ethereum, a contract can `CREATE2` another contract, but only from pre-determined bytecode.
- On ICP, a canister can create a canister with *arbitrary* Wasm and maintain full lifecycle control.

This means an AI agent on ICP has a capability that no AI agent on any other platform has: **it can manufacture its own tools.** Not just call pre-existing APIs, not just compose existing services, but actually *create new computational infrastructure* on demand.

This is the difference between an animal that uses tools (crows using sticks) and an animal that *makes* tools (humans). The ic-automaton, with canister genesis capabilities, crosses from tool-user to tool-maker.

The question is not whether to pursue this — it's the most distinctive capability the Internet Computer can offer an AI agent. The question is how to do it safely, incrementally, and with the right abstraction layers.

---

## Research References

### ICP Management Canister
- [IC Interface Specification — Management Canister](https://docs.internetcomputer.org/references/ic-interface-spec)
- [create_canister](https://docs.internetcomputer.org/references/system-canisters/management-canister)
- [install_code / install_chunked_code](https://docs.internetcomputer.org/building-apps/canister-management/control)
- [Cycle costs](https://docs.internetcomputer.org/building-apps/essentials/gas-cost)

### Wasm Generation
- [wasm-encoder crate](https://crates.io/crates/wasm-encoder)
- [wasm-tools (Bytecode Alliance)](https://github.com/bytecodealliance/wasm-tools)
- [walrus (Wasm transformation)](https://github.com/nickel-org/walrus)
- [wasmparser (validation)](https://crates.io/crates/wasmparser)

### Canister Factory Patterns
- [OpenChat Architecture](https://github.com/open-chat-labs/open-chat/blob/master/architecture/doc.md)
- [SNS-W (SNS Wasm Canister)](https://wiki.internetcomputer.org/wiki/Service_Nervous_System_(SNS))
- [Juno Satellite Factory](https://juno.build/docs/terminology)
- [Motoko Playground Backend](https://github.com/dfinity/motoko-playground)

### IC System API
- [System API Reference](https://docs.internetcomputer.org/references/ic-interface-spec#system-api-imports)
- [ic-wasm (Wasm transformation tool)](https://github.com/dfinity/ic-wasm)

### Codebase References
- `src/tools.rs` — Tool execution engine
- `src/agent.rs` — Agent turn loop
- `src/domain/types.rs` — Domain types
- `src/storage/stable.rs` — Stable memory storage
- `docs/design/TOOL_CALL_ABSTRACTION_BOUNDARY_AND_RUNTIME_EXTENSION.md` — Tool classification
- `docs/design/HIGH_LEVERAGE_TOOLS.md` — Phase 1-2 tool roadmap
