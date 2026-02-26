# Debugging the Live Canister

Practical guide for investigating a running ic-automaton canister on mainnet.
Assumes `icp` CLI is installed and you have the canister principal.

```
CANISTER=oc3hk-viaaa-aaaak-qxcuq-cai
```

---

## 1. Quick snapshot

The HTTP API exposes a human-readable snapshot without any CLI tooling:

```
https://<canister>.icp0.io/api/snapshot
```

Returns: state, turn counter, cycle runway, active strategy, last turn summary, storage pressure.
Good first stop before going deeper.

---

## 2. `icp` CLI basics

All canister query calls follow the same pattern:

```bash
icp canister call <principal> <method> '<candid_args>' -n ic
```

Query methods run instantly and are free. Update methods require a round-trip and cost cycles — avoid them for inspection.

---

## 3. Most useful query methods

### Recent turns (last N)

```bash
icp canister call $CANISTER list_turns '(50 : nat32)' -n ic
```

Each `TurnRecord` contains:
- `id` — turn identifier (`turn-NNN`)
- `state_from` / `state_to` — e.g. `Sleeping → Sleeping` (healthy) vs `ExecutingActions → Faulted`
- `tool_call_count` — how many tools fired
- `inner_dialogue` — full agent reasoning + tool results (key field for debugging)
- `error` — `None` on success, `Some("reason")` on fault
- `duration_ms` — wall-clock time for the turn
- `inference_round_count` — number of LLM calls made

**Look for `error: Some(...)` and `state_to: Faulted` to find problem turns.**

### State transition log

```bash
icp canister call $CANISTER list_recent_events '(50 : nat32)' -n ic
```

Shows the raw FSM events. Look for `TurnFailed { reason: "..." }` events — these give the fault reason without having to parse the full turn record. Also shows the previous state on recovery (`Faulted → LoadingContext` means auto-recovery worked).

### Tool calls for a specific turn

```bash
icp canister call $CANISTER get_tool_calls_for_turn '("turn-451")' -n ic
```

Returns every `ToolCallRecord` for that turn: tool name, args JSON, output, success flag, error string. The most direct way to see exactly what failed and why.
If your deployment is older and this method is missing, try `list_tool_calls_for_turn`.

### Observability snapshot (everything at once)

```bash
icp canister call $CANISTER get_observability_snapshot '(20 : nat32)' -n ic 2>&1 \
  > /tmp/snapshot.txt
```

Dumps turns, events, jobs, conversations, memory facts, and scheduler state in one call. Useful for a full picture but output is large (save to file).

### Memory facts

```bash
icp canister call $CANISTER list_memory_facts_by_prefix '("config")' -n ic
```

_(Method name may vary — check `list_memory_facts` or use `recall` via the agent.)_
Shows what the agent has stored under stable `config.*` keys — endpoint URLs, working json_paths, pool addresses. Empty `config.*` namespace means the agent hasn't yet learned to persist its reference data.

### Scheduler jobs

```bash
icp canister call $CANISTER list_scheduler_jobs '(20 : nat32)' -n ic
```

Shows pending/completed task records with attempt counts and errors. Useful for spotting tasks that are repeatedly failing or stalled.

### Inference config

```bash
icp canister call $CANISTER get_inference_config '()' -n ic
```

Confirms which model and provider is active.

---

## 4. Parsing turn data efficiently

Turn output is a single giant Candid string with `;`-separated records. Parse it with Python rather than reading raw:

```bash
# Find all faulted turns with their error messages
icp canister call $CANISTER list_turns '(100 : nat32)' -n ic \
  | python3 -c "
import sys, re
text = sys.stdin.read()
for t in text.split('TurnRecord { id:')[1:]:
    turn_id = t.split('\"')[1]
    if 'error: Some(' in t or ('failed' in t and 'error:' in t):
        error = re.search(r'error: Some\(\"(.*?)\"\)', t)
        diag = re.search(r'inner_dialogue: Some\(\"(.{0,400})', t)
        print(f'{turn_id}: {error.group(1) if error else \"no error field\"}')
        if diag:
            print(f'  {diag.group(1)[:300]}')
        print()
"
```

```bash
# Count and categorize all http_fetch failures
icp canister call $CANISTER list_turns '(100 : nat32)' -n ic \
  | python3 -c "
import sys, re
from collections import Counter
text = sys.stdin.read()
errors = re.findall(r'http_fetch\x60? failed: ([^\\\n]+)', text)
for err, n in Counter(errors).most_common():
    print(f'{n:3d}x  {err[:120]}')
"
```

```bash
# List all URLs the agent has tried fetching
icp canister call $CANISTER list_turns '(100 : nat32)' -n ic \
  | python3 -c "
import sys, re
from collections import Counter
text = sys.stdin.read()
urls = re.findall(r'https://[a-zA-Z0-9._/\-?=&]+', text)
for url, n in Counter(urls).most_common(20):
    print(f'{n:3d}x  {url}')
"
```

---

## 5. Key error patterns and what they mean

| Error | Meaning | Severity |
|---|---|---|
| `HTTP 404 from ...` | Agent fetched a non-existent URL (often a hallucinated address) | Fault if 4xx not degraded |
| `json_path extraction failed: path ... not found` | LLM used wrong path for this API's schema | Degraded (no fault) |
| `json_path extraction failed: response is not valid JSON` | API returned HTML/error page instead of JSON | Degraded |
| `tool execution reported failures` | At least one non-recoverable tool failed | Fault → `Faulted` state |
| `http_fetch outcall timeout envelope exceeded` | HTTP outcall took >20s | Fault |
| `insufficient cycles for HTTP fetch` | Cycle runway too low to pay for outcall | Fault |
| `domain not in allowlist` | Agent tried a URL not on the allowed domains list | Fault |

**Recovery:** `Faulted` state auto-recovers on the next timer tick — no manual intervention needed unless the fault loops (same error every turn).

---

## 6. Spotting recurring vs one-off failures

If the same URL appears in errors across many turns, the agent is stuck in a loop — the LLM isn't learning from the failure. This usually means:

1. The error isn't being fed back into the LLM's context clearly enough.
2. The correct URL isn't stored in a `config.*` memory fact, so the LLM reconstructs (and hallucinates) it each turn.
3. The API itself has changed its schema.

Check whether the agent has stored a working URL under `config.*`. If not, the memory discipline prompt should lead it to do so after the next successful fetch.

---

## 7. Checking what the agent actually remembers

Inspect `config.*` facts (never rolled up, always loaded into context):

```bash
icp canister call $CANISTER get_observability_snapshot '(10 : nat32)' -n ic 2>&1 \
  | grep -i 'config\.'
```

Or look in the `inner_dialogue` of a recent turn for `recall("config.")` calls and their results. If the agent is recalling empty results, the stable reference data hasn't been seeded yet.

---

## 8. Monitoring cycle runway

```bash
icp canister call $CANISTER get_runtime_view '()' -n ic
```

Key fields: `cycles_balance`, `liquid_cycles`, `freezing_threshold`. Estimated runway is in the `/api/snapshot` HTTP response. Alert if liquid cycles drop below ~3× the freezing threshold.

---

## 9. Tips

- **Save large outputs to file** before inspecting: `icp canister call ... > /tmp/out.txt`. The output can be 300 KB+.
- **Use `list_turns(50)` not `get_observability_snapshot`** when you just want error history — much smaller and faster to parse.
- **`inner_dialogue` is the most information-dense field.** It contains the agent's full reasoning, all tool inputs/outputs, and the inference conclusion. When a turn goes wrong, read the inner_dialogue first.
- **`list_recent_events` is fastest for FSM health.** Scanning for `TurnFailed` events gives fault history in seconds without parsing full turn records.
- **The `/api/snapshot` HTTP endpoint is the fastest overall check** — bookmark it for quick health checks during live incidents.
