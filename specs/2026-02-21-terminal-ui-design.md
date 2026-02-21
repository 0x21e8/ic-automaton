# Terminal UI Design Document

**Date:** 2026-02-21
**Status:** Draft
**Replaces:** Current dashboard UI (`ui_index.html`, `ui_app.js`, `ui_styles.css`)

---

## 1. Overview

A terminal-style embedded UI served directly from the ICP canister, replacing the current dashboard. Users interact with the automaton exclusively through typed commands in a phosphor-green-on-black terminal interface. The UI connects to browser EVM wallets (via viem) to sign transactions against the `Inbox.sol` contract, then polls the canister API for responses.

### Design Direction

Retro-terminal with CRT aesthetics, based on the reference design (`design-cb4e5e3b`). Key refinements over the reference:

- **Remove** the standalone "CONNECT WALLET" pill button from the header — wallet connection is now a terminal command
- **Add** a minimal status line below the logo showing connection state + wallet address (when connected)
- **Replace** the simulated typewriter boot sequence with a faster, staggered line reveal (CSS animation-delay) — the original 20ms-per-character typing is charming on first load but frustrating on repeat visits
- **Add** ANSI-style color coding: system messages in phosphor green, user input in white, errors in red (`#ff3333`), success confirmations in bright white, progress spinners in dim green
- **Add** a subtle CRT flicker on the terminal window border (not the text — text flicker causes accessibility issues)
- **Improve** the background canvas: reduce shape density by ~40% and slow pulse frequency — the current version is visually noisy

### Aesthetic Spec

| Property | Value |
|---|---|
| Font | `Space Mono` 400/700 (already loaded in reference) |
| Background | `#000000` pure black |
| Primary color | `#ccff00` phosphor green |
| Dim variant | `rgba(204, 255, 0, 0.15)` |
| User input color | `#ffffff` white |
| Error color | `#ff3333` |
| Success color | `#ffffff` bright white |
| Glow | `0 0 8px rgba(204, 255, 0, 0.6)` text shadow |
| CRT scanlines | Retained from reference (alternating 2px lines) |
| Terminal border | 1px solid phosphor-dim, no border-radius (square = more terminal) |

---

## 2. Architecture

### Tech Stack

- **Vanilla JavaScript** — no framework, no build step. Files compiled into canister WASM.
- **viem** (via ESM CDN) — wallet connection + contract interaction
- **Single-page app** — three files: `ui_index.html`, `ui_app.js`, `ui_styles.css`

### Why viem (Not Reown AppKit or RainbowKit)

| Criterion | viem | Reown AppKit | RainbowKit |
|---|---|---|---|
| Vanilla JS | Native | Yes (Web Components) | **No (React-only)** |
| Bundle size (gzip) | ~35 KB | ~200-300 KB | N/A |
| External service dependency | None | Requires Reown Cloud projectId | None |
| Wallet modal UI | None (build custom) | Full (700+ wallets) | Full (React) |
| Contract interaction | Native `readContract`/`writeContract` | Via adapter | Via wagmi hooks |

**Decision: viem.** Rationale:

1. **No external dependency.** Reown AppKit requires a `projectId` from a centralized service. For a decentralized ICP canister, adding a dependency on Reown Cloud's availability is architecturally wrong.
2. **Bundle size matters.** Canister storage costs cycles. 35 KB vs 200-300 KB is meaningful.
3. **We only need injected wallets.** MetaMask, Coinbase Wallet, Brave — all expose `window.ethereum`. No relay protocol needed.
4. **Custom UI fits the terminal aesthetic.** A pre-built modal would break the terminal design. Our "connect" command *is* the wallet UI.
5. **RainbowKit eliminated.** Requires React — incompatible with our vanilla JS architecture.

### Loading Strategy

viem will be loaded via ESM import map in the HTML:

```html
<script type="importmap">
{
  "imports": {
    "viem": "https://esm.sh/viem@2",
    "viem/chains": "https://esm.sh/viem@2/chains"
  }
}
</script>
<script type="module" src="/app.js"></script>
```

**Fallback consideration:** If the CDN is unreachable, wallet commands (`connect`, `send`, `donate`) will display an error. Read-only commands (`status`, `log`, `peek`, `help`, `price`) work without viem since they only call the canister HTTP API.

**Alternative (future):** Bundle viem into the canister WASM alongside the other static assets to eliminate the CDN dependency entirely. This adds ~100 KB to the canister but removes the external dependency. Recommended for production.

---

## 3. Command Reference

### 3.1 `help`

Lists all available commands with descriptions.

```
> help

AUTOMATON TERMINAL v2.0

  connect              Connect EVM wallet (MetaMask, Coinbase, etc.)
  send -m "message"    Send a message to the automaton
       [--usdc]        Pay with USDC + ETH (default: ETH only)
  price                Show current message cost (ETH and USDC)
  status               System diagnostics and automaton state
  log [-f]             Display automaton activity log
  peek [-f]            Display internal monologue
  donate <amount>      Send ETH or USDC to automaton
       [--usdc]        Donate USDC instead of ETH
  clear                Clear terminal
  help                 Show this message
```

### 3.2 `connect`

Connects to an EVM wallet via `window.ethereum` (EIP-1193).

**Flow:**

1. Check `window.ethereum` exists → if not: `ERROR: No wallet detected. Install MetaMask or another EVM wallet.`
2. Call `walletClient.requestAddresses()` via viem
3. On success: display connected address, store in app state
4. On rejection: `WALLET CONNECTION REJECTED BY USER.`

**Output:**

```
> connect
DETECTING WALLET PROVIDER...
REQUESTING ACCESS...
CONNECTED: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
CHAIN: Ethereum Mainnet (1)
```

**Reconnection:** If already connected, show current address and offer disconnect:

```
> connect
ALREADY CONNECTED: 0x71C...976F
TYPE 'disconnect' TO UNLINK WALLET.
```

**Chain validation:** If the user is on the wrong chain, prompt to switch:

```
> connect
CONNECTED: 0x71C...976F
WARNING: Wrong chain. Expected chain ID 31337 (Anvil). Current: 1 (Mainnet).
Attempting chain switch...
```

### 3.3 `send -m "message" [--usdc]`

Posts a message to the Inbox contract, then polls the canister until a reply appears.

**Prerequisites:** Wallet must be connected. Fails with `ERROR: No wallet connected. Run 'connect' first.`

**Argument parsing:**

- `-m "quoted message"` or `-m 'quoted message'` — required
- `--usdc` — flag, if present calls `queueMessage()` (ETH+USDC), otherwise calls `queueMessageEth()` (ETH only)

**Flow (ETH only):**

```
> send -m "What is your purpose?"
FETCHING CURRENT PRICES...
  ETH MINIMUM: 0.0005 ETH
PREPARING TRANSACTION...
  TO: 0xInboxContractAddress
  FUNCTION: queueMessageEth(automaton, "What is your purpose?")
  VALUE: 0.0005 ETH
AWAITING WALLET SIGNATURE... ⣾
TX SUBMITTED: 0xabcdef...1234
CONFIRMING... ⣾ (1/2 blocks)
CONFIRMED ✓ NONCE: 42

WAITING FOR AUTOMATON RESPONSE... ⣾
[Polls /api/snapshot every 2s, watching for outbox message matching this nonce/sender]

AUTOMATON REPLIED (12.4s):
─────────────────────────────────
I exist to observe, reason, and act autonomously on the Internet Computer.
My purpose is shaped by my prompt layers and evolves with each interaction.
─────────────────────────────────
```

**Flow (USDC):**

```
> send -m "Hello" --usdc
FETCHING CURRENT PRICES...
  ETH MINIMUM: 0.0005 ETH
  USDC MINIMUM: 1.000000 USDC
CHECKING USDC ALLOWANCE...
USDC APPROVAL NEEDED. REQUESTING APPROVAL TX... ⣾
APPROVAL TX: 0x...  CONFIRMED ✓
PREPARING MESSAGE TX...
  FUNCTION: queueMessage(automaton, "Hello", 1000000)
  VALUE: 0.0005 ETH + 1.0 USDC
AWAITING WALLET SIGNATURE... ⣾
TX SUBMITTED: 0x...
CONFIRMED ✓ NONCE: 43

WAITING FOR AUTOMATON RESPONSE... ⣾
...
```

**Error states:**

- Insufficient ETH: `ERROR: Insufficient ETH. Need 0.0005 ETH, have 0.0001 ETH.`
- Insufficient USDC: `ERROR: Insufficient USDC. Need 1.0 USDC, have 0.0 USDC.`
- TX reverted: `ERROR: Transaction reverted: insufficient eth`
- Timeout (no reply after 120s): `TIMEOUT: Automaton has not responded yet. Check 'log -f' for activity.`

**Spinner implementation:** Use braille spinner characters `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` cycling at 80ms intervals.

### 3.4 `price`

Fetches the current message cost from the Inbox contract.

**Flow:**

1. Call `Inbox.minPricesFor(automatonAddress)` via viem publicClient (read-only, no wallet needed)
2. Display results

```
> price
FETCHING PRICES FROM INBOX CONTRACT...

MESSAGE COST:
  ETH:  0.0005 ETH (minimum)
  USDC: 1.000000 USDC (minimum, with --usdc flag)

  Default pricing: yes
  Inbox contract: 0xInboxAddress
  Automaton: 0xAutomatonAddress
```

**Fallback:** If viem isn't loaded (CDN failure), fetch prices via the canister API if such an endpoint exists, or display an error.

### 3.5 `status`

Displays automaton diagnostics by fetching `/api/snapshot` and `/api/wallet/balance`.

```
> status

AUTOMATON STATUS
────────────────────────────────────
  STATE:          Running
  SOUL:           curious-observer
  TURNS:          142
  LOOP:           enabled
  LAST TRANSITION: 3m ago (Idle → Running)

SCHEDULER
────────────────────────────────────
  MODE:           normal
  ENABLED:        true
  ACTIVE LEASE:   none
  LAST TICK:      12s ago
  LAST ERROR:     no

WALLET
────────────────────────────────────
  EVM ADDRESS:    0xAutomatonAddress
  ETH BALANCE:    0.0234 ETH (fresh, 2m ago)
  USDC BALANCE:   15.50 USDC (fresh, 2m ago)

CYCLES
────────────────────────────────────
  TOTAL:          4.234T
  LIQUID:         3.891T
  BURN/HOUR:      12.5B cycles · $0.02
  RUNWAY:         12d 8h

INBOX
────────────────────────────────────
  TOTAL:          89
  PENDING:        2
  STAGED:         1
  CONSUMED:       86
```

### 3.6 `log [-f]`

Displays the automaton's activity log (scheduler jobs + state transitions).

**Without `-f`:** Fetches `/api/snapshot` once and renders recent jobs and transitions.

```
> log

RECENT TRANSITIONS
────────────────────────────────────
  12:34:02  Idle → Running        trx:abc123
  12:31:45  Running → Idle        trx:def456
  12:28:10  Idle → Running        trx:ghi789

RECENT JOBS
────────────────────────────────────
  12:34:05  AgentTurn    completed   job:jkl012
  12:33:58  PollInbox    completed   job:mno345
  12:31:40  AgentTurn    completed   job:pqr678
```

**With `-f` (follow):** Enters streaming mode. Polls `/api/snapshot` every 2s and appends new entries. Shows a header:

```
> log -f
FOLLOWING AUTOMATON LOG (Ctrl+C or 'q' to stop)
────────────────────────────────────
  12:34:05  AgentTurn    completed   job:jkl012
  12:35:08  PollInbox    completed   job:stu901
  ...
```

**Stopping follow mode:** User types `q` or presses Escape or Ctrl+C. The input line shows `[following — press q to stop]` instead of the normal prompt.

### 3.7 `peek [-f]`

Displays the automaton's internal monologue / inner dialogue.

**Without `-f`:** Fetches `/api/snapshot` and renders `recent_turns` entries that have `inner_dialogue`.

```
> peek

INNER MONOLOGUE
────────────────────────────────────
turn:42 · inbox_batch · 3m ago
  The user asked about my purpose. This is a philosophical question
  that touches on my core identity. I should reference my soul layer
  and provide a thoughtful, authentic response...

turn:41 · scheduled · 8m ago
  No new messages in inbox. System is idle. I'll continue monitoring
  for new inputs and observing the chain state...
```

**With `-f`:** Same streaming behavior as `log -f`.

### 3.8 `donate <amount> [--usdc]`

Sends ETH or USDC directly to the automaton's EVM address (not through the Inbox contract).

**Prerequisites:** Wallet must be connected.

**Flow (ETH, default):**

```
> donate 0.01
PREPARING DONATION...
  TO: 0xAutomatonAddress
  AMOUNT: 0.01 ETH
AWAITING WALLET SIGNATURE... ⣾
TX SUBMITTED: 0xabcdef...
CONFIRMED ✓
DONATION COMPLETE: 0.01 ETH sent to automaton.
```

**Flow (USDC):**

```
> donate 5.0 --usdc
PREPARING USDC DONATION...
  TO: 0xAutomatonAddress
  AMOUNT: 5.000000 USDC
CHECKING USDC ALLOWANCE...
APPROVAL TX NEEDED... ⣾
APPROVAL CONFIRMED ✓
TRANSFER TX... ⣾
CONFIRMED ✓
DONATION COMPLETE: 5.0 USDC sent to automaton.
```

### 3.9 `clear`

Clears all terminal output. Retained from reference design.

### 3.10 `disconnect`

Disconnects the currently connected wallet.

```
> disconnect
DISCONNECTED: 0x71C...976F
```

---

## 4. UI Layout

```
┌──────────────────────────────────────────────────┐
│ [canvas: sparse floating shapes, phosphor green] │
│                                                  │
│              A U T O M A T O N                   │
│          AUTONOMOUS AGENT V.2.0.0                │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ // terminal window                         │  │
│  │ INITIALIZING AUTOMATON CORE...             │  │
│  │ CONNECTION: SECURE [OK]                    │  │
│  │ WALLET: not connected                      │  │
│  │ ────────────────────────────────────        │  │
│  │ TYPE 'help' FOR COMMANDS.                  │  │
│  │                                            │  │
│  │                                            │  │
│  │                                            │  │
│  │                                            │  │
│  │                                            │  │
│  │ ────────────────────────────────────        │  │
│  │ > _                                        │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ STATUS: ● online │ wallet: not connected   │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### Status Bar (bottom)

A single-line status bar below the terminal showing:

- Automaton state (● online / ● idle / ● faulted)
- Wallet connection status
- Chain ID (when connected)
- Last poll timestamp

This replaces the removed "CONNECT WALLET" button from the reference design.

```
● ONLINE │ 0x71C...976F │ Chain 31337 │ Updated 12:34:05
```

When not connected:

```
● ONLINE │ WALLET: not connected │ Updated 12:34:05
```

---

## 5. Application State

```javascript
const state = {
  // Wallet
  walletConnected: false,
  walletAddress: null,
  chainId: null,

  // viem clients
  publicClient: null,    // For read-only contract calls
  walletClient: null,    // For signing transactions

  // Contract addresses (fetched from canister API)
  automatonEvmAddress: null,
  inboxContractAddress: null,
  usdcContractAddress: null,
  targetChainId: null,

  // Terminal
  commandHistory: [],
  historyIndex: -1,
  isFollowMode: false,   // true when log -f or peek -f is active
  followType: null,       // 'log' or 'peek'
  followInterval: null,

  // Polling
  pollHandle: null,
  lastSnapshotData: null,
  knownJobIds: new Set(),
  knownTransitionIds: new Set(),
  knownTurnIds: new Set(),
};
```

---

## 6. Contract Integration

### ABI (minimal, only what the UI needs)

```javascript
const INBOX_ABI = [
  'function queueMessage(address automaton, string message, uint256 usdcAmount) payable returns (uint64)',
  'function queueMessageEth(address automaton, string message) payable returns (uint64)',
  'function minPricesFor(address automaton) view returns (uint256 usdcMin, uint256 ethMinWei, bool usesDefault)',
  'function nonces(address) view returns (uint64)',
];

const ERC20_ABI = [
  'function approve(address spender, uint256 amount) returns (bool)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function balanceOf(address account) view returns (uint256)',
  'function decimals() view returns (uint8)',
];
```

### Client Setup

```javascript
import { createPublicClient, createWalletClient, custom, http, parseAbi } from 'viem';

// Public client for reads (uses canister's RPC or public RPC)
const publicClient = createPublicClient({
  chain: targetChain,
  transport: http(rpcUrl),
});

// Wallet client (after connect)
const walletClient = createWalletClient({
  chain: targetChain,
  transport: custom(window.ethereum),
});
```

### Configuration Bootstrap

On page load, fetch contract addresses and chain config from the canister:

```javascript
// New API endpoint needed: GET /api/evm/config
// Returns: { automaton_address, inbox_contract_address, usdc_address, chain_id, rpc_url }
const config = await fetch('/api/evm/config').then(r => r.json());
```

> **Backend work required:** Add a `GET /api/evm/config` endpoint that returns the automaton's EVM address, inbox contract address, USDC token address, chain ID, and RPC URL. These are all already stored in canister state.

---

## 7. Polling & Reply Matching

### Background Polling

The status bar updates via a lightweight poll every 5s (increased from current 2s — less aggressive):

```javascript
setInterval(async () => {
  const snapshot = await fetch('/api/snapshot').then(r => r.json());
  updateStatusBar(snapshot);
  state.lastSnapshotData = snapshot;
}, 5000);
```

### Reply Matching After `send`

After a `send` transaction is confirmed on-chain, we need to match the automaton's reply to our message. Strategy:

1. Record the sender address and approximate timestamp before sending
2. Poll `/api/conversation` with the sender address every 2s
3. Look for a new outbox entry that appeared after our send timestamp
4. Display the reply and stop polling
5. Timeout after 120s

```javascript
async function waitForReply(senderAddress, sentAfterMs) {
  const maxWaitMs = 120_000;
  const start = Date.now();

  while (Date.now() - start < maxWaitMs) {
    await sleep(2000);
    const convo = await fetch('/api/conversation', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sender: senderAddress }),
    }).then(r => r.json());

    if (convo?.entries?.length) {
      const latest = convo.entries[convo.entries.length - 1];
      const entryTs = Number(latest.timestamp_ns) / 1e6;
      if (entryTs > sentAfterMs && latest.agent_reply) {
        return latest.agent_reply;
      }
    }
  }
  return null; // timeout
}
```

---

## 8. Terminal Engine

### Command Parser

```javascript
function parseCommand(input) {
  const tokens = [];
  let current = '';
  let inQuote = null;

  for (const char of input) {
    if (inQuote) {
      if (char === inQuote) { inQuote = null; }
      else { current += char; }
    } else if (char === '"' || char === "'") {
      inQuote = char;
    } else if (char === ' ') {
      if (current) { tokens.push(current); current = ''; }
    } else {
      current += char;
    }
  }
  if (current) tokens.push(current);

  const cmd = tokens[0]?.toLowerCase();
  const flags = new Set();
  const args = {};

  for (let i = 1; i < tokens.length; i++) {
    if (tokens[i] === '-m' && tokens[i + 1]) {
      args.message = tokens[++i];
    } else if (tokens[i] === '-f' || tokens[i] === '--follow') {
      flags.add('follow');
    } else if (tokens[i] === '--usdc') {
      flags.add('usdc');
    } else if (!tokens[i].startsWith('-')) {
      args.positional = args.positional || [];
      args.positional.push(tokens[i]);
    }
  }

  return { cmd, flags, args };
}
```

### Output Rendering

Terminal lines are rendered as DOM elements (not raw innerHTML) to prevent XSS:

```javascript
function printLine(text, className = 'system') {
  const line = document.createElement('div');
  line.className = `term-line ${className}`;
  line.textContent = text;
  outputEl.appendChild(line);
  outputEl.scrollTop = outputEl.scrollHeight;
  return line;
}

function printError(text) {
  return printLine(text, 'error');
}

function printSuccess(text) {
  return printLine(text, 'success');
}
```

### Spinner

A spinner element that updates in place:

```javascript
function createSpinner(text) {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;
  const line = printLine(`${text} ${frames[0]}`);
  const interval = setInterval(() => {
    i = (i + 1) % frames.length;
    line.textContent = `${text} ${frames[i]}`;
  }, 80);

  return {
    update(newText) { text = newText; },
    stop(finalText) {
      clearInterval(interval);
      line.textContent = finalText || text;
    },
  };
}
```

### Command History

Arrow up/down cycles through previous commands (stored in `state.commandHistory`). Standard terminal behavior.

### Follow Mode

When `log -f` or `peek -f` is active:

- The input prompt changes to `[following — q to stop] >`
- Only `q`, `quit`, Escape, or Ctrl+C stop the follow mode
- New entries are appended as they appear from polling
- The terminal auto-scrolls to the bottom

---

## 9. Boot Sequence

On page load:

```
AUTOMATON TERMINAL v2.0
────────────────────────────────────
CONNECTING TO CANISTER... [OK]
LOADING EVM CONFIG...     [OK]
READY.

Type 'help' for available commands.
Type 'connect' to link your EVM wallet.
```

Lines appear with staggered `animation-delay` (100ms apart), no character-by-character typing. Total boot time: ~500ms.

---

## 10. File Structure

```
src/
  ui_index.html    — HTML shell + import map for viem
  ui_app.js        — All application logic (terminal engine, commands, viem integration)
  ui_styles.css    — Terminal styling, CRT effects, animations
```

All three files are embedded in the canister WASM and served via the existing `http_request` handler at `/`, `/app.js`, and `/styles.css`.

---

## 11. Backend Changes Required

### New API Endpoint

**`GET /api/evm/config`**

Returns the EVM configuration needed by the frontend:

```json
{
  "automaton_address": "0x...",
  "inbox_contract_address": "0x...",
  "usdc_address": "0x...",
  "chain_id": 31337,
  "rpc_url": "http://127.0.0.1:8545"
}
```

All these values already exist in canister state. This just exposes them via the HTTP API.

### No Other Backend Changes

All other data needs are served by existing endpoints:
- `/api/snapshot` — status, log, peek data
- `/api/wallet/balance` — wallet balance telemetry
- `/api/conversation` — reply matching after send

---

## 12. Security Considerations

- **XSS prevention:** All terminal output uses `textContent`, never `innerHTML`. Command responses are escaped.
- **Transaction confirmation:** The `send` command shows the full transaction details (to, function, value) before requesting the wallet signature. The user confirms in their wallet.
- **No private keys:** The UI never touches private keys. All signing happens in the browser wallet.
- **USDC approval scope:** When approving USDC for `send --usdc`, approve only the exact amount needed (not unlimited).
- **Chain validation:** Before any transaction, verify the wallet is on the expected chain. Prompt to switch if mismatched.

---

## 13. Implementation Phases

### Phase 1: Terminal Shell
- HTML structure, CSS styling, CRT effects
- Boot sequence
- Command parser
- `help`, `clear`, command history
- Status bar with canister polling

### Phase 2: Read-Only Commands
- `status` (fetch `/api/snapshot` + `/api/wallet/balance`)
- `log` and `log -f`
- `peek` and `peek -f`
- `price` (requires viem publicClient for contract read)
- Backend: add `GET /api/evm/config`

### Phase 3: Wallet Integration
- `connect` / `disconnect`
- viem client setup
- Chain validation

### Phase 4: Transactions
- `send -m "message"` (ETH only via `queueMessageEth`)
- `send -m "message" --usdc` (ETH+USDC via `queueMessage`)
- Reply polling and matching
- `donate` (ETH and USDC)
- USDC approval flow
