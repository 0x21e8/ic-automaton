/**
 * AUTOMATON TERMINAL — ui_app.js
 * Phase 1: Terminal shell, command parser, help/clear, command history,
 *          status-bar canister polling, background canvas animation.
 *
 * Phase 2: read-only commands (status, log, peek, price),
 *          EVM config bootstrap, viem public client setup.
 *
 * Phase 3: wallet connection/disconnection via viem (connect, disconnect),
 *          chain validation + switch, account/chain change listeners.
 *
 * Phase 4+: EVM transactions (send, donate)
 */

// =============================================================================
// STATE
// =============================================================================

const state = {
  // Wallet (Phase 3)
  walletConnected: false,
  walletAddress: null,
  chainId: null,
  publicClient: null,    // viem public client (initialized in Phase 2 for reads)
  walletClient: null,    // viem wallet client (Phase 3)

  // EVM config from canister (Phase 2+)
  automatonEvmAddress: null,
  inboxContractAddress: null,
  usdcContractAddress: null,
  targetChainId: null,
  rpcUrl: null,

  // Terminal
  commandHistory: [],
  historyIndex: -1,

  // Follow mode (log -f, peek -f)
  isFollowMode: false,
  followType: null,      // 'log' | 'peek'
  followInterval: null,

  // Background polling for status bar
  pollHandle: null,
  lastSnapshotData: null,

  // Known IDs for follow mode deduplication
  knownJobIds: new Set(),
  knownTransitionIds: new Set(),
  knownTurnIds: new Set(),
};

// =============================================================================
// DOM ELEMENTS
// =============================================================================

const outputEl   = document.getElementById("output");
const inputEl    = document.getElementById("cmd-input");
const inputRow   = document.getElementById("input-row");
const sbStateEl  = document.getElementById("sb-state");
const sbWalletEl = document.getElementById("sb-wallet");
const sbTimeEl   = document.getElementById("sb-time");
const sbIndEl    = document.getElementById("sb-indicator");

// =============================================================================
// OUTPUT UTILITIES
// =============================================================================

/**
 * Append a line to the terminal output.
 * @param {string} text
 * @param {string} className  — CSS class(es) added to the base 'term-line' class
 * @param {number} [bootDelay]  — ms animation-delay for staggered boot reveal
 * @returns {HTMLDivElement}
 */
function printLine(text, className = "system", bootDelay = 0) {
  const el = document.createElement("div");
  el.className = `term-line ${className}`;
  el.textContent = text;
  if (bootDelay > 0) {
    el.style.animationDelay = `${bootDelay}ms`;
  }
  outputEl.appendChild(el);
  scrollBottom();
  return el;
}

function printEmpty(bootDelay = 0) {
  const el = document.createElement("div");
  el.className = "term-line empty";
  if (bootDelay > 0) {
    el.style.animationDelay = `${bootDelay}ms`;
  }
  outputEl.appendChild(el);
  return el;
}

function printSeparator(bootDelay = 0) {
  return printLine("────────────────────────────────────", "separator", bootDelay);
}

function printError(text) {
  return printLine(`ERROR: ${text}`, "error");
}

function printSuccess(text) {
  return printLine(text, "success");
}

function scrollBottom() {
  outputEl.scrollTop = outputEl.scrollHeight;
}

// =============================================================================
// SPINNER
// =============================================================================

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/**
 * Create an in-place spinner line.
 * Returns { update(text), stop(finalText, className) }.
 */
function createSpinner(text) {
  let frameIdx = 0;
  let currentText = text;
  const el = printLine(`${currentText} ${SPINNER_FRAMES[0]}`, "system dim");
  // Spinners appear instantly — override the fade-in animation
  el.style.animation = "none";
  el.style.opacity = "1";

  const timer = setInterval(() => {
    frameIdx = (frameIdx + 1) % SPINNER_FRAMES.length;
    el.textContent = `${currentText} ${SPINNER_FRAMES[frameIdx]}`;
    scrollBottom();
  }, 80);

  return {
    update(newText) {
      currentText = newText;
    },
    stop(finalText, className = "system") {
      clearInterval(timer);
      if (finalText === "") {
        // Empty string = remove the spinner line entirely
        el.remove();
        return;
      }
      el.textContent = finalText ?? currentText;
      el.className = `term-line ${className}`;
    },
  };
}

// =============================================================================
// FORMAT HELPERS (Phase 2)
// =============================================================================

/**
 * Convert a hex wei string (e.g. "0x1bc16d674ec80000") or BigInt to an ETH
 * decimal string.
 */
function formatWei(hexOrBigInt) {
  try {
    const wei = typeof hexOrBigInt === "bigint" ? hexOrBigInt : BigInt(hexOrBigInt);
    const eth = Number(wei) / 1e18;
    if (eth === 0) return "0";
    if (eth < 0.0001) return eth.toExponential(4);
    return eth.toFixed(6).replace(/\.?0+$/, "");
  } catch {
    return "?";
  }
}

/**
 * Format a hex-encoded USDC raw amount with the given decimal precision.
 */
function formatUsdcHex(hexStr, decimals = 6) {
  try {
    return formatUsdcRaw(BigInt(hexStr), decimals);
  } catch {
    return "?";
  }
}

/**
 * Format a BigInt raw USDC amount into a decimal string.
 */
function formatUsdcRaw(rawBigInt, decimals = 6) {
  try {
    const divisor = 10n ** BigInt(decimals);
    const whole = rawBigInt / divisor;
    const frac  = rawBigInt % divisor;
    return `${whole}.${frac.toString().padStart(decimals, "0")}`;
  } catch {
    return "?";
  }
}

/**
 * Format a cycle count into a human-readable string (T / B / M).
 */
function formatCycles(n) {
  if (n == null) return "—";
  const num = Number(n);
  if (num >= 1e12) return `${(num / 1e12).toFixed(3)}T`;
  if (num >= 1e9)  return `${(num / 1e9).toFixed(1)}B`;
  if (num >= 1e6)  return `${(num / 1e6).toFixed(1)}M`;
  return num.toLocaleString();
}

/**
 * Format seconds-until-freeze as "Xd Yh" or "Xh Ym".
 */
function formatRunway(secs) {
  if (secs == null) return "—";
  const days  = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  const mins  = Math.floor((secs % 3600) / 60);
  if (days > 0)  return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

/**
 * Format a nanosecond timestamp as HH:MM:SS.
 */
function formatTs(ns) {
  if (!ns) return "--:--:--";
  const ms = Number(ns) / 1e6;
  return new Date(ms).toLocaleTimeString("en-US", { hour12: false });
}

/**
 * Format a nanosecond timestamp as a relative age like "3m ago".
 */
function formatAge(ns) {
  if (!ns) return "never";
  const ageSecs = Math.max(0, Math.floor((Date.now() - Number(ns) / 1e6) / 1000));
  if (ageSecs < 60)    return `${ageSecs}s ago`;
  if (ageSecs < 3600)  return `${Math.floor(ageSecs / 60)}m ago`;
  if (ageSecs < 86400) return `${Math.floor(ageSecs / 3600)}h ago`;
  return `${Math.floor(ageSecs / 86400)}d ago`;
}

/**
 * Left-pad a string to width.
 */
function padRight(str, width) {
  return String(str).padEnd(width);
}

/**
 * Format the duration between two nanosecond timestamps as "Xms" or "X.Xs".
 * Returns null if either timestamp is missing.
 */
function formatDurationNs(startNs, endNs) {
  if (!startNs || !endNs) return null;
  const ms = (Number(endNs) - Number(startNs)) / 1e6;
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

// =============================================================================
// BOOT SEQUENCE
// =============================================================================

const BOOT_DELAY_STEP = 90; // ms between each boot line reveal
const BOOT_LINE_COUNT = 9;  // lines emitted by runBoot (for focus timer)

async function runBoot() {
  let delay = 80;
  const S = BOOT_DELAY_STEP;

  printLine("AUTOMATON TERMINAL v2.0",              "system bright", delay); delay += S;
  printSeparator(delay);                                                      delay += S;

  const connectingLine = printLine("CONNECTING TO CANISTER...", "system dim", delay); delay += S;
  const evmConfigLine  = printLine("LOADING EVM CONFIG...",     "system dim", delay); delay += S;

  printEmpty(delay);                                                           delay += S;
  printLine("READY.", "system bright", delay);                                 delay += S;
  printEmpty(delay);                                                           delay += S;
  printLine("Type 'help' for available commands.",    "system dim", delay);   delay += S;
  printLine("Type 'connect' to link your EVM wallet.", "system dim", delay);

  // Canister reachability — initial status poll
  await pollStatus();
  if (state.lastSnapshotData) {
    connectingLine.textContent = "CONNECTING TO CANISTER...    [OK]";
  } else {
    connectingLine.textContent = "CONNECTING TO CANISTER...    [FAIL]";
  }

  // EVM config bootstrap
  try {
    await loadEvmConfig();
    evmConfigLine.textContent = "LOADING EVM CONFIG...        [OK]";
  } catch (_) {
    evmConfigLine.textContent = "LOADING EVM CONFIG...        [—]";
  }
}

// =============================================================================
// EVM CONFIG BOOTSTRAP (Phase 2)
// =============================================================================

async function loadEvmConfig() {
  const config = await apiFetch("/api/evm/config");
  state.automatonEvmAddress  = config.automaton_address       ?? null;
  state.inboxContractAddress = config.inbox_contract_address  ?? null;
  state.usdcContractAddress  = config.usdc_address            ?? null;
  state.targetChainId        = config.chain_id                ?? null;
  state.rpcUrl               = config.rpc_url                 ?? null;
  // Invalidate any stale public client when config changes
  state.publicClient = null;
}

// =============================================================================
// VIEM (Phase 2 reads; Phase 3 wallet)
// =============================================================================

let _viemModule = null;

async function ensureViem() {
  if (_viemModule) return _viemModule;
  try {
    _viemModule = await import("viem");
    return _viemModule;
  } catch {
    return null;
  }
}

async function ensurePublicClient() {
  if (state.publicClient) return state.publicClient;
  if (!state.rpcUrl || !state.targetChainId) return null;

  const viem = await ensureViem();
  if (!viem) return null;

  const { createPublicClient, http } = viem;
  const chain = {
    id: state.targetChainId,
    name: `Chain ${state.targetChainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [state.rpcUrl] } },
  };
  state.publicClient = createPublicClient({ chain, transport: http(state.rpcUrl) });
  return state.publicClient;
}

/**
 * Map common chain IDs to human-readable names.
 */
function chainName(id) {
  const NAMES = {
    1:        "Ethereum Mainnet",
    5:        "Goerli",
    11155111: "Sepolia",
    31337:    "Anvil",
    8453:     "Base",
    84532:    "Base Sepolia",
  };
  return NAMES[id] ?? `Chain ${id}`;
}

/**
 * Create (or return cached) a viem walletClient backed by window.ethereum.
 * Returns null if no injected provider is available.
 */
async function ensureWalletClient() {
  if (state.walletClient) return state.walletClient;
  if (!window.ethereum) return null;

  const viem = await ensureViem();
  if (!viem) return null;

  const { createWalletClient, custom } = viem;
  const chainId = state.targetChainId ?? 1;
  const chain = {
    id: chainId,
    name: chainName(chainId),
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [state.rpcUrl ?? ""] } },
  };
  state.walletClient = createWalletClient({ chain, transport: custom(window.ethereum) });
  return state.walletClient;
}

// =============================================================================
// COMMAND PARSER
// =============================================================================

/**
 * Parse a raw input string into tokens, respecting single- and double-quoted
 * strings. Returns { cmd, flags, args, positional }.
 *
 * Flags:   -f / --follow → flags.has('follow')
 *          --usdc        → flags.has('usdc')
 * Named:   -m "text"     → args.message
 * Other positional tokens (not starting with '-') → positional array
 */
function parseInput(raw) {
  const tokens = [];
  let current = "";
  let inQuote = null;

  for (const ch of raw.trim()) {
    if (inQuote) {
      if (ch === inQuote) {
        inQuote = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = ch;
    } else if (ch === " ") {
      if (current) {
        tokens.push(current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);

  const cmd = (tokens[0] ?? "").toLowerCase();
  const flags = new Set();
  const args = {};
  const positional = [];

  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === "-f" || tok === "--follow") {
      flags.add("follow");
    } else if (tok === "--usdc") {
      flags.add("usdc");
    } else if (tok === "-m") {
      if (tokens[i + 1] !== undefined) {
        args.message = tokens[++i];
      }
    } else if (!tok.startsWith("-")) {
      positional.push(tok);
    }
  }

  return { cmd, flags, args, positional };
}

// =============================================================================
// COMMANDS — Phase 1 (help, clear)
// =============================================================================

const HELP_LINES = [
  { text: "AVAILABLE COMMANDS", cls: "system bright" },
  { text: "────────────────────────────────────", cls: "separator" },
  { text: "  connect              Connect EVM wallet (MetaMask, etc.)", cls: "system" },
  { text: "  disconnect           Unlink wallet", cls: "system" },
  { text: "  send -m \"message\"    Post a message to the automaton", cls: "system" },
  { text: "       [--usdc]          Pay with USDC + ETH (default: ETH only)", cls: "system dim" },
  { text: "  price                Show message cost (ETH and USDC)", cls: "system" },
  { text: "  status               System diagnostics and automaton state", cls: "system" },
  { text: "  log [-f]             Activity log  (jobs + transitions)", cls: "system" },
  { text: "  peek [-f]            Internal monologue (inner dialogue)", cls: "system" },
  { text: "  donate <amount>      Send ETH directly to automaton", cls: "system" },
  { text: "       [--usdc]          Donate USDC instead", cls: "system dim" },
  { text: "  clear                Clear terminal", cls: "system" },
  { text: "  help                 Show this message", cls: "system" },
  { text: null },
  { text: "  Tip: use -f for live follow mode; press q or Esc to stop.", cls: "system dim" },
];

function cmdHelp() {
  printEmpty();
  HELP_LINES.forEach(({ text, cls }) => {
    if (text === null) {
      printEmpty();
    } else {
      printLine(text, cls ?? "system");
    }
  });
  printEmpty();
}

function cmdClear() {
  outputEl.innerHTML = "";
}

// =============================================================================
// COMMANDS — Phase 2: status
// =============================================================================

async function cmdStatus() {
  printEmpty();
  const spinner = createSpinner("FETCHING SYSTEM STATUS...");

  let snapshot, wallet;
  try {
    [snapshot, wallet] = await Promise.all([
      apiFetch("/api/snapshot"),
      apiFetch("/api/wallet/balance"),
    ]);
  } catch (err) {
    spinner.stop(`ERROR: ${err.message ?? err}`, "error");
    printEmpty();
    return;
  }
  spinner.stop("");

  const runtime   = snapshot?.runtime   ?? {};
  const scheduler = snapshot?.scheduler ?? {};
  const cycles    = snapshot?.cycles    ?? {};
  const inbox     = snapshot?.inbox_stats ?? {};

  // — AUTOMATON STATUS —
  printLine("AUTOMATON STATUS", "system bright");
  printSeparator();
  printLine(`  STATE:           ${String(runtime.state ?? "unknown").toUpperCase()}`, "system");
  printLine(`  SOUL:            ${runtime.soul ?? "unknown"}`, "system");
  printLine(`  TURNS:           ${runtime.turn_counter ?? 0}`, "system");
  printLine(`  LOOP:            ${runtime.loop_enabled ? "enabled" : "disabled"}`, "system");
  const transAge = runtime.last_transition_at_ns
    ? formatAge(runtime.last_transition_at_ns)
    : "never";
  printLine(`  LAST TRANSITION: ${transAge}`, "system");
  printEmpty();

  // — SCHEDULER —
  printLine("SCHEDULER", "system bright");
  printSeparator();
  printLine(`  ENABLED:         ${scheduler.enabled ? "yes" : "no"}`, "system");
  printLine(`  LOW CYCLES:      ${scheduler.low_cycles_mode ? "yes" : "no"}`, "system");
  if (scheduler.paused_reason) {
    printLine(`  PAUSED:          ${scheduler.paused_reason}`, "system");
  }
  const lastTick = scheduler.last_tick_finished_ns
    ? formatAge(scheduler.last_tick_finished_ns)
    : "never";
  printLine(`  LAST TICK:       ${lastTick}`, "system");
  printLine(`  LAST ERROR:      ${scheduler.last_tick_error ?? "none"}`, "system");
  printEmpty();

  // — WALLET —
  printLine("WALLET", "system bright");
  printSeparator();
  printLine(`  EVM ADDRESS:     ${state.automatonEvmAddress ?? "not configured"}`, "system");
  const ethStr = wallet?.eth_balance_wei_hex
    ? `${formatWei(wallet.eth_balance_wei_hex)} ETH`
    : "unknown";
  const balAge = wallet?.age_secs != null ? `, ${wallet.age_secs}s ago` : "";
  printLine(`  ETH BALANCE:     ${ethStr}${balAge}`, "system");
  const usdcStr = wallet?.usdc_balance_raw_hex
    ? `${formatUsdcHex(wallet.usdc_balance_raw_hex, wallet.usdc_decimals ?? 6)} USDC`
    : "unknown";
  printLine(`  USDC BALANCE:    ${usdcStr}${balAge}`, "system");
  printEmpty();

  // — CYCLES —
  if (cycles.total_cycles) {
    printLine("CYCLES", "system bright");
    printSeparator();
    printLine(`  TOTAL:           ${formatCycles(cycles.total_cycles)}`, "system");
    printLine(`  LIQUID:          ${formatCycles(cycles.liquid_cycles)}`, "system");
    if (cycles.burn_rate_cycles_per_hour != null) {
      const usdPart = cycles.burn_rate_usd_per_hour != null
        ? ` · $${Number(cycles.burn_rate_usd_per_hour).toFixed(3)}/h`
        : "";
      printLine(`  BURN/HOUR:       ${formatCycles(cycles.burn_rate_cycles_per_hour)}${usdPart}`, "system");
    }
    if (cycles.estimated_seconds_until_freezing_threshold != null) {
      printLine(`  RUNWAY:          ${formatRunway(cycles.estimated_seconds_until_freezing_threshold)}`, "system");
    }
    printEmpty();
  }

  // — INBOX —
  printLine("INBOX", "system bright");
  printSeparator();
  printLine(`  TOTAL:           ${inbox.total_messages ?? 0}`, "system");
  printLine(`  PENDING:         ${inbox.pending_count ?? 0}`, "system");
  printLine(`  STAGED:          ${inbox.staged_count ?? 0}`, "system");
  printLine(`  CONSUMED:        ${inbox.consumed_count ?? 0}`, "system");
  printEmpty();
}

// =============================================================================
// COMMANDS — Phase 2: log
// =============================================================================

async function cmdLog(flags) {
  const follow = flags.has("follow");

  const spinner = createSpinner("FETCHING LOG...");
  let snapshot;
  try {
    snapshot = await apiFetch("/api/snapshot");
  } catch (err) {
    spinner.stop(`ERROR: ${err.message ?? err}`, "error");
    printEmpty();
    return;
  }
  spinner.stop("");
  printEmpty();

  renderLogSnapshot(snapshot);

  if (follow) {
    startFollowMode("log", snapshot);
  }
}

function renderLogSnapshot(snapshot) {
  const jobs = [...(snapshot?.recent_jobs ?? [])];

  if (jobs.length === 0) {
    printLine("No recent job activity.", "system dim");
    printEmpty();
    return;
  }

  // Oldest first → newest at bottom
  jobs.sort((a, b) => {
    const ta = Number(a.finished_at_ns ?? a.started_at_ns ?? a.created_at_ns ?? 0);
    const tb = Number(b.finished_at_ns ?? b.started_at_ns ?? b.created_at_ns ?? 0);
    return ta - tb;
  });

  printLine("SCHEDULER LOG", "system bright");
  printSeparator();

  for (const j of jobs) {
    const ts     = formatTs(j.finished_at_ns ?? j.started_at_ns ?? j.created_at_ns);
    const kind   = padRight(j.kind, 14);
    const status = padRight(String(j.status).toLowerCase(), 10);
    const dur    = formatDurationNs(j.started_at_ns, j.finished_at_ns);
    const durStr = dur ? `  ${padRight(dur, 7)}` : "         ";
    const retry  = j.attempts > 1 ? `  [${j.attempts}/${j.max_attempts}]` : "";
    printLine(`  ${ts}  ${kind}  ${status}${durStr}${retry}`, "system");
    if (j.last_error) {
      printLine(`    ↳ ${j.last_error}`, "error");
    }
  }
  printEmpty();
}

// =============================================================================
// COMMANDS — Phase 2: peek
// =============================================================================

async function cmdPeek(flags) {
  const follow = flags.has("follow");

  const spinner = createSpinner("FETCHING INNER MONOLOGUE...");
  let snapshot;
  try {
    snapshot = await apiFetch("/api/snapshot");
  } catch (err) {
    spinner.stop(`ERROR: ${err.message ?? err}`, "error");
    printEmpty();
    return;
  }
  spinner.stop("");
  printEmpty();

  const turns = (snapshot?.recent_turns ?? []).filter((t) => t.inner_dialogue);

  if (turns.length === 0) {
    printLine("No inner monologue recorded yet.", "system dim");
    printEmpty();
    if (follow) startFollowMode("peek", snapshot);
    return;
  }

  printLine("INNER MONOLOGUE", "system bright");
  printSeparator();
  renderTurns(turns);

  if (follow) {
    startFollowMode("peek", snapshot);
  }
}

function renderTurns(turns) {
  // Oldest first → newest at bottom
  const sorted = [...turns].sort((a, b) => Number(a.created_at_ns ?? 0) - Number(b.created_at_ns ?? 0));

  for (const t of sorted) {
    const age    = formatAge(t.created_at_ns);
    const source = t.source_events > 0 ? `inbox_batch (${t.source_events})` : "scheduled";
    printLine(`${t.id} · ${source} · ${age}`, "system dim");

    if (t.input_summary) {
      printLine(`  INPUT: ${t.input_summary}`, "system dim");
    }

    const stats = [];
    if (t.tool_call_count > 0)       stats.push(`${t.tool_call_count} tool call${t.tool_call_count !== 1 ? "s" : ""}`);
    if (t.inference_round_count > 0) stats.push(`${t.inference_round_count} inference round${t.inference_round_count !== 1 ? "s" : ""}`);
    if (stats.length > 0) {
      printLine(`  ${stats.join(" · ")}`, "system dim");
    }

    if (t.error) {
      printLine(`  ↳ ERROR: ${t.error}`, "error");
    }

    if (t.inner_dialogue) {
      const lines = String(t.inner_dialogue).split("\n");
      for (const l of lines) {
        printLine(`  ${l}`, "system");
      }
    }

    printEmpty();
  }
}

// =============================================================================
// COMMANDS — Phase 2: price
// =============================================================================

async function cmdPrice() {
  printEmpty();

  if (!state.inboxContractAddress || !state.automatonEvmAddress) {
    printError("EVM config not loaded. Canister may still be initializing.");
    printLine("Tip: retry in a moment, or check 'status'.", "system dim");
    printEmpty();
    return;
  }

  const spinner = createSpinner("FETCHING PRICES FROM INBOX CONTRACT...");

  const viem = await ensureViem();
  if (!viem) {
    spinner.stop(
      "ERROR: viem not available (CDN unreachable). Price query requires contract read.",
      "error"
    );
    printEmpty();
    return;
  }

  const client = await ensurePublicClient();
  if (!client) {
    spinner.stop("ERROR: Could not create EVM client. Check EVM config.", "error");
    printEmpty();
    return;
  }

  try {
    const { parseAbi } = viem;
    const result = await client.readContract({
      address: state.inboxContractAddress,
      abi: parseAbi([
        "function minPricesFor(address automaton) view returns (uint256 usdcMin, uint256 ethMinWei, bool usesDefault)",
      ]),
      functionName: "minPricesFor",
      args: [state.automatonEvmAddress],
    });

    const [usdcMin, ethMinWei, usesDefault] = result;
    spinner.stop("");

    printLine("MESSAGE COST:", "system bright");
    printLine(`  ETH:  ${formatWei(ethMinWei)} ETH (minimum)`, "system");
    printLine(`  USDC: ${formatUsdcRaw(usdcMin, 6)} USDC (minimum, with --usdc flag)`, "system");
    printEmpty();
    printLine(`  Default pricing:  ${usesDefault ? "yes" : "no"}`, "system dim");
    printLine(`  Inbox contract:   ${state.inboxContractAddress}`, "system dim");
    printLine(`  Automaton:        ${state.automatonEvmAddress}`, "system dim");
    printEmpty();
  } catch (err) {
    spinner.stop(`ERROR: ${err.message ?? err}`, "error");
    printEmpty();
  }
}

// =============================================================================
// COMMANDS — Phase 3: connect / disconnect
// =============================================================================

/** Whether we've already attached window.ethereum event listeners. */
let _walletListenersAttached = false;

/**
 * Attach one-time listeners for EIP-1193 accountsChanged / chainChanged events.
 * Safe to call multiple times — attaches only once.
 */
function registerWalletListeners() {
  if (_walletListenersAttached || !window.ethereum) return;
  _walletListenersAttached = true;

  window.ethereum.on("accountsChanged", (accounts) => {
    if (accounts.length === 0) {
      // User locked their wallet or removed the site permission
      const prev = state.walletAddress;
      state.walletConnected = false;
      state.walletAddress   = null;
      state.chainId         = null;
      state.walletClient    = null;
      if (prev) {
        printEmpty();
        printLine("[wallet disconnected by provider]", "system dim");
        printEmpty();
      }
      updateStatusBar({ online: true, stateName: state.lastSnapshotData?.runtime?.state });
    } else {
      state.walletAddress = accounts[0];
      updateStatusBar({
        online: true,
        stateName: state.lastSnapshotData?.runtime?.state,
        walletAddress: accounts[0],
        chainId: state.chainId,
      });
    }
  });

  window.ethereum.on("chainChanged", (chainIdHex) => {
    const newId = parseInt(chainIdHex, 16);
    state.chainId      = newId;
    state.walletClient = null; // invalidate — chain changed
    updateStatusBar({
      online: true,
      stateName: state.lastSnapshotData?.runtime?.state,
      walletAddress: state.walletAddress,
      chainId: newId,
    });
    printEmpty();
    printLine(`[chain changed: ${chainName(newId)} (${newId})]`, "system dim");
    printEmpty();
  });
}

async function cmdConnect() {
  printEmpty();

  // Already connected
  if (state.walletConnected && state.walletAddress) {
    printLine(`ALREADY CONNECTED: ${state.walletAddress}`, "system");
    printLine("TYPE 'disconnect' TO UNLINK WALLET.", "system dim");
    printEmpty();
    return;
  }

  // No injected provider
  if (!window.ethereum) {
    printError("No wallet detected. Install MetaMask or another EVM wallet.");
    printEmpty();
    return;
  }

  const viem = await ensureViem();
  if (!viem) {
    printError("viem not available (CDN unreachable). Cannot connect wallet.");
    printEmpty();
    return;
  }

  const detectSpinner = createSpinner("DETECTING WALLET PROVIDER...");
  const walletClient = await ensureWalletClient();
  if (!walletClient) {
    detectSpinner.stop("ERROR: Failed to create wallet client.", "error");
    printEmpty();
    return;
  }
  detectSpinner.stop("DETECTING WALLET PROVIDER...     [OK]");

  const requestSpinner = createSpinner("REQUESTING ACCESS...");
  let address, chainId;
  try {
    const addresses = await walletClient.requestAddresses();
    address = addresses[0];
    chainId = await walletClient.getChainId();
  } catch (err) {
    if (err.code === 4001) {
      requestSpinner.stop("WALLET CONNECTION REJECTED BY USER.", "error");
    } else {
      requestSpinner.stop(`ERROR: ${err.message ?? err}`, "error");
    }
    state.walletClient = null; // don't cache a failed client
    printEmpty();
    return;
  }
  requestSpinner.stop("REQUESTING ACCESS...             [OK]");

  state.walletConnected = true;
  state.walletAddress   = address;
  state.chainId         = chainId;

  printSuccess(`CONNECTED: ${address}`);
  printLine(`CHAIN: ${chainName(chainId)} (${chainId})`, "system");

  // Chain validation
  if (state.targetChainId && chainId !== state.targetChainId) {
    printEmpty();
    printLine(
      `WARNING: Wrong chain. Expected ${chainName(state.targetChainId)} (${state.targetChainId}). Current: ${chainName(chainId)} (${chainId}).`,
      "error"
    );
    const switchSpinner = createSpinner("Attempting chain switch...");
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: `0x${state.targetChainId.toString(16)}` }],
      });
      const switched = await walletClient.getChainId();
      state.chainId = switched;
      switchSpinner.stop(`CHAIN SWITCHED: ${chainName(switched)} (${switched})`, "success");
    } catch (switchErr) {
      const msg = switchErr.code === 4001 ? "user rejected" : (switchErr.message ?? switchErr);
      switchSpinner.stop(`CHAIN SWITCH FAILED: ${msg}`, "error");
      printLine("Transactions may fail on the wrong chain.", "system dim");
    }
  }

  printEmpty();
  updateStatusBar({
    online: true,
    stateName: state.lastSnapshotData?.runtime?.state,
    walletAddress: state.walletAddress,
    chainId: state.chainId,
  });

  registerWalletListeners();
}

async function cmdDisconnect() {
  printEmpty();
  if (!state.walletConnected) {
    printLine("No wallet connected.", "system dim");
    printEmpty();
    return;
  }
  const prev = state.walletAddress;
  state.walletConnected = false;
  state.walletAddress   = null;
  state.chainId         = null;
  state.walletClient    = null;

  printLine(`DISCONNECTED: ${prev}`, "system");
  printEmpty();
  updateStatusBar({ online: true, stateName: state.lastSnapshotData?.runtime?.state });
}

// =============================================================================
// COMMANDS — Phase 4: send / donate
// =============================================================================

// Minimal human-readable ABIs — only functions the UI needs
const INBOX_ABI = [
  "function queueMessage(address automaton, string message, uint256 usdcAmount) payable returns (uint64)",
  "function queueMessageEth(address automaton, string message) payable returns (uint64)",
  "function minPricesFor(address automaton) view returns (uint256 usdcMin, uint256 ethMinWei, bool usesDefault)",
];

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parse a decimal string (e.g. "5.0") into a raw BigInt with `decimals` places.
 * Returns null on parse failure.
 */
function parseDecimalAmount(str, decimals = 6) {
  try {
    const parts = String(str).split(".");
    const whole = BigInt(parts[0] || "0");
    const factor = 10n ** BigInt(decimals);
    if (!parts[1]) return whole * factor;
    const fracStr = parts[1].slice(0, decimals).padEnd(decimals, "0");
    return whole * factor + BigInt(fracStr);
  } catch {
    return null;
  }
}

/**
 * Classify a transaction error as user-rejected vs other.
 */
function isTxRejected(err) {
  return (
    err.code === 4001 ||
    err.name === "UserRejectedRequestError" ||
    String(err.message ?? "").toLowerCase().includes("rejected")
  );
}

/**
 * Poll /api/conversation for `senderAddress` until a new agent reply appears
 * after `sentAfterMs`, or until 120s elapses.
 * Returns { reply, elapsed } or null on timeout.
 */
async function waitForReply(senderAddress, sentAfterMs) {
  const MAX_MS = 120_000;
  const start = Date.now();

  while (Date.now() - start < MAX_MS) {
    await sleep(2000);
    try {
      const convo = await apiFetch("/api/conversation", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sender: senderAddress }),
      });
      const entries = convo?.entries ?? [];
      if (entries.length) {
        const latest = entries[entries.length - 1];
        const entryTs = Number(latest.timestamp_ns) / 1e6;
        if (entryTs > sentAfterMs && latest.agent_reply) {
          return { reply: latest.agent_reply, elapsed: Date.now() - start };
        }
      }
    } catch (_) {}
  }
  return null;
}

async function cmdSend(args, flags) {
  printEmpty();

  const message = args.message;
  if (!message) {
    printError('Usage: send -m "your message" [--usdc]');
    printEmpty();
    return;
  }

  if (!state.walletConnected || !state.walletAddress) {
    printError("No wallet connected. Run 'connect' first.");
    printEmpty();
    return;
  }

  if (!state.inboxContractAddress || !state.automatonEvmAddress) {
    printError("EVM config not loaded. Canister may still be initializing.");
    printEmpty();
    return;
  }

  const useUsdc = flags.has("usdc");
  const viem = await ensureViem();
  if (!viem) {
    printError("viem not available (CDN unreachable).");
    printEmpty();
    return;
  }

  const pubClient = await ensurePublicClient();
  const walClient = await ensureWalletClient();
  if (!pubClient || !walClient) {
    printError("Could not create EVM clients. Try 'connect' again.");
    printEmpty();
    return;
  }

  const { parseAbi } = viem;
  const inboxAbi = parseAbi(INBOX_ABI);
  const erc20Abi = parseAbi(ERC20_ABI);

  // ── Fetch prices ──────────────────────────────────────────────────────────
  const priceSpinner = createSpinner("FETCHING CURRENT PRICES...");
  let ethMinWei, usdcMin;
  try {
    [usdcMin, ethMinWei] = await pubClient.readContract({
      address: state.inboxContractAddress,
      abi: inboxAbi,
      functionName: "minPricesFor",
      args: [state.automatonEvmAddress],
    });
    priceSpinner.stop("FETCHING CURRENT PRICES...       [OK]");
  } catch (err) {
    priceSpinner.stop(`ERROR: ${err.message ?? err}`, "error");
    printEmpty();
    return;
  }

  printLine(`  ETH MINIMUM: ${formatWei(ethMinWei)} ETH`, "system");
  if (useUsdc) printLine(`  USDC MINIMUM: ${formatUsdcRaw(usdcMin, 6)} USDC`, "system");

  // ── USDC approval ─────────────────────────────────────────────────────────
  if (useUsdc) {
    if (!state.usdcContractAddress) {
      printError("USDC contract address not configured.");
      printEmpty();
      return;
    }

    const allowSpinner = createSpinner("CHECKING USDC ALLOWANCE...");
    let allowance;
    try {
      allowance = await pubClient.readContract({
        address: state.usdcContractAddress,
        abi: erc20Abi,
        functionName: "allowance",
        args: [state.walletAddress, state.inboxContractAddress],
      });
      allowSpinner.stop("CHECKING USDC ALLOWANCE...       [OK]");
    } catch (err) {
      allowSpinner.stop(`ERROR: ${err.message ?? err}`, "error");
      printEmpty();
      return;
    }

    if (allowance < usdcMin) {
      const approveSpinner = createSpinner("USDC APPROVAL NEEDED. REQUESTING APPROVAL TX...");
      try {
        const approveTxHash = await walClient.writeContract({
          address: state.usdcContractAddress,
          abi: erc20Abi,
          functionName: "approve",
          args: [state.inboxContractAddress, usdcMin],
          account: state.walletAddress,
        });
        approveSpinner.stop(`APPROVAL TX: ${approveTxHash}`);
        const approveConfirmSpinner = createSpinner("CONFIRMING APPROVAL...");
        const approveReceipt = await pubClient.waitForTransactionReceipt({ hash: approveTxHash });
        if (approveReceipt.status === "reverted") {
          approveConfirmSpinner.stop("ERROR: Approval transaction reverted.", "error");
          printEmpty();
          return;
        }
        approveConfirmSpinner.stop("APPROVAL CONFIRMED ✓", "success");
      } catch (err) {
        approveSpinner.stop(
          isTxRejected(err) ? "APPROVAL REJECTED BY USER." : `ERROR: ${err.message ?? err}`,
          "error"
        );
        printEmpty();
        return;
      }
    }
  }

  // ── Show transaction details ──────────────────────────────────────────────
  printEmpty();
  printLine("PREPARING TRANSACTION...", "system");
  printLine(`  TO: ${state.inboxContractAddress}`, "system dim");
  if (useUsdc) {
    printLine(`  FUNCTION: queueMessage(automaton, "${message}", ${usdcMin})`, "system dim");
    printLine(`  VALUE: ${formatWei(ethMinWei)} ETH + ${formatUsdcRaw(usdcMin, 6)} USDC`, "system dim");
  } else {
    printLine(`  FUNCTION: queueMessageEth(automaton, "${message}")`, "system dim");
    printLine(`  VALUE: ${formatWei(ethMinWei)} ETH`, "system dim");
  }

  // ── Submit transaction ────────────────────────────────────────────────────
  const sentAfterMs = Date.now();
  const signSpinner = createSpinner("AWAITING WALLET SIGNATURE...");
  let txHash;
  try {
    txHash = useUsdc
      ? await walClient.writeContract({
          address: state.inboxContractAddress,
          abi: inboxAbi,
          functionName: "queueMessage",
          args: [state.automatonEvmAddress, message, usdcMin],
          value: ethMinWei,
          account: state.walletAddress,
        })
      : await walClient.writeContract({
          address: state.inboxContractAddress,
          abi: inboxAbi,
          functionName: "queueMessageEth",
          args: [state.automatonEvmAddress, message],
          value: ethMinWei,
          account: state.walletAddress,
        });
    signSpinner.stop(`TX SUBMITTED: ${txHash}`, "system");
  } catch (err) {
    signSpinner.stop(
      isTxRejected(err) ? "TRANSACTION REJECTED BY USER." : `ERROR: ${err.message ?? err}`,
      "error"
    );
    printEmpty();
    return;
  }

  // ── Wait for on-chain confirmation ────────────────────────────────────────
  const confirmSpinner = createSpinner("CONFIRMING...");
  let receipt;
  try {
    receipt = await pubClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status === "reverted") {
      confirmSpinner.stop("ERROR: Transaction reverted on-chain.", "error");
      printEmpty();
      return;
    }
    confirmSpinner.stop(`CONFIRMED ✓  block: ${receipt.blockNumber}`, "success");
  } catch (err) {
    confirmSpinner.stop(`ERROR: ${err.message ?? err}`, "error");
    printEmpty();
    return;
  }

  // ── Poll for automaton reply ──────────────────────────────────────────────
  printEmpty();
  const replySpinner = createSpinner("WAITING FOR AUTOMATON RESPONSE...");
  const result = await waitForReply(state.walletAddress, sentAfterMs);
  if (result) {
    const elapsed = (result.elapsed / 1000).toFixed(1);
    replySpinner.stop(`AUTOMATON REPLIED (${elapsed}s):`, "system bright");
    printSeparator();
    for (const l of String(result.reply).split("\n")) {
      printLine(l, "system");
    }
    printSeparator();
  } else {
    replySpinner.stop(
      "TIMEOUT: Automaton has not responded yet. Check 'log -f' for activity.",
      "error"
    );
  }
  printEmpty();
}

async function cmdDonate(positional, flags) {
  printEmpty();

  const amountStr = positional[0];
  if (!amountStr) {
    printError("Usage: donate <amount> [--usdc]");
    printEmpty();
    return;
  }

  if (!state.walletConnected || !state.walletAddress) {
    printError("No wallet connected. Run 'connect' first.");
    printEmpty();
    return;
  }

  if (!state.automatonEvmAddress) {
    printError("EVM config not loaded. Canister may still be initializing.");
    printEmpty();
    return;
  }

  const useUsdc = flags.has("usdc");
  const viem = await ensureViem();
  if (!viem) {
    printError("viem not available (CDN unreachable).");
    printEmpty();
    return;
  }

  const pubClient = await ensurePublicClient();
  const walClient = await ensureWalletClient();
  if (!pubClient || !walClient) {
    printError("Could not create EVM clients. Try 'connect' again.");
    printEmpty();
    return;
  }

  const { parseAbi, parseEther } = viem;

  if (!useUsdc) {
    // ── ETH donation — direct transfer ──────────────────────────────────────
    let weiAmount;
    try {
      weiAmount = parseEther(amountStr);
    } catch {
      printError(`Invalid ETH amount: '${amountStr}'`);
      printEmpty();
      return;
    }

    printLine("PREPARING DONATION...", "system");
    printLine(`  TO: ${state.automatonEvmAddress}`, "system dim");
    printLine(`  AMOUNT: ${amountStr} ETH`, "system dim");

    const signSpinner = createSpinner("AWAITING WALLET SIGNATURE...");
    let txHash;
    try {
      txHash = await walClient.sendTransaction({
        to: state.automatonEvmAddress,
        value: weiAmount,
        account: state.walletAddress,
      });
      signSpinner.stop(`TX SUBMITTED: ${txHash}`, "system");
    } catch (err) {
      signSpinner.stop(
        isTxRejected(err) ? "TRANSACTION REJECTED BY USER." : `ERROR: ${err.message ?? err}`,
        "error"
      );
      printEmpty();
      return;
    }

    const confirmSpinner = createSpinner("CONFIRMING...");
    try {
      const receipt = await pubClient.waitForTransactionReceipt({ hash: txHash });
      if (receipt.status === "reverted") {
        confirmSpinner.stop("ERROR: Transaction reverted on-chain.", "error");
        printEmpty();
        return;
      }
      confirmSpinner.stop("CONFIRMED ✓", "success");
    } catch (err) {
      confirmSpinner.stop(`ERROR: ${err.message ?? err}`, "error");
      printEmpty();
      return;
    }

    printSuccess(`DONATION COMPLETE: ${amountStr} ETH sent to automaton.`);
    printEmpty();
  } else {
    // ── USDC donation — direct ERC-20 transfer ───────────────────────────────
    if (!state.usdcContractAddress) {
      printError("USDC contract address not configured.");
      printEmpty();
      return;
    }

    const erc20Abi = parseAbi(ERC20_ABI);

    let decimals = 6;
    try {
      decimals = Number(
        await pubClient.readContract({
          address: state.usdcContractAddress,
          abi: erc20Abi,
          functionName: "decimals",
        })
      );
    } catch (_) {}

    const rawAmount = parseDecimalAmount(amountStr, decimals);
    if (rawAmount === null || rawAmount <= 0n) {
      printError(`Invalid USDC amount: '${amountStr}'`);
      printEmpty();
      return;
    }

    printLine("PREPARING USDC DONATION...", "system");
    printLine(`  TO: ${state.automatonEvmAddress}`, "system dim");
    printLine(`  AMOUNT: ${formatUsdcRaw(rawAmount, decimals)} USDC`, "system dim");

    const transferSpinner = createSpinner("TRANSFER TX...");
    let txHash;
    try {
      txHash = await walClient.writeContract({
        address: state.usdcContractAddress,
        abi: erc20Abi,
        functionName: "transfer",
        args: [state.automatonEvmAddress, rawAmount],
        account: state.walletAddress,
      });
      transferSpinner.stop(`TX SUBMITTED: ${txHash}`, "system");
    } catch (err) {
      transferSpinner.stop(
        isTxRejected(err) ? "TRANSACTION REJECTED BY USER." : `ERROR: ${err.message ?? err}`,
        "error"
      );
      printEmpty();
      return;
    }

    const confirmSpinner = createSpinner("CONFIRMING...");
    try {
      const receipt = await pubClient.waitForTransactionReceipt({ hash: txHash });
      if (receipt.status === "reverted") {
        confirmSpinner.stop("ERROR: Transaction reverted on-chain.", "error");
        printEmpty();
        return;
      }
      confirmSpinner.stop("CONFIRMED ✓", "success");
    } catch (err) {
      confirmSpinner.stop(`ERROR: ${err.message ?? err}`, "error");
      printEmpty();
      return;
    }

    printSuccess(`DONATION COMPLETE: ${formatUsdcRaw(rawAmount, decimals)} USDC sent to automaton.`);
    printEmpty();
  }
}

// =============================================================================
// FOLLOW MODE
// =============================================================================

/**
 * Enter follow mode for 'log' or 'peek'. Marks all items in the initial
 * snapshot as already-seen so only new entries are appended.
 */
function startFollowMode(type, initialSnapshot) {
  // Reset known-ID sets and populate from the initial snapshot
  state.knownJobIds        = new Set();
  state.knownTransitionIds = new Set();
  state.knownTurnIds       = new Set();

  if (type === "log") {
    for (const j of initialSnapshot?.recent_jobs ?? []) state.knownJobIds.add(j.id);
  } else if (type === "peek") {
    for (const t of initialSnapshot?.recent_turns ?? []) state.knownTurnIds.add(t.id);
  }

  state.isFollowMode = true;
  state.followType   = type;

  printLine(`FOLLOWING ${type.toUpperCase()} (q or Esc to stop)`, "system dim");
  printSeparator();

  inputRow.classList.add("follow-mode");
  inputEl.placeholder = "following — press q to stop";

  state.followInterval = setInterval(async () => {
    try {
      const snapshot = await apiFetch("/api/snapshot");
      if (type === "log")  appendNewLogEntries(snapshot);
      if (type === "peek") appendNewPeekEntries(snapshot);
    } catch (_) {}
  }, 2000);
}

/**
 * Stop an active follow mode session.
 * Called by Escape key, 'q' command, or Ctrl+C.
 */
function stopFollowMode() {
  if (!state.isFollowMode) return;
  clearInterval(state.followInterval);
  state.followInterval = null;
  state.isFollowMode   = false;
  state.followType     = null;

  // Restore normal prompt appearance
  inputRow.classList.remove("follow-mode");
  inputEl.placeholder = "type 'help' for commands...";

  printEmpty();
  printLine("[follow mode stopped]", "system dim");
  printEmpty();
}

function appendNewLogEntries(snapshot) {
  const newJobs = (snapshot?.recent_jobs ?? [])
    .filter((j) => !state.knownJobIds.has(j.id));

  for (const j of newJobs) {
    state.knownJobIds.add(j.id);
    const ts     = formatTs(j.finished_at_ns ?? j.started_at_ns ?? j.created_at_ns);
    const kind   = padRight(j.kind, 14);
    const status = padRight(String(j.status).toLowerCase(), 10);
    const dur    = formatDurationNs(j.started_at_ns, j.finished_at_ns);
    const durStr = dur ? `  ${padRight(dur, 7)}` : "         ";
    const retry  = j.attempts > 1 ? `  [${j.attempts}/${j.max_attempts}]` : "";
    printLine(`  ${ts}  ${kind}  ${status}${durStr}${retry}`, "system");
    if (j.last_error) {
      printLine(`    ↳ ${j.last_error}`, "error");
    }
  }
}

function appendNewPeekEntries(snapshot) {
  const newTurns = (snapshot?.recent_turns ?? [])
    .filter((t) => t.inner_dialogue && !state.knownTurnIds.has(t.id))
    .sort((a, b) => Number(a.created_at_ns ?? 0) - Number(b.created_at_ns ?? 0));

  for (const t of newTurns) {
    state.knownTurnIds.add(t.id);
    const age    = formatAge(t.created_at_ns);
    const source = t.source_events > 0 ? `inbox_batch (${t.source_events})` : "scheduled";
    printLine(`${t.id} · ${source} · ${age}`, "system dim");
    if (t.input_summary) {
      printLine(`  INPUT: ${t.input_summary}`, "system dim");
    }
    const stats = [];
    if (t.tool_call_count > 0)       stats.push(`${t.tool_call_count} tool call${t.tool_call_count !== 1 ? "s" : ""}`);
    if (t.inference_round_count > 0) stats.push(`${t.inference_round_count} inference round${t.inference_round_count !== 1 ? "s" : ""}`);
    if (stats.length > 0) printLine(`  ${stats.join(" · ")}`, "system dim");
    if (t.error) printLine(`  ↳ ERROR: ${t.error}`, "error");
    const lines = String(t.inner_dialogue).split("\n");
    for (const l of lines) printLine(`  ${l}`, "system");
    printEmpty();
  }
}

// =============================================================================
// COMMAND DISPATCH
// =============================================================================

/**
 * Dispatch a parsed command to the correct handler.
 * All handlers are async-safe; unhandled rejections are caught here.
 */
async function handleCommand(raw) {
  const { cmd, flags, args, positional } = parseInput(raw);

  // Echo the user's input
  printLine(`> ${raw}`, "user");

  if (!cmd) return;

  try {
    switch (cmd) {
      case "help":
        cmdHelp();
        break;

      case "clear":
        cmdClear();
        break;

      // Phase 2 — read-only commands
      case "status":
        await cmdStatus();
        break;

      case "log":
        await cmdLog(flags);
        break;

      case "peek":
        await cmdPeek(flags);
        break;

      case "price":
        await cmdPrice();
        break;

      // Phase 3 — wallet commands
      case "connect":
        await cmdConnect();
        break;

      case "disconnect":
        await cmdDisconnect();
        break;

      // Phase 4 — transaction commands
      case "send":
        await cmdSend(args, flags);
        break;

      case "donate":
        await cmdDonate(positional, flags);
        break;

      default:
        printEmpty();
        printError(`Unknown command: '${cmd}'. Type 'help' for assistance.`);
        printEmpty();
        break;
    }
  } catch (err) {
    printEmpty();
    printError(String(err?.message ?? err));
    printEmpty();
  }
}

// =============================================================================
// STATUS BAR
// =============================================================================

function updateStatusBar({ online, stateName, walletAddress, chainId } = {}) {
  const now  = new Date();
  const time = now.toLocaleTimeString("en-US", { hour12: false });

  if (online === false) {
    sbIndEl.className   = "sb-indicator offline";
    sbStateEl.textContent = "OFFLINE";
  } else {
    sbIndEl.className =
      stateName?.toLowerCase() === "idle" ? "sb-indicator idle" : "sb-indicator";
    sbStateEl.textContent = (stateName ?? "ONLINE").toUpperCase();
  }

  const addr = walletAddress ?? state.walletAddress;
  if (addr) {
    sbWalletEl.textContent = `${addr.slice(0, 6)}…${addr.slice(-4)}${chainId ? ` · chain ${chainId}` : ""}`;
  } else {
    sbWalletEl.textContent = "WALLET: not connected";
  }

  sbTimeEl.textContent = time;
}

// =============================================================================
// API UTILITIES
// =============================================================================

async function apiFetch(path, init) {
  const res  = await fetch(path, { cache: "no-store", ...init });
  const text = await res.text();
  let data   = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {}
  if (!res.ok) {
    throw new Error((data && data.error) || `HTTP ${res.status}`);
  }
  return data;
}

async function pollStatus() {
  try {
    const snapshot  = await apiFetch("/api/snapshot");
    const stateName = snapshot?.runtime?.state ?? "ONLINE";
    updateStatusBar({ online: true, stateName });
    state.lastSnapshotData = snapshot;
  } catch (_) {
    updateStatusBar({ online: false });
  }
}

// =============================================================================
// INPUT HANDLING
// =============================================================================

function recordHistory(cmd) {
  // Deduplicate consecutive identical commands
  if (cmd && state.commandHistory[0] !== cmd) {
    state.commandHistory.unshift(cmd);
    if (state.commandHistory.length > 100) {
      state.commandHistory.pop();
    }
  }
  state.historyIndex = -1;
}

inputEl.addEventListener("keydown", (e) => {
  switch (e.key) {
    case "Enter": {
      const raw = inputEl.value.trim();
      inputEl.value      = "";
      state.historyIndex = -1;

      if (!raw) break;

      // In follow mode, only 'q' / 'quit' exits — everything else is swallowed
      if (state.isFollowMode) {
        if (raw === "q" || raw === "quit") {
          stopFollowMode();
        }
        break;
      }

      recordHistory(raw);
      handleCommand(raw);
      break;
    }

    case "ArrowUp": {
      e.preventDefault();
      if (state.commandHistory.length === 0) break;
      if (state.historyIndex < state.commandHistory.length - 1) {
        state.historyIndex++;
      }
      inputEl.value = state.commandHistory[state.historyIndex] ?? "";
      requestAnimationFrame(() => {
        inputEl.selectionStart = inputEl.selectionEnd = inputEl.value.length;
      });
      break;
    }

    case "ArrowDown": {
      e.preventDefault();
      if (state.historyIndex <= 0) {
        state.historyIndex = -1;
        inputEl.value      = "";
        break;
      }
      state.historyIndex--;
      inputEl.value = state.commandHistory[state.historyIndex] ?? "";
      break;
    }

    case "Escape": {
      if (state.isFollowMode) {
        stopFollowMode();
      }
      break;
    }
  }
});

// Click anywhere in the page to restore input focus (unless user is selecting text)
document.addEventListener("click", () => {
  if (!window.getSelection()?.toString()) {
    inputEl.focus();
  }
});

// =============================================================================
// BACKGROUND CANVAS ANIMATION
// =============================================================================

const bgCanvas  = document.getElementById("bg-canvas");
const bgCtx     = bgCanvas.getContext("2d");
const hbOverlay = document.getElementById("heartbeat-overlay");

let canvasW = 0;
let canvasH = 0;
let shapes  = [];

class Shape {
  constructor() {
    this.init();
  }

  init() {
    this.x         = Math.random() * canvasW;
    this.y         = Math.random() * canvasH;
    this.size      = Math.random() * 7 + 3;
    this.type      = Math.floor(Math.random() * 3); // 0=square 1=triangle 2=circle
    this.baseAlpha = Math.random() * 0.1 + 0.02;
    this.alpha     = this.baseAlpha;
    this.phase     = Math.random() * Math.PI * 2;
    this.speed     = Math.random() * 0.007 + 0.002;
  }

  update(t, pulseActive) {
    this.alpha = this.baseAlpha + Math.sin(t * this.speed + this.phase) * 0.03;
    if (pulseActive) {
      const dx      = this.x - canvasW / 2;
      const dy      = this.y - canvasH / 2;
      const dist    = Math.hypot(dx, dy);
      const wavePos = (t % 2800) * 0.38;
      if (Math.abs(dist - wavePos) < 90) {
        this.alpha = Math.min(0.55, this.baseAlpha + 0.45);
      }
    }
  }

  draw() {
    bgCtx.fillStyle = `rgba(204, 255, 0, ${this.alpha})`;
    bgCtx.beginPath();
    if (this.type === 0) {
      bgCtx.fillRect(this.x, this.y, this.size, this.size);
      return;
    }
    if (this.type === 1) {
      bgCtx.moveTo(this.x, this.y + this.size);
      bgCtx.lineTo(this.x + this.size / 2, this.y);
      bgCtx.lineTo(this.x + this.size, this.y + this.size);
    } else {
      bgCtx.arc(
        this.x + this.size / 2,
        this.y + this.size / 2,
        this.size / 2,
        0,
        Math.PI * 2
      );
    }
    bgCtx.fill();
  }
}

function initCanvas() {
  canvasW = window.innerWidth;
  canvasH = window.innerHeight;
  bgCanvas.width  = canvasW;
  bgCanvas.height = canvasH;
  // Reduced density vs original: divide by 6500 (was ~4000)
  const count = Math.floor((canvasW * canvasH) / 6500);
  shapes = Array.from({ length: count }, () => new Shape());
}

let pulseActive = false;
let lastPulse   = 0;

function animateCanvas(t) {
  bgCtx.clearRect(0, 0, canvasW, canvasH);

  // Trigger radial pulse every 45s (reduced from 30s)
  if (t - lastPulse > 45_000) {
    pulseActive = true;
    lastPulse   = t;
    hbOverlay.style.opacity = "0.28";
    setTimeout(() => {
      pulseActive = false;
      hbOverlay.style.opacity = "0";
    }, 2200);
  }

  for (const s of shapes) {
    s.update(t, pulseActive);
    s.draw();
  }

  requestAnimationFrame(animateCanvas);
}

// =============================================================================
// BOOT
// =============================================================================

function boot() {
  // Canvas
  initCanvas();
  requestAnimationFrame(animateCanvas);
  window.addEventListener("resize", initCanvas);

  // Boot sequence (async — fetches canister status + EVM config, updates lines)
  runBoot();

  // Recurring poll every 5s (initial poll is done inside runBoot)
  state.pollHandle = setInterval(pollStatus, 5_000);

  // Focus input after boot animation completes (~BOOT_LINE_COUNT lines × step + buffer)
  setTimeout(() => inputEl.focus(), BOOT_LINE_COUNT * BOOT_DELAY_STEP + 200);
}

boot();
