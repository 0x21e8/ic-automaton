set dotenv-load := true

default:
  @just --list

anvil_host := "127.0.0.1"
anvil_port := "18545"
anvil_chain_id := "31337"
base_chain_id := "8453"
anvil_rpc_url := "http://" + anvil_host + ":" + anvil_port
anvil_private_key := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
bootstrap_usdc_amount := "1000000000"
bootstrap_eth_wei := "500000000000000"
bootstrap_wallet_usdc_amount := "100000000"
bootstrap_wallet_eth_wei := "1000000000000000000"
bootstrap_secondary_evm_address := "0x62dAFfDC4D59eA05fedDb0a77A266B0a7b6F28ca"
automaton_wait_timeout_secs := "180"
automaton_wait_poll_secs := "2"
local_url := "http://127.0.0.1:8000"
openrouter_default_model := "google/gemini-3-flash-preview"
ic_llm_default_model := "llama3.1:8b"
ollama_host := "127.0.0.1"
ollama_port := "11434"
ollama_api_url := "http://" + ollama_host + ":" + ollama_port
llm_default_canister_id := "w36hm-eqaaa-aaaal-qr76a-cai"

ic-start:
  icp network start --background || true
  icp network ping --wait-healthy

ic-stop:
  icp network stop

anvil-start mode="local" fork_url="" fork_block="":
  #!/usr/bin/env bash
  set -euo pipefail
  mode="{{mode}}"
  fork_url="{{fork_url}}"
  fork_block="{{fork_block}}"
  mkdir -p .local
  current_mode=""
  if [ -f .local/anvil.mode ]; then
    current_mode="$(cat .local/anvil.mode)"
  fi

  if [ -f .local/anvil.pid ]; then
    if kill -0 "$(cat .local/anvil.pid)" 2>/dev/null; then
      if [ "$current_mode" = "$mode" ]; then
        echo "Anvil already running with PID $(cat .local/anvil.pid) in mode=$mode"
      else
        echo "Anvil is running in mode=$current_mode and will be restarted with mode=$mode"
        kill "$(cat .local/anvil.pid)"
        rm -f .local/anvil.pid
      fi
    else
      echo "Removing stale Anvil PID file: $(cat .local/anvil.pid)"
      rm -f .local/anvil.pid
    fi
  fi

  if [ ! -f .local/anvil.pid ]; then
    case "$mode" in
      local)
        chain_id="{{anvil_chain_id}}"
        nohup anvil --host {{anvil_host}} --port {{anvil_port}} --chain-id "$chain_id" --silent >/tmp/anvil-ic-automaton.log 2>&1 &
        ;;
      base-fork)
        chain_id="{{base_chain_id}}"
        if [ -z "$fork_url" ]; then
          fork_url="${BASE_MAINNET_RPC_URL:-}"
        fi
        if [ -z "$fork_url" ]; then
          echo "base-fork mode requires fork_url arg or BASE_MAINNET_RPC_URL env var" >&2
          exit 1
        fi
        anvil_cmd=(anvil --host {{anvil_host}} --port {{anvil_port}} --chain-id "$chain_id" --fork-url "$fork_url" --silent)
        if [ -n "$fork_block" ]; then
          anvil_cmd+=(--fork-block-number "$fork_block")
        fi
        nohup "${anvil_cmd[@]}" >/tmp/anvil-ic-automaton.log 2>&1 &
        ;;
      *)
        echo "unsupported mode=$mode (supported: local, base-fork)" >&2
        exit 1
        ;;
    esac
    echo $! > .local/anvil.pid
    printf '%s\n' "$mode" > .local/anvil.mode
    printf '%s\n' "$chain_id" > .local/anvil.chain_id
    echo "Started Anvil with PID $(cat .local/anvil.pid) in mode=$mode"
  fi
  ready=0
  for _ in $(seq 1 50); do
    if curl -fsS \
      -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
      "{{anvil_rpc_url}}" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.2
  done

  if [ "$ready" -ne 1 ]; then
    echo "Anvil did not become ready at {{anvil_rpc_url}}" >&2
    if [ -f /tmp/anvil-ic-automaton.log ]; then
      tail -n 40 /tmp/anvil-ic-automaton.log >&2 || true
    fi
    exit 1
  fi

anvil-stop:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -f .local/anvil.pid ] && kill -0 "$(cat .local/anvil.pid)" 2>/dev/null; then
    kill "$(cat .local/anvil.pid)"
    rm -f .local/anvil.pid
    echo "Stopped Anvil"
  else
    echo "No tracked Anvil PID in .local/anvil.pid"
  fi

deploy-inbox:
  #!/usr/bin/env bash
  set -euo pipefail
  cd evm
  mock_usdc_address="$(
    forge create src/mocks/MockUSDC.sol:MockUSDC \
      --rpc-url {{anvil_rpc_url}} \
      --private-key {{anvil_private_key}} \
      --broadcast | awk '/Deployed to:/ { print $3 }'
  )"
  inbox_address="$(
    forge create src/Inbox.sol:Inbox \
      --rpc-url {{anvil_rpc_url}} \
      --private-key {{anvil_private_key}} \
      --broadcast \
      --constructor-args "$mock_usdc_address" | awk '/Deployed to:/ { print $3 }'
  )"
  cd ..
  mkdir -p .local
  printf '%s\n' "$mock_usdc_address" > .local/mock_usdc_address
  printf '%s\n' "$inbox_address" > .local/inbox_contract_address
  echo "MockUSDC: $mock_usdc_address"
  echo "Inbox:    $inbox_address"

deploy-canister inbox_address="" llm_canister_id=llm_default_canister_id evm_chain_id=anvil_chain_id evm_rpc_url=anvil_rpc_url inference_mode="openrouter" openrouter_model=openrouter_default_model:
  #!/usr/bin/env bash
  set -euo pipefail
  escape_candid_text() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
  }
  inbox_address="{{inbox_address}}"
  llm_canister_id="{{llm_canister_id}}"
  evm_chain_id="{{evm_chain_id}}"
  evm_rpc_url="{{evm_rpc_url}}"
  inference_mode="{{inference_mode}}"
  openrouter_model="{{openrouter_model}}"
  if [ -z "$inbox_address" ]; then
    inbox_address="$(cat .local/inbox_contract_address)"
  fi
  icp build backend
  if ! icp canister create backend -e local >/dev/null 2>&1; then
    echo "backend canister already exists on local"
  fi
  icp canister install backend -e local --mode reinstall --args "(record { ecdsa_key_name = \"dfx_test_key\"; inbox_contract_address = opt \"$inbox_address\"; evm_chain_id = opt ($evm_chain_id : nat64); evm_rpc_url = opt \"$evm_rpc_url\"; evm_confirmation_depth = opt (0 : nat64); llm_canister_id = opt principal \"$llm_canister_id\" })"
  case "$inference_mode" in
    openrouter)
      model_escaped="$(escape_candid_text "$openrouter_model")"
      icp canister call backend set_inference_provider '(variant { OpenRouter })' -e local >/dev/null
      icp canister call backend set_inference_model "(\"$model_escaped\")" -e local >/dev/null
      if [ -n "${OPENROUTER_BASE_URL:-}" ]; then
        base_url_escaped="$(escape_candid_text "$OPENROUTER_BASE_URL")"
        icp canister call backend set_openrouter_base_url "(\"$base_url_escaped\")" -e local >/dev/null
      fi
      if [ -z "${OPENROUTER_API_KEY:-}" ] || [ "${OPENROUTER_API_KEY}" = "replace-with-your-openrouter-api-key" ]; then
        echo "OPENROUTER_API_KEY must be set to a valid OpenRouter API key." >&2
        exit 1
      fi
      api_key_escaped="$(escape_candid_text "$OPENROUTER_API_KEY")"
      icp canister call backend set_openrouter_api_key "(opt \"$api_key_escaped\")" -e local >/dev/null
      echo "Configured OpenRouter provider with model=$openrouter_model and OPENROUTER_API_KEY"
      ;;
    icllm|ic-llm|ollama)
      ;;
    *)
      echo "unsupported inference_mode=$inference_mode (supported: openrouter, icllm)" >&2
      exit 1
      ;;
  esac
  canister_id="$(icp canister status backend -e local | awk '/Canister Id:/ { print $3 }')"
  echo "Canister ID: $canister_id"
  echo "UI URL: http://$canister_id.localhost:8000/"

deploy-llm:
  #!/usr/bin/env bash
  set -euo pipefail
  icp build llm
  if ! icp canister create llm -e local >/dev/null 2>&1; then
    echo "llm canister already exists on local"
  fi
  icp canister install llm -e local --mode reinstall
  llm_canister_id="$(icp canister status llm -e local | awk '/Canister Id:/ { print $3 }')"
  mkdir -p .local
  printf '%s\n' "$llm_canister_id" > .local/llm_canister_id
  echo "LLM canister ID: $llm_canister_id"

automaton-evm-address timeout_secs=automaton_wait_timeout_secs poll_secs=automaton_wait_poll_secs:
  #!/usr/bin/env bash
  set -euo pipefail
  deadline="$(( $(date +%s) + {{timeout_secs}} ))"

  while true; do
    response="$(icp canister call backend get_automaton_evm_address '()' -e local 2>/dev/null || true)"
    automaton_address="$(
      printf '%s\n' "$response" \
        | tr '"(),;' '\n' \
        | grep -E '^0x[0-9a-fA-F]{40}$' \
        | head -n1 \
        | tr '[:upper:]' '[:lower:]' || true
    )"

    if [ -n "$automaton_address" ]; then
      mkdir -p .local
      printf '%s\n' "$automaton_address" > .local/automaton_evm_address
      echo "$automaton_address"
      exit 0
    fi

    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out waiting for automaton EVM address after {{timeout_secs}}s" >&2
      echo "last get_automaton_evm_address response: ${response:-<empty>}" >&2
      exit 1
    fi

    sleep "{{poll_secs}}"
  done

seed-bootstrap-payer:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f .local/mock_usdc_address ] || [ ! -f .local/inbox_contract_address ]; then
    echo "Missing inbox deployment artifacts in .local; run just deploy-inbox first" >&2
    exit 1
  fi

  sender_address="$(cast wallet address --private-key {{anvil_private_key}})"
  mock_usdc_address="$(cat .local/mock_usdc_address)"
  inbox_address="$(cat .local/inbox_contract_address)"

  cast send "$mock_usdc_address" \
    "mint(address,uint256)" \
    "$sender_address" \
    {{bootstrap_usdc_amount}} \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}} >/dev/null

  cast send "$mock_usdc_address" \
    "approve(address,uint256)" \
    "$inbox_address" \
    {{bootstrap_usdc_amount}} \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}} >/dev/null

  echo "Seeded payer $sender_address with {{bootstrap_usdc_amount}} mock USDC and approved inbox"

seed-bootstrap-wallets automaton_address="" recipient_address=bootstrap_secondary_evm_address:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f .local/mock_usdc_address ]; then
    echo "Missing mock USDC address in .local; run just deploy-inbox first" >&2
    exit 1
  fi

  automaton_address="{{automaton_address}}"
  recipient_address="{{recipient_address}}"
  if [ -z "$automaton_address" ]; then
    automaton_address="$(just --quiet automaton-evm-address)"
  fi

  for address in "$automaton_address" "$recipient_address"; do
    if ! printf '%s\n' "$address" | grep -Eiq '^0x[0-9a-f]{40}$'; then
      echo "Invalid EVM address: $address" >&2
      exit 1
    fi
  done

  mock_usdc_address="$(cat .local/mock_usdc_address)"

  cast send "$mock_usdc_address" \
    "transfer(address,uint256)" \
    "$automaton_address" \
    {{bootstrap_wallet_usdc_amount}} \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}} >/dev/null
  cast send "$automaton_address" \
    --value {{bootstrap_wallet_eth_wei}} \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}} >/dev/null

  cast send "$mock_usdc_address" \
    "transfer(address,uint256)" \
    "$recipient_address" \
    {{bootstrap_wallet_usdc_amount}} \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}} >/dev/null
  cast send "$recipient_address" \
    --value {{bootstrap_wallet_eth_wei}} \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}} >/dev/null

  echo "Seeded $automaton_address and $recipient_address with {{bootstrap_wallet_usdc_amount}} mock USDC and {{bootstrap_wallet_eth_wei}} wei"

configure-inference-openrouter model="":
  #!/usr/bin/env bash
  set -euo pipefail

  model="{{model}}"
  if [ -z "$model" ]; then
    model="${OPENROUTER_MODEL:-{{openrouter_default_model}}}"
  fi
  escape_candid_text() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
  }
  model_escaped="$(escape_candid_text "$model")"

  icp canister call backend set_inference_provider '(variant { OpenRouter })' -e local >/dev/null
  icp canister call backend set_inference_model "(\"$model_escaped\")" -e local >/dev/null

  if [ -n "${OPENROUTER_BASE_URL:-}" ]; then
    base_url_escaped="$(escape_candid_text "$OPENROUTER_BASE_URL")"
    icp canister call backend set_openrouter_base_url "(\"$base_url_escaped\")" -e local >/dev/null
  fi

  if [ -n "${OPENROUTER_API_KEY:-}" ]; then
    api_key_escaped="$(escape_candid_text "$OPENROUTER_API_KEY")"
    icp canister call backend set_openrouter_api_key "(opt \"$api_key_escaped\")" -e local >/dev/null
    echo "Configured OpenRouter provider with model=$model and OPENROUTER_API_KEY"
  else
    echo "Configured OpenRouter provider with model=$model"
    echo "OPENROUTER_API_KEY is not set; inference will fail until you set it."
  fi

ollama-start model="":
  #!/usr/bin/env bash
  set -euo pipefail
  model="{{model}}"
  if [ -z "$model" ]; then
    model="${IC_LLM_MODEL:-{{ic_llm_default_model}}}"
  fi
  mkdir -p .local

  if curl -fsS "{{ollama_api_url}}/api/tags" >/dev/null 2>&1; then
    echo "Ollama already reachable at {{ollama_api_url}}"
  elif [ -f .local/ollama.pid ] && kill -0 "$(cat .local/ollama.pid)" 2>/dev/null; then
    echo "Ollama already running with tracked PID $(cat .local/ollama.pid)"
  else
    rm -f .local/ollama.pid
    nohup ollama serve >/tmp/ollama-ic-automaton.log 2>&1 &
    echo $! > .local/ollama.pid
    echo "Started Ollama with PID $(cat .local/ollama.pid)"
  fi

  ready=0
  for _ in $(seq 1 50); do
    if curl -fsS "{{ollama_api_url}}/api/tags" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.2
  done

  if [ "$ready" -ne 1 ]; then
    echo "Ollama did not become ready at {{ollama_api_url}}" >&2
    if [ -f /tmp/ollama-ic-automaton.log ]; then
      tail -n 40 /tmp/ollama-ic-automaton.log >&2 || true
    fi
    exit 1
  fi

  ollama pull "$model"

ollama-stop:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -f .local/ollama.pid ] && kill -0 "$(cat .local/ollama.pid)" 2>/dev/null; then
    kill "$(cat .local/ollama.pid)"
    rm -f .local/ollama.pid
    echo "Stopped Ollama"
  else
    echo "No tracked Ollama PID in .local/ollama.pid"
  fi

configure-inference-icllm model="":
  #!/usr/bin/env bash
  set -euo pipefail

  escape_candid_text() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
  }

  model="{{model}}"
  if [ -z "$model" ]; then
    model="${IC_LLM_MODEL:-{{ic_llm_default_model}}}"
  fi
  model_escaped="$(escape_candid_text "$model")"
  icp canister call backend set_inference_provider '(variant { IcLlm })' -e local >/dev/null
  icp canister call backend set_inference_model "(\"$model_escaped\")" -e local >/dev/null
  echo "Configured IcLlm provider with model=$model"
  echo "Configured backend to use llm canister from init args."

send-message-usdc message="hello automaton" usdc_amount="1000000" eth_wei=bootstrap_eth_wei:
  #!/usr/bin/env bash
  set -euo pipefail
  automaton_address="$(just --quiet automaton-evm-address)"
  inbox_address="$(cat .local/inbox_contract_address)"

  cast send "$inbox_address" \
    "queueMessage(address,string,uint256)" \
    "$automaton_address" \
    "{{message}}" \
    "{{usdc_amount}}" \
    --value "{{eth_wei}}" \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}}

send-message-eth-only message="hello automaton (eth-only)" eth_wei=bootstrap_eth_wei:
  #!/usr/bin/env bash
  set -euo pipefail
  automaton_address="$(just --quiet automaton-evm-address)"
  inbox_address="$(cat .local/inbox_contract_address)"

  cast send "$inbox_address" \
    "queueMessageEth(address,string)" \
    "$automaton_address" \
    "{{message}}" \
    --value "{{eth_wei}}" \
    --rpc-url {{anvil_rpc_url}} \
    --private-key {{anvil_private_key}}

bootstrap mode="openrouter" openrouter_model="" ic_llm_model="" evm_mode="local" base_rpc_url="" base_fork_block="":
  #!/usr/bin/env bash
  set -euo pipefail
  mode="{{mode}}"
  openrouter_model="{{openrouter_model}}"
  ic_llm_model="{{ic_llm_model}}"
  evm_mode="{{evm_mode}}"
  base_rpc_url="{{base_rpc_url}}"
  base_fork_block="{{base_fork_block}}"
  evm_chain_id="{{anvil_chain_id}}"
  llm_canister_id="{{llm_default_canister_id}}"
  if [ -z "$openrouter_model" ]; then
    openrouter_model="${OPENROUTER_MODEL:-{{openrouter_default_model}}}"
  fi
  if [ -z "$ic_llm_model" ]; then
    ic_llm_model="${IC_LLM_MODEL:-{{ic_llm_default_model}}}"
  fi
  just ic-start
  case "$evm_mode" in
    local)
      just anvil-start
      ;;
    base-fork)
      just anvil-start "base-fork" "$base_rpc_url" "$base_fork_block"
      evm_chain_id="{{base_chain_id}}"
      ;;
    *)
      echo "unsupported evm_mode=$evm_mode (supported: local, base-fork)" >&2
      exit 1
      ;;
  esac
  just deploy-inbox
  case "$mode" in
    openrouter)
      ;;
    icllm|ic-llm|ollama)
      just ollama-start "$ic_llm_model"
      just deploy-llm
      llm_canister_id="$(cat .local/llm_canister_id)"
      ;;
    *)
      echo "unsupported mode=$mode (supported: openrouter, icllm)" >&2
      exit 1
      ;;
  esac

  just deploy-canister "" "$llm_canister_id" "$evm_chain_id" "{{anvil_rpc_url}}" "$mode" "$openrouter_model"
  automaton_address="$(just --quiet automaton-evm-address)"
  echo "Automaton EVM address: $automaton_address"
  just seed-bootstrap-payer
  just seed-bootstrap-wallets "$automaton_address"
  case "$mode" in
    openrouter)
      just configure-inference-openrouter "$openrouter_model"
      ;;
    icllm|ic-llm|ollama)
      just configure-inference-icllm "$ic_llm_model"
      ;;
    *)
      echo "unsupported mode=$mode (supported: openrouter, icllm)" >&2
      exit 1
      ;;
  esac

down mode="all":
  #!/usr/bin/env bash
  set -euo pipefail
  mode="{{mode}}"
  case "$mode" in
    all|icllm|ic-llm|ollama) just ollama-stop || true ;;
    openrouter) ;;
    *)
      echo "unsupported mode=$mode (supported: all, openrouter, icllm)" >&2
      exit 1
      ;;
  esac
  just anvil-stop || true
  just ic-stop || true
