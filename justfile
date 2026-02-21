default:
  @just --list

anvil_host := "127.0.0.1"
anvil_port := "18545"
anvil_chain_id := "31337"
anvil_rpc_url := "http://" + anvil_host + ":" + anvil_port
anvil_private_key := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
bootstrap_usdc_amount := "1000000000"
bootstrap_eth_wei := "500000000000000"
automaton_wait_timeout_secs := "180"
automaton_wait_poll_secs := "2"
local_url := "http://127.0.0.1:8000"

ic-start:
  icp network start --background || true
  icp network ping --wait-healthy

ic-stop:
  icp network stop

anvil-start:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p .local
  if [ -f .local/anvil.pid ] && kill -0 "$(cat .local/anvil.pid)" 2>/dev/null; then
    echo "Anvil already running with PID $(cat .local/anvil.pid)"
  else
    nohup anvil --host {{anvil_host}} --port {{anvil_port}} --chain-id {{anvil_chain_id}} --silent >/tmp/anvil-ic-automaton.log 2>&1 &
    echo $! > .local/anvil.pid
    echo "Started Anvil with PID $(cat .local/anvil.pid)"
  fi
  cast chain-id --rpc-url {{anvil_rpc_url}}

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

deploy-canister inbox_address="":
  #!/usr/bin/env bash
  set -euo pipefail
  inbox_address="{{inbox_address}}"
  if [ -z "$inbox_address" ]; then
    inbox_address="$(cat .local/inbox_contract_address)"
  fi
  icp build backend
  if ! icp canister create backend -e local >/dev/null 2>&1; then
    echo "backend canister already exists on local"
  fi
  icp canister install backend -e local --mode reinstall --args "(record { ecdsa_key_name = \"dfx_test_key\"; inbox_contract_address = opt \"$inbox_address\"; evm_chain_id = opt {{anvil_chain_id}} })"
  icp canister call backend set_evm_chain_id_admin "({{anvil_chain_id}})" -e local >/dev/null
  canister_id="$(icp canister status backend -e local | awk '/Canister Id:/ { print $3 }')"
  echo "Canister ID: $canister_id"
  echo "UI URL: http://$canister_id.localhost:8000/"

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

bootstrap:
  #!/usr/bin/env bash
  set -euo pipefail
  just ic-start
  just anvil-start
  just deploy-inbox
  just deploy-canister
  automaton_address="$(just --quiet automaton-evm-address)"
  echo "Automaton EVM address: $automaton_address"
  just seed-bootstrap-payer

down:
  #!/usr/bin/env bash
  set -euo pipefail
  just anvil-stop || true
  just ic-stop || true
