#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [output_did_path]" >&2
  echo "Example: $0 ic-automaton.did" >&2
  exit 1
fi

if ! command -v candid-extractor >/dev/null 2>&1; then
  echo "Missing required tool: candid-extractor" >&2
  echo "Install it with: cargo install candid-extractor" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

if [[ $# -eq 1 ]]; then
  if [[ "$1" = /* ]]; then
    output_path="$1"
  else
    output_path="${repo_root}/$1"
  fi
else
  output_path="${repo_root}/ic-automaton.did"
fi

wasm_path=""
for candidate in \
  "${repo_root}/target/wasm32-unknown-unknown/release/backend.wasm" \
  "${repo_root}/target/wasm32-unknown-unknown/release/deps/backend.wasm"
do
  if [[ -f "${candidate}" ]]; then
    wasm_path="${candidate}"
    break
  fi
done

if [[ -z "${wasm_path}" ]]; then
  echo "Could not find backend.wasm in target/wasm32-unknown-unknown/release." >&2
  echo "Run 'icp build' first, then run this script again." >&2
  exit 1
fi

mkdir -p "$(dirname "${output_path}")"
candid-extractor "${wasm_path}" > "${output_path}"

echo "Generated Candid: ${output_path}"
