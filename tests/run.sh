#!/usr/bin/env bash
# Needs wasm-tools and node; neither is a build dependency, so this is not
# wired into `make`.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 tests/wrap.py "$tmp/t.wat"
wasm-tools parse "$tmp/t.wat" -o "$tmp/t.wasm"
node tests/adapters.mjs "$tmp/t.wasm"
