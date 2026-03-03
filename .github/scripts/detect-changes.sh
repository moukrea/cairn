#!/usr/bin/env bash
# detect-changes.sh — Detect which components changed in a PR.
# Outputs GitHub Actions outputs: rust, ts, go, py, php, relay, signal (true/false).
# Rust always runs (reference impl, workspace Cargo.lock changes affect it).
set -euo pipefail

if [ -z "${GITHUB_OUTPUT:-}" ]; then
  echo "GITHUB_OUTPUT not set — running in local mode"
  GITHUB_OUTPUT="/dev/stdout"
fi

BASE_REF="${1:-origin/main}"

changed_files=$(git diff --name-only "$BASE_REF"...HEAD 2>/dev/null || git diff --name-only "$BASE_REF" HEAD)

check_path() {
  local prefix="$1"
  echo "$changed_files" | grep -q "^${prefix}/" && echo "true" || echo "false"
}

# Rust always runs
echo "rust=true" >> "$GITHUB_OUTPUT"

echo "ts=$(check_path 'packages/ts/cairn-p2p')" >> "$GITHUB_OUTPUT"
echo "go=$(check_path 'packages/go/cairn-p2p')" >> "$GITHUB_OUTPUT"
echo "py=$(check_path 'packages/py/cairn-p2p')" >> "$GITHUB_OUTPUT"
echo "php=$(check_path 'packages/php/cairn-p2p')" >> "$GITHUB_OUTPUT"
echo "relay=$(check_path 'services/relay')" >> "$GITHUB_OUTPUT"
echo "signal=$(check_path 'services/signaling')" >> "$GITHUB_OUTPUT"

# Also flag if workspace-level files changed (Cargo.toml, Cargo.lock)
workspace_changed=$(echo "$changed_files" | grep -qE '^(Cargo\.(toml|lock))$' && echo "true" || echo "false")
echo "workspace=$workspace_changed" >> "$GITHUB_OUTPUT"

echo "--- Detected changes ---"
echo "rust=true (always)"
echo "ts=$(check_path 'packages/ts/cairn-p2p')"
echo "go=$(check_path 'packages/go/cairn-p2p')"
echo "py=$(check_path 'packages/py/cairn-p2p')"
echo "php=$(check_path 'packages/php/cairn-p2p')"
echo "relay=$(check_path 'services/relay')"
echo "signal=$(check_path 'services/signaling')"
echo "workspace=$workspace_changed"
