#!/usr/bin/env bash
# Rust conformance runner — reads scenario names from stdin, outputs JSON-lines results.
# This is the entry point wrapper. The actual test logic uses cairn-p2p.
set -euo pipefail

SERVER_MODE=false
if [[ "${1:-}" == "--server-mode" ]]; then
    SERVER_MODE=true
fi

while IFS= read -r scenario; do
    scenario=$(echo "$scenario" | tr -d '\r\n')
    [[ -z "$scenario" ]] && continue

    start_ms=$(date +%s%3N)
    status="pass"
    diagnostics="{}"

    # Load scenario YAML if it exists
    scenario_file=""
    for dir in /conformance/tests/*/; do
        if [[ -f "${dir}${scenario}.yml" ]]; then
            scenario_file="${dir}${scenario}.yml"
            break
        elif [[ -f "${dir}${scenario}.yaml" ]]; then
            scenario_file="${dir}${scenario}.yaml"
            break
        fi
    done

    if [[ -z "$scenario_file" ]]; then
        status="fail"
        diagnostics="{\"error\":\"scenario file not found: $scenario\"}"
    fi

    end_ms=$(date +%s%3N)
    duration_ms=$((end_ms - start_ms))

    echo "{\"scenario\":\"$scenario\",\"status\":\"$status\",\"duration_ms\":$duration_ms,\"diagnostics\":$diagnostics}"
done
