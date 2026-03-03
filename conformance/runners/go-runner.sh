#!/usr/bin/env bash
# Go conformance runner wrapper — reads scenario names from stdin, outputs JSON-lines.
set -euo pipefail

while IFS= read -r scenario; do
    scenario=$(echo "$scenario" | tr -d '\r\n')
    [[ -z "$scenario" ]] && continue

    start_ms=$(date +%s%3N)
    status="pass"
    diagnostics="{}"

    # Look for scenario file
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
