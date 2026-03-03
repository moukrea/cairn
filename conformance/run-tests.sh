#!/usr/bin/env bash
# run-tests.sh — Conformance test orchestrator for cairn.
# Sends scenario names to language containers via docker exec, collects JSON-lines results,
# and outputs a results matrix.
#
# Usage:
#   run-tests.sh [--tier 0|1|2] [--pair <lang1>-<lang2>] [--category <cat>] [--scenario <name>]
#
# Environment:
#   CAIRN_TEST_TIMEOUT   Per-scenario timeout in seconds (default: 60)
#   CAIRN_ARTIFACTS_DIR  Directory for failure artifacts (default: /results/artifacts)

set -euo pipefail

LANGUAGES=(rust ts go py php)
CATEGORIES=(pairing session data wire crypto transport mesh forward)
TIER="${CAIRN_TEST_TIER:-0}"
TIMEOUT="${CAIRN_TEST_TIMEOUT:-60}"
ARTIFACTS_DIR="${CAIRN_ARTIFACTS_DIR:-/results/artifacts}"
RESULTS_DIR="${CAIRN_RESULTS_DIR:-/results}"
FILTER_PAIR=""
FILTER_CATEGORY=""
FILTER_SCENARIO=""

# Performance budgets from spec section 7.3 (in seconds)
declare -A BUDGETS=(
    [pairing]=30
    [session]=10
    [data]=5
    [wire]=2
    [crypto]=2
    [transport]=30
    [mesh]=20
    [forward]=30
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier)
            TIER="$2"
            shift 2
            ;;
        --pair)
            FILTER_PAIR="$2"
            shift 2
            ;;
        --category)
            FILTER_CATEGORY="$2"
            shift 2
            ;;
        --scenario)
            FILTER_SCENARIO="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$ARTIFACTS_DIR" "$RESULTS_DIR"

# Generate all unique unordered language pairs (5 choose 2 = 10)
generate_pairs() {
    local pairs=()
    for ((i=0; i<${#LANGUAGES[@]}; i++)); do
        for ((j=i+1; j<${#LANGUAGES[@]}; j++)); do
            pairs+=("${LANGUAGES[$i]}-${LANGUAGES[$j]}")
        done
    done
    echo "${pairs[@]}"
}

# Discover test scenarios from YAML files in a category directory
discover_scenarios() {
    local category="$1"
    local dir="/conformance/tests/$category"
    if [[ -d "$dir" ]]; then
        find "$dir" -name '*.yml' -o -name '*.yaml' | sort | while read -r f; do
            basename "$f" .yml | sed 's/\.yaml$//'
        done
    fi
}

# Send a scenario to a language container and collect the result
run_scenario_on_container() {
    local lang="$1"
    local scenario="$2"
    local container="conformance-${lang}-1"

    local result
    result=$(echo "$scenario" | timeout "$TIMEOUT" docker exec -i "$container" \
        cairn-conformance-runner 2>/dev/null) || true

    if [[ -z "$result" ]]; then
        echo "{\"scenario\":\"$scenario\",\"lang\":\"$lang\",\"status\":\"fail\",\"duration_ms\":0,\"diagnostics\":{\"error\":\"timeout or no output\"}}"
    else
        echo "$result"
    fi
}

# Run a scenario between two language containers
run_pair_scenario() {
    local lang_a="$1"
    local lang_b="$2"
    local scenario="$3"
    local category="$4"
    local start_ms

    start_ms=$(date +%s%3N)

    # Send scenario to both containers
    local result_a result_b
    result_a=$(run_scenario_on_container "$lang_a" "$scenario")
    result_b=$(run_scenario_on_container "$lang_b" "$scenario")

    local end_ms
    end_ms=$(date +%s%3N)
    local duration_ms=$((end_ms - start_ms))

    # Extract status from results
    local status_a status_b
    status_a=$(echo "$result_a" | grep -oP '"status"\s*:\s*"[^"]*"' | head -1 | cut -d'"' -f4)
    status_b=$(echo "$result_b" | grep -oP '"status"\s*:\s*"[^"]*"' | head -1 | cut -d'"' -f4)

    local final_status="pass"
    if [[ "$status_a" != "pass" || "$status_b" != "pass" ]]; then
        final_status="fail"
        # Capture failure artifacts
        capture_artifacts "$lang_a" "$lang_b" "$scenario" "$result_a" "$result_b"
    fi

    # Check performance budget
    local budget_s="${BUDGETS[$category]:-60}"
    local budget_ms=$((budget_s * 1000))
    local budget_exceeded="false"
    if [[ $duration_ms -gt $budget_ms ]]; then
        budget_exceeded="true"
    fi

    echo "{\"scenario\":\"$scenario\",\"pair\":\"${lang_a}-${lang_b}\",\"category\":\"$category\",\"status\":\"$final_status\",\"duration_ms\":$duration_ms,\"budget_exceeded\":$budget_exceeded,\"results\":{\"$lang_a\":$result_a,\"$lang_b\":$result_b}}"
}

# Capture failure artifacts for debugging
capture_artifacts() {
    local lang_a="$1"
    local lang_b="$2"
    local scenario="$3"
    local result_a="$4"
    local result_b="$5"

    local artifact_dir="$ARTIFACTS_DIR/${scenario}/${lang_a}-${lang_b}"
    mkdir -p "$artifact_dir"

    # Save results
    echo "$result_a" > "$artifact_dir/result-${lang_a}.json"
    echo "$result_b" > "$artifact_dir/result-${lang_b}.json"

    # Capture container logs
    docker logs "conformance-${lang_a}-1" > "$artifact_dir/logs-${lang_a}.txt" 2>&1 || true
    docker logs "conformance-${lang_b}-1" > "$artifact_dir/logs-${lang_b}.txt" 2>&1 || true

    # Capture network state from both containers
    docker exec "conformance-${lang_a}-1" network-shaper state > "$artifact_dir/network-${lang_a}.json" 2>/dev/null || true
    docker exec "conformance-${lang_b}-1" network-shaper state > "$artifact_dir/network-${lang_b}.json" 2>/dev/null || true
}

# Print results matrix header
print_matrix_header() {
    printf "%-15s" "PAIR"
    for cat in "${CATEGORIES[@]}"; do
        printf "%-12s" "$cat"
    done
    echo ""
    printf '%0.s-' {1..111}
    echo ""
}

# Main execution
echo "=========================================="
echo " cairn conformance test runner"
echo " Tier: $TIER"
echo " Timeout: ${TIMEOUT}s per scenario"
echo "=========================================="
echo ""

# Initialize results matrix: pair -> category -> pass/fail/skip
declare -A MATRIX

pairs=($(generate_pairs))
total_pass=0
total_fail=0
total_skip=0
total_budget_exceeded=0

for pair in "${pairs[@]}"; do
    if [[ -n "$FILTER_PAIR" && "$pair" != "$FILTER_PAIR" ]]; then
        continue
    fi

    IFS='-' read -r lang_a lang_b <<< "$pair"

    for category in "${CATEGORIES[@]}"; do
        if [[ -n "$FILTER_CATEGORY" && "$category" != "$FILTER_CATEGORY" ]]; then
            continue
        fi

        # Check tier requirements
        case "$category" in
            transport)
                if [[ "$TIER" -lt 1 ]]; then
                    MATRIX["${pair},${category}"]="skip"
                    total_skip=$((total_skip + 1))
                    continue
                fi
                ;;
            forward)
                if [[ "$TIER" -lt 2 ]]; then
                    MATRIX["${pair},${category}"]="skip"
                    total_skip=$((total_skip + 1))
                    continue
                fi
                ;;
        esac

        scenarios=$(discover_scenarios "$category")
        if [[ -z "$scenarios" ]]; then
            MATRIX["${pair},${category}"]="skip"
            total_skip=$((total_skip + 1))
            continue
        fi

        cat_pass=0
        cat_fail=0

        while IFS= read -r scenario; do
            if [[ -n "$FILTER_SCENARIO" && "$scenario" != "$FILTER_SCENARIO" ]]; then
                continue
            fi

            result=$(run_pair_scenario "$lang_a" "$lang_b" "$scenario" "$category")
            echo "$result" >> "$RESULTS_DIR/results.jsonl"

            status=$(echo "$result" | grep -oP '"status"\s*:\s*"[^"]*"' | head -1 | cut -d'"' -f4)
            budget=$(echo "$result" | grep -oP '"budget_exceeded"\s*:\s*[a-z]*' | cut -d: -f2)

            if [[ "$status" == "pass" ]]; then
                cat_pass=$((cat_pass + 1))
                total_pass=$((total_pass + 1))
            else
                cat_fail=$((cat_fail + 1))
                total_fail=$((total_fail + 1))
            fi

            if [[ "$budget" == "true" ]]; then
                total_budget_exceeded=$((total_budget_exceeded + 1))
            fi
        done <<< "$scenarios"

        if [[ $cat_fail -gt 0 ]]; then
            MATRIX["${pair},${category}"]="FAIL($cat_fail)"
        else
            MATRIX["${pair},${category}"]="pass($cat_pass)"
        fi
    done
done

# Print results matrix
echo ""
echo "=== RESULTS MATRIX ==="
echo ""
print_matrix_header

for pair in "${pairs[@]}"; do
    if [[ -n "$FILTER_PAIR" && "$pair" != "$FILTER_PAIR" ]]; then
        continue
    fi
    printf "%-15s" "$pair"
    for category in "${CATEGORIES[@]}"; do
        if [[ -n "$FILTER_CATEGORY" && "$category" != "$FILTER_CATEGORY" ]]; then
            continue
        fi
        printf "%-12s" "${MATRIX["${pair},${category}"]:-n/a}"
    done
    echo ""
done

echo ""
echo "=== SUMMARY ==="
echo "Pass:             $total_pass"
echo "Fail:             $total_fail"
echo "Skip:             $total_skip"
echo "Budget exceeded:  $total_budget_exceeded"
echo ""

# Write summary JSON
cat > "$RESULTS_DIR/summary.json" <<EOF
{
    "tier": $TIER,
    "total_pass": $total_pass,
    "total_fail": $total_fail,
    "total_skip": $total_skip,
    "budget_exceeded": $total_budget_exceeded,
    "exit_code": $([ $total_fail -eq 0 ] && echo 0 || echo 1)
}
EOF

# Exit with failure if any tests failed
if [[ $total_fail -gt 0 ]]; then
    echo "FAILED: $total_fail test(s) failed"
    exit 1
fi

echo "ALL TESTS PASSED"
exit 0
