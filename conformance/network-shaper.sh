#!/usr/bin/env bash
# network-shaper.sh — Controlled networking for cairn conformance tests.
# Requires NET_ADMIN capability. Runs inside containers.
#
# Usage:
#   network-shaper nat <profile>           Apply NAT profile
#   network-shaper netem <params>          Apply packet loss/latency
#   network-shaper disconnect              Drop all outbound packets
#   network-shaper reconnect               Remove packet drop rule
#   network-shaper reset                   Clear all rules
#
# NAT Profiles:
#   open             No rules (default)
#   full_cone        SNAT with static port mapping
#   restricted_cone  SNAT + per-destination conntrack filtering
#   symmetric        SNAT with random port per destination:port tuple
#
# Netem Parameters:
#   --delay <ms>     Latency in milliseconds
#   --jitter <ms>    Jitter in milliseconds
#   --loss <pct>     Packet loss percentage

set -euo pipefail

IFACE="${CAIRN_NET_IFACE:-eth0}"

log() {
    echo "{\"component\":\"network-shaper\",\"action\":\"$1\",\"detail\":\"$2\"}" >&2
}

reset_all() {
    # Flush iptables rules
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true

    # Remove tc qdisc
    tc qdisc del dev "$IFACE" root 2>/dev/null || true

    log "reset" "all iptables and tc rules cleared on $IFACE"
}

apply_nat() {
    local profile="$1"

    # Clear existing NAT rules first
    iptables -t nat -F 2>/dev/null || true

    case "$profile" in
        open)
            log "nat" "open — no NAT rules applied"
            ;;
        full_cone)
            # SNAT with static port mapping: same external port for all destinations
            iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE --random-fully 2>/dev/null || \
                iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
            # Full cone: allow any incoming to the mapped port
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -j ACCEPT
            log "nat" "full_cone — MASQUERADE with unrestricted inbound"
            ;;
        restricted_cone)
            # SNAT + only allow return traffic from addresses we've sent to
            iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -j DROP
            log "nat" "restricted_cone — MASQUERADE with conntrack-filtered inbound"
            ;;
        symmetric)
            # SNAT with random port per destination:port tuple
            iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE --random
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -j DROP
            # Mark packets to force different mappings per dest
            iptables -t mangle -A OUTPUT -j CONNMARK --set-mark 1
            log "nat" "symmetric — random port per destination:port"
            ;;
        *)
            echo "{\"error\":\"unknown NAT profile: $profile\"}" >&2
            exit 1
            ;;
    esac
}

apply_netem() {
    local delay=""
    local jitter=""
    local loss=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --delay)
                delay="$2"
                shift 2
                ;;
            --jitter)
                jitter="$2"
                shift 2
                ;;
            --loss)
                loss="$2"
                shift 2
                ;;
            *)
                echo "{\"error\":\"unknown netem parameter: $1\"}" >&2
                exit 1
                ;;
        esac
    done

    # Remove existing qdisc
    tc qdisc del dev "$IFACE" root 2>/dev/null || true

    # Build netem command
    local cmd="tc qdisc add dev $IFACE root netem"
    local desc=""

    if [[ -n "$delay" ]]; then
        cmd="$cmd delay ${delay}ms"
        desc="delay=${delay}ms"
        if [[ -n "$jitter" ]]; then
            cmd="$cmd ${jitter}ms"
            desc="$desc jitter=${jitter}ms"
        fi
    fi

    if [[ -n "$loss" ]]; then
        cmd="$cmd loss ${loss}%"
        desc="$desc loss=${loss}%"
    fi

    eval "$cmd"
    log "netem" "$desc"
}

disconnect() {
    iptables -A OUTPUT -j DROP
    log "disconnect" "all outbound packets dropped"
}

reconnect() {
    iptables -D OUTPUT -j DROP 2>/dev/null || true
    log "reconnect" "outbound DROP rule removed"
}

# State query: dump current iptables and tc rules as JSON
dump_state() {
    local ipt_rules
    local tc_rules
    ipt_rules=$(iptables -L -n 2>/dev/null | head -50)
    tc_rules=$(tc qdisc show dev "$IFACE" 2>/dev/null)

    echo "{\"iptables\":$(echo "$ipt_rules" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""'),\"tc\":$(echo "$tc_rules" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')}"
}

case "${1:-help}" in
    nat)
        apply_nat "${2:?NAT profile required (open|full_cone|restricted_cone|symmetric)}"
        ;;
    netem)
        shift
        apply_netem "$@"
        ;;
    disconnect)
        disconnect
        ;;
    reconnect)
        reconnect
        ;;
    reset)
        reset_all
        ;;
    state)
        dump_state
        ;;
    help|--help|-h)
        echo "Usage: network-shaper <command> [args]"
        echo ""
        echo "Commands:"
        echo "  nat <profile>        Apply NAT profile: open, full_cone, restricted_cone, symmetric"
        echo "  netem [--delay ms] [--jitter ms] [--loss pct]"
        echo "                       Apply packet loss/latency via tc/netem"
        echo "  disconnect           Drop all outbound packets (simulate disconnect)"
        echo "  reconnect            Remove outbound DROP (simulate reconnect)"
        echo "  reset                Clear all iptables and tc rules"
        echo "  state                Dump current network rules as JSON"
        exit 0
        ;;
    *)
        echo "{\"error\":\"unknown command: $1\"}" >&2
        exit 1
        ;;
esac
