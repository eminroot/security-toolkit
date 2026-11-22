#!/bin/bash
#===============================================================================
# Failed Login Counter with IP Blocking
# Counts failed logins per IP, blocks repeat offenders via iptables/ufw,
# supports whitelisting, dry-run mode, and persistent block lists.
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
LOG_FILE="${LOG_FILE:-/var/log/auth.log}"
THRESHOLD="${THRESHOLD:-5}"
DRY_RUN="${DRY_RUN:-false}"
WHITELIST="${WHITELIST:-}"
BLOCK_LOG="${BLOCK_LOG:-/var/log/failed_login_blocks.log}"
CHAIN_NAME="${CHAIN_NAME:-FAILED_LOGIN}"

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Counts failed SSH/login attempts and blocks IPs exceeding threshold.

Options:
  -l, --log FILE      Auth log path (default: /var/log/auth.log)
  -t, --threshold N   Failures before block (default: 5)
  -w, --whitelist IP  Comma-separated IPs to never block
  -n, --dry-run       Report only, do not block
  -h, --help          Show this help

Environment: LOG_FILE, THRESHOLD, DRY_RUN, WHITELIST
EOF
}

is_whitelisted() {
    local ip="$1"
    [[ -z "$WHITELIST" ]] && return 1
    for w in ${WHITELIST//,/ }; do
        [[ "$ip" == "$w" ]] && return 0
    done
    return 1
}

get_failed_ips() {
    grep -E "Failed password for|authentication failure" "$LOG_FILE" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i=="from" || $i=="for") {
            for(j=i+1;j<=NF;j++) if($j~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {print $j; next}
        }}' | sort | uniq -c | sort -rn
}

block_ip_iptables() {
    local ip="$1"
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
        return 0
    fi
    return 1
}

block_ip_ufw() {
    local ip="$1"
    ufw deny from "$ip" 2>/dev/null && return 0
    return 1
}

block_ip() {
    local ip="$1"
    local count="$2"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  [DRY-RUN] Would block $ip ($count failures)"
        return 0
    fi

    if command -v iptables &>/dev/null; then
        if block_ip_iptables "$ip"; then
            echo "  -> Blocked via iptables"
            echo "$(date -Iseconds) $ip $count iptables" >> "$BLOCK_LOG"
            return 0
        fi
    fi

    if command -v ufw &>/dev/null; then
        if block_ip_ufw "$ip"; then
            echo "  -> Blocked via ufw"
            echo "$(date -Iseconds) $ip $count ufw" >> "$BLOCK_LOG"
            return 0
        fi
    fi

    echo "  -> No firewall available. Add manually: block $ip"
    echo "$(date -Iseconds) $ip $count manual" >> "$BLOCK_LOG"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--log)      LOG_FILE="$2"; shift 2 ;;
            -t|--threshold) THRESHOLD="$2"; shift 2 ;;
            -w|--whitelist) WHITELIST="$2"; shift 2 ;;
            -n|--dry-run)  DRY_RUN="true"; shift ;;
            -h|--help)     usage; exit 0 ;;
            *) shift ;;
        esac
    done

    if [[ ! -r "$LOG_FILE" ]]; then
        echo "ERROR: Cannot read $LOG_FILE (run as root?)"
        exit 1
    fi

    echo "[*] Failed Login Counter"
    echo "[*] Log: $LOG_FILE | Threshold: $THRESHOLD"
    [[ "$DRY_RUN" == "true" ]] && echo "[*] DRY RUN - no blocks will be applied"
    echo ""

    blocked=0
    while read -r count ip; do
        [[ -z "$ip" ]] && continue
        if is_whitelisted "$ip"; then
            continue
        fi
        if (( count >= THRESHOLD )); then
            echo "[BLOCK] $ip ($count failures)"
            block_ip "$ip" "$count"
            (( blocked++ )) || true
        fi
    done < <(get_failed_ips)

    echo ""
    echo "[+] Processed. IPs flagged: $blocked"
}

main "$@"
