#!/bin/bash
#===============================================================================
# SSH Brute-Force Attempt Detector
# Monitors auth.log for repeated failed SSH login attempts with configurable
# thresholds, whitelisting, alert actions, and detailed reporting.
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
LOG_FILE="${LOG_FILE:-/var/log/auth.log}"
THRESHOLD="${THRESHOLD:-5}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
ALERT_LOG="${ALERT_LOG:-/var/log/ssh_bruteforce_alerts.log}"
WHITELIST_FILE="${WHITELIST_FILE:-/etc/ssh_bruteforce_whitelist}"
ENABLE_ALERT_SCRIPT="${ENABLE_ALERT_SCRIPT:-false}"
ALERT_SCRIPT="${ALERT_SCRIPT:-/usr/local/bin/ssh_bruteforce_alert}"
LOOKBACK_MINUTES="${LOOKBACK_MINUTES:-60}"

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

is_whitelisted() {
    local ip="$1"
    [[ -f "$WHITELIST_FILE" ]] && grep -qFx "$ip" "$WHITELIST_FILE" 2>/dev/null
}

run_alert_script() {
    local ip="$1"
    local count="$2"
    if [[ "$ENABLE_ALERT_SCRIPT" == "true" ]] && [[ -x "$ALERT_SCRIPT" ]]; then
        "$ALERT_SCRIPT" "$ip" "$count" 2>/dev/null || true
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--log)      LOG_FILE="$2"; shift 2 ;;
            -t|--threshold) THRESHOLD="$2"; shift 2 ;;
            -i|--interval)  CHECK_INTERVAL="$2"; shift 2 ;;
            -o|--output)   ALERT_LOG="$2"; shift 2 ;;
            -w|--whitelist) WHITELIST_FILE="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]
  -l, --log FILE       Auth log path (default: /var/log/auth.log)
  -t, --threshold N    Failed attempts before alert (default: 5)
  -i, --interval N     Check interval in seconds (default: 60)
  -o, --output FILE    Alert log file
  -w, --whitelist FILE IP whitelist (one IP per line)
  -h, --help           Show this help"
                exit 0
                ;;
            *) shift ;;
        esac
    done
}

#-------------------------------------------------------------------------------
# Main detection loop
#-------------------------------------------------------------------------------
main() {
    parse_args "$@"

    if [[ ! -r "$LOG_FILE" ]]; then
        log "ERROR: Cannot read $LOG_FILE (try running as root)"
        exit 1
    fi

    log "SSH Brute-Force Detector started"
    log "  Log: $LOG_FILE | Threshold: $THRESHOLD | Interval: ${CHECK_INTERVAL}s"
    log "  Alert log: $ALERT_LOG"
    [[ -f "$WHITELIST_FILE" ]] && log "  Whitelist: $WHITELIST_FILE (($(wc -l < "$WHITELIST_FILE")) IPs)"
    echo ""

    while true; do
        FAILED_IPS=$(grep "Failed password for" "$LOG_FILE" 2>/dev/null | \
            awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | \
            sort | uniq -c | sort -rn)

        if [[ -n "$FAILED_IPS" ]]; then
            while read -r count ip; do
                [[ -z "$ip" ]] && continue
                if is_whitelisted "$ip"; then
                    continue
                fi
                if (( count >= THRESHOLD )); then
                    log "ALERT: Possible brute-force from $ip ($count failed attempts)"
                    echo "$(date -Iseconds) $ip $count" >> "$ALERT_LOG"
                    run_alert_script "$ip" "$count"
                fi
            done <<< "$FAILED_IPS"
        fi
        sleep "$CHECK_INTERVAL"
    done
}

main "$@"
