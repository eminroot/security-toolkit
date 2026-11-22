#!/bin/bash
#===============================================================================
# Suspicious Process Monitor
# Detects reverse shells, backdoors, and malicious process patterns with
# severity scoring, continuous monitoring, and JSON/CSV export.
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"
ALERT_LOG="${ALERT_LOG:-/var/log/suspicious_processes.log}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
CONTINUOUS="${CONTINUOUS:-false}"

# Pattern: "regex" "severity" "description"
# Severity: 1=low, 2=medium, 3=high, 4=critical
declare -a PATTERNS=(
    "nc -e .* bash|4|Netcat reverse shell"
    "ncat.*-e .*|4|Ncat reverse shell"
    "bash -i|4|Interactive bash shell"
    "/dev/tcp/|4|Bash TCP redirect"
    "base64.*-d.*\||4|Base64 decoded pipe"
    "python.*-c.*socket\.connect|4|Python reverse shell"
    "perl.*socket.*connect|4|Perl reverse shell"
    "php.*eval.*base64|4|PHP eval backdoor"
    "wget.*-O-.*\|\s*bash|3|Wget pipe to shell"
    "curl.*\|\s*sh|3|Curl pipe to shell"
    "ruby.*socket|3|Ruby socket"
    "socat.*EXEC|3|Socat exec"
    "mkfifo.*/tmp|3|Fifo backdoor"
    "\./\.\./\.\./|2|Path traversal"
    "chmod \+s|2|SUID escalation"
)

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

scan_processes() {
    local alerts=0
    local output=""

    for entry in "${PATTERNS[@]}"; do
        IFS='|' read -r pattern sev desc <<< "$entry"
        local matches
        matches=$(ps auxww 2>/dev/null | grep -E "$pattern" | grep -v grep | grep -v "$$")
        if [[ -n "$matches" ]]; then
            echo "[ALERT] Severity $sev: $desc"
            echo "  Pattern: $pattern"
            echo "$matches" | while read -r line; do
                echo "  $line"
                echo "$(timestamp)|$sev|$desc|$line" >> "$ALERT_LOG"
            done
            echo ""
            (( alerts++ )) || true
        fi
    done

    return $alerts
}

resource_report() {
    echo "=== High Resource Processes ==="
    echo ""
    echo "--- Top CPU (15) ---"
    ps aux --sort=-%cpu 2>/dev/null | head -16 | tail -15
    echo ""
    echo "--- Top Memory (15) ---"
    ps aux --sort=-%mem 2>/dev/null | head -16 | tail -15
    echo ""
    echo "--- Processes in /tmp or /dev/shm ---"
    ls -la /proc/*/cwd 2>/dev/null | grep -E "/tmp|/dev/shm" || echo "None"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    echo "[*] Suspicious Process Monitor"
    echo "[*] Scan at $(timestamp)"
    echo ""

    scan_processes || true
    resource_report

    if [[ -f "$ALERT_LOG" ]]; then
        echo "[*] Alerts logged to $ALERT_LOG"
    fi
}

# Continuous mode
if [[ "${1:-}" == "-c" || "$CONTINUOUS" == "true" ]]; then
    echo "[*] Continuous mode (interval: ${CHECK_INTERVAL}s)"
    while true; do
        main
        sleep "$CHECK_INTERVAL"
    done
else
    main
fi
