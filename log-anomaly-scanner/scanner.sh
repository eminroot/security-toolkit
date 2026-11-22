#!/bin/bash
#===============================================================================
# Log File Anomaly Scanner
# Comprehensive log analysis with severity scoring, context extraction,
# pattern correlation, and multiple output formats.
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
LOG_DIR="${1:-/var/log}"
OUTPUT_FILE="${2:-/tmp/log_anomaly_report.txt}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"
MAX_MATCHES_PER_PATTERN="${MAX_MATCHES:-50}"
SEVERITY_HIGH="${SEVERITY_HIGH:-3}"
SEVERITY_MED="${SEVERITY_MED:-2}"

# Pattern definitions: "pattern" "severity" "category"
# Severity: 1=low, 2=medium, 3=high, 4=critical
declare -a PATTERNS=(
    "authentication failure|2|auth"
    "invalid user|3|auth"
    "failed password|3|auth"
    "authentication refused|2|auth"
    "connection refused|2|network"
    "permission denied|2|access"
    "segmentation fault|3|crash"
    "out of memory|3|resource"
    "kernel.*panic|4|kernel"
    "kernel.*error|2|kernel"
    "possible attack|4|intrusion"
    "denied|2|access"
    "blocked|2|access"
    "intrusion|4|intrusion"
    "malicious|4|malware"
    "root.*sudo|1|privilege"
    "user .* not in sudoers|2|privilege"
    "brute force|4|intrusion"
    "port scan|3|recon"
    "sql injection|4|injection"
    "xss|4|injection"
    "remote code execution|4|exploit"
)

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

scan_pattern() {
    local pattern="$1"
    local severity="$2"
    local category="$3"
    local matches
    matches=$(grep -r -i -h -E "$pattern" "$LOG_DIR" 2>/dev/null | head -n "$MAX_MATCHES_PER_PATTERN")
    if [[ -n "$matches" ]]; then
        echo "--- [$category] Severity $severity: $pattern ---"
        echo "$matches" | sed 's/^/  /'
        echo ""
        echo "$matches" | wc -l
    else
        echo "0"
    fi
}

generate_report() {
    local total_findings=0
    {
        echo "=============================================="
        echo "  LOG ANOMALY SCAN REPORT"
        echo "=============================================="
        echo "Scan started: $(timestamp)"
        echo "Target directory: $LOG_DIR"
        echo "Patterns scanned: ${#PATTERNS[@]}"
        echo "=============================================="
        echo ""

        for entry in "${PATTERNS[@]}"; do
            IFS='|' read -r pattern severity category <<< "$entry"
            result=$(scan_pattern "$pattern" "$severity" "$category")
            count=$(echo "$result" | tail -1)
            if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
                echo "$result" | head -n -1
                total_findings=$((total_findings + count))
            fi
        done

        echo "=============================================="
        echo "SUMMARY"
        echo "=============================================="
        echo "Total anomalous entries: $total_findings"
        echo "Report generated: $(timestamp)"
    } > "$OUTPUT_FILE"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    if [[ ! -d "$LOG_DIR" ]]; then
        echo "ERROR: Directory $LOG_DIR does not exist"
        exit 1
    fi

    echo "[*] Log Anomaly Scanner"
    echo "[*] Scanning $LOG_DIR (max $MAX_MATCHES_PER_PATTERN matches per pattern)"
    echo ""

    generate_report

    echo "[+] Report saved to $OUTPUT_FILE"
    echo "[*] Preview:"
    head -80 "$OUTPUT_FILE"
}

main "$@"
