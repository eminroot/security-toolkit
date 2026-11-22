#!/bin/bash
#===============================================================================
# Port Scanner using Netcat
# Scans target for open ports with configurable ranges, timeout,
# and optional service probing.
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
TARGET="${1:-127.0.0.1}"
PORTS="${2:-1-1000}"
TIMEOUT="${3:-1}"
OUTPUT="${4:-}"

# Common services for reporting
declare -A SERVICES=(
    [21]="FTP" [22]="SSH" [23]="Telnet" [25]="SMTP" [53]="DNS"
    [80]="HTTP" [110]="POP3" [143]="IMAP" [443]="HTTPS" [445]="SMB"
    [3306]="MySQL" [5432]="PostgreSQL" [8080]="HTTP-Alt"
)

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
usage() {
    echo "Usage: $0 <target> [ports] [timeout] [output_file]
  target   - Hostname or IP
  ports    - Range (1-1000) or list (22,80,443)
  timeout  - Connection timeout seconds
  output   - Optional file to save results"
}

scan_port() {
    local host="$1"
    local port="$2"
    local to="$3"
    if nc -z -w "$to" "$host" "$port" 2>/dev/null; then
        local svc="${SERVICES[$port]:-unknown}"
        echo "OPEN: $port ($svc)"
    fi
}

get_port_list() {
    local spec="$1"
    if [[ "$spec" == *-* ]]; then
        local start end
        start=$(echo "$spec" | cut -d'-' -f1)
        end=$(echo "$spec" | cut -d'-' -f2)
        seq "$start" "$end"
    else
        echo "$spec" | tr ',' ' '
    fi
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        usage
        exit 0
    fi

    if ! command -v nc &>/dev/null; then
        echo "Error: netcat (nc) required"
        exit 1
    fi

    echo "[*] Netcat Port Scanner"
    echo "[*] Target: $TARGET | Ports: $PORTS | Timeout: ${TIMEOUT}s"
    echo ""

    {
        for port in $(get_port_list "$PORTS"); do
            scan_port "$TARGET" "$port" "$TIMEOUT"
        done
    } | tee "${OUTPUT:-/dev/stdout}"

    echo ""
    echo "[*] Scan complete"
}

main "$@"
