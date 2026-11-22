#!/bin/bash
#===============================================================================
# Automated Nmap Report Generator
# Runs comprehensive Nmap scans with multiple scan types, output formats,
# and integration with vulnerability scripts.
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
TARGET="${1:-127.0.0.1}"
OUTPUT_DIR="${2:-./nmap_reports}"
SCAN_LEVEL="${SCAN_LEVEL:-2}"  # 1=quick, 2=standard, 3=comprehensive
FORMATS="${FORMATS:-txt}"      # txt,xml,json (comma-sep)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_BASE="$OUTPUT_DIR/nmap_${TARGET//[\/:.]/_}_${TIMESTAMP}"

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
usage() {
    echo "Usage: $0 <target> [output_dir] [options]
  target     - IP, hostname, or CIDR
  output_dir - Report directory (default: ./nmap_reports)
  Set SCAN_LEVEL=1|2|3, FORMATS=txt,xml,json"
}

run_nmap() {
    local args="$1"
    local out="$2"
    nmap $args -oN "${out}.txt" 2>/dev/null || echo "nmap failed: $args"
    [[ "$FORMATS" == *xml* ]] && nmap $args -oX "${out}.xml" 2>/dev/null
    [[ "$FORMATS" == *json* ]] && nmap $args -oX - | xsltproc /usr/share/nmap/nmap.xsl - 2>/dev/null > "${out}.json" || true
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        usage
        exit 0
    fi

    if ! command -v nmap &>/dev/null; then
        echo "Error: nmap required"
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    echo "[*] Nmap Report Generator"
    echo "[*] Target: $TARGET | Level: $SCAN_LEVEL | Dir: $OUTPUT_DIR"
    echo ""

    {
        echo "=============================================="
        echo "  NMAP SCAN REPORT"
        echo "=============================================="
        echo "Target: $TARGET"
        echo "Date: $(date -Iseconds)"
        echo "Host: $(hostname)"
        echo "=============================================="
        echo ""

        echo "--- Host Discovery (Ping Scan) ---"
        nmap -sn "$TARGET" 2>/dev/null || echo "Ping scan failed"
        echo ""

        case "$SCAN_LEVEL" in
            1)
                echo "--- Quick Port Scan (Top 100) ---"
                nmap -sT -F "$TARGET" 2>/dev/null
                ;;
            2)
                echo "--- Standard Scan (Top 1000 + Version) ---"
                nmap -sV -sC -T4 -p 1-1000 "$TARGET" 2>/dev/null
                echo ""
                echo "--- OS Detection ---"
                nmap -O --osscan-guess "$TARGET" 2>/dev/null | head -30
                ;;
            3)
                echo "--- Full Port Scan ---"
                nmap -sV -sC -T4 -p- "$TARGET" 2>/dev/null
                echo ""
                echo "--- OS Detection ---"
                nmap -O --osscan-guess "$TARGET" 2>/dev/null
                echo ""
                echo "--- Vulnerability Scripts ---"
                nmap --script vuln -p 21,22,80,443,3306 "$TARGET" 2>/dev/null | head -100
                ;;
            *)
                nmap -sV -sC -p 1-1000 "$TARGET" 2>/dev/null
                ;;
        esac

        echo ""
        echo "=============================================="
        echo "  COMMON SERVICES"
        echo "=============================================="
        nmap -sV -p 21,22,23,25,53,80,110,143,443,445,993,995,3306,5432,5900,8080,8443 "$TARGET" 2>/dev/null

        echo ""
        echo "=============================================="
        echo "Report generated: $(date -Iseconds)"
    } | tee "${REPORT_BASE}.txt"

    echo ""
    echo "[+] Report saved: ${REPORT_BASE}.txt"
}

main "$@"
