#!/bin/bash
# Active Connection Monitor
# Monitors and displays active network connections

REFRESH="${1:-5}"

echo "[*] Active Connection Monitor (refresh every ${REFRESH}s)"
echo ""

while true; do
    clear
    echo "=== Active Connections - $(date) ==="
    echo ""
    echo "--- ESTABLISHED (ss) ---"
    ss -tnp state established 2>/dev/null | head -30
    echo ""
    echo "--- LISTEN ---"
    ss -tuln 2>/dev/null
    echo ""
    echo "--- Top connections by remote IP ---"
    ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
    sleep "$REFRESH"
done
