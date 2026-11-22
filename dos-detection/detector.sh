#!/bin/bash
# Basic DoS Detection via Connection Count
# Monitors connection counts per IP for potential DoS

THRESHOLD="${1:-100}"
CHECK_INTERVAL="${2:-10}"

echo "[*] DoS Detection - Threshold: $THRESHOLD connections per IP"
echo ""

while true; do
    # Count ESTABLISHED connections per remote IP
    CONN_COUNTS=$(ss -tn state established 2>/dev/null | \
        awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn)
    
    if [ -n "$CONN_COUNTS" ]; then
        echo "$CONN_COUNTS" | while read count ip; do
            if [ "$count" -ge "$THRESHOLD" ] 2>/dev/null; then
                echo "[ALERT] Possible DoS from $ip - $count connections"
                echo "$(date): $ip - $count connections" >> /tmp/dos_alerts.log
            fi
        done
    fi
    
    echo "[*] $(date) - Check complete"
    sleep "$CHECK_INTERVAL"
done
