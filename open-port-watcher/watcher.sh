#!/bin/bash
# Open Port Watcher with Alerts
# Monitors for changes in listening ports

BASELINE="/tmp/open_ports_baseline.txt"
CURRENT="/tmp/open_ports_current.txt"
ALERT_SCRIPT="${1:-/bin/echo}"

get_ports() {
    ss -tuln 2>/dev/null | grep LISTEN | sort || netstat -tuln 2>/dev/null | grep LISTEN | sort
}

echo "[*] Open Port Watcher"
echo "[*] Creating baseline..."

get_ports > "$BASELINE"

echo "[*] Monitoring for port changes (Ctrl+C to stop)"
while true; do
    sleep 60
    get_ports > "$CURRENT"
    
    added=$(diff "$BASELINE" "$CURRENT" | grep "^>" | grep -v ">" | wc -l)
    removed=$(diff "$BASELINE" "$CURRENT" | grep "^<" | grep -v "<" | wc -l)
    
    if [ "$added" -gt 0 ] || [ "$removed" -gt 0 ]; then
        echo "[ALERT] Port changes detected at $(date)"
        diff "$BASELINE" "$CURRENT"
        cp "$CURRENT" "$BASELINE"
        $ALERT_SCRIPT "Open port change detected" 2>/dev/null
    fi
done
