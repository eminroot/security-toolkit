#!/bin/bash
# Simple Honeypot (Fake Login)
# Listens on a port and logs connection attempts - simulates vulnerable service

PORT="${1:-2222}"
LOG_FILE="${2:-/tmp/honeypot.log}"

echo "[*] Simple Honeypot - Port $PORT"
echo "[*] Logging to $LOG_FILE"
echo "[*] Waiting for connections (Ctrl+C to stop)"
echo ""

while true; do
    {
        echo "SSH-2.0-OpenSSH_7.4"
        sleep 2
        echo "Connection closed by remote host."
    } | nc -l -p "$PORT" 2>/dev/null &
    NC_PID=$!
    
    # Get connecting IP
    sleep 1
    CONN=$(ss -tn state established 2>/dev/null | grep ":$PORT" | awk '{print $5}')
    [ -n "$CONN" ] && echo "$(date): Connection from $CONN" >> "$LOG_FILE" && echo "[+] Logged: $CONN"
    
    wait $NC_PID 2>/dev/null
done
