#!/bin/bash
# Local Network Device Scanner
# Discovers devices on the local network

NETWORK="${1:-192.168.1.0/24}"
TIMEOUT="${2:-1}"

echo "[*] Local Network Device Scanner"
echo "[*] Network: $NETWORK"
echo ""

# Extract base IP (e.g., 192.168.1)
BASE=$(echo "$NETWORK" | cut -d'/' -f1 | cut -d'.' -f1-3)

echo "IP Address       MAC Address           Hostname"
echo "----------------------------------------------"

for i in $(seq 1 254); do
    ip="$BASE.$i"
    (ping -c 1 -W "$TIMEOUT" "$ip" &>/dev/null) &
done
wait

for i in $(seq 1 254); do
    ip="$BASE.$i"
    if ping -c 1 -W "$TIMEOUT" "$ip" &>/dev/null; then
        mac=$(arp -n "$ip" 2>/dev/null | awk 'NR==2 {print $3}')
        host=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}')
        echo "$ip        ${mac:-N/A}    ${host:-}"
    fi
done

echo ""
echo "[+] Scan complete"
