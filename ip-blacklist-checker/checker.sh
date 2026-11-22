#!/bin/bash
# Suspicious IP Blacklist Checker
# Checks IPs against known threat intelligence lists

IP="${1:-}"
BLACKLIST_URL="${2:-https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt}"

if [ -z "$IP" ]; then
    echo "Usage: $0 <IP_address> [blacklist_url]"
    exit 1
fi

echo "[*] Checking $IP against blacklist"
echo ""

# Fetch blacklist (cache for repeated use)
CACHE="/tmp/ip_blacklist_$$.txt"
curl -s "$BLACKLIST_URL" 2>/dev/null | grep -v "^#" > "$CACHE" 2>/dev/null

if [ -f "$CACHE" ]; then
    if grep -q "^$IP$" "$CACHE" 2>/dev/null; then
        echo "[ALERT] $IP is in blacklist!"
    else
        echo "[OK] $IP not found in blacklist"
    fi
else
    echo "[!] Could not fetch blacklist. Check connectivity."
fi

rm -f "$CACHE"
echo ""
echo "[*] Done"
