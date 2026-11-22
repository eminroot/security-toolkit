#!/bin/bash
# Reverse Shell Detector
# Scans processes and network connections for reverse shell indicators

echo "[*] Reverse Shell Detector"
echo ""

# Suspicious process patterns
PATTERNS=(
    "bash -i"
    "/bin/bash -i"
    "sh -i"
    "nc -e"
    "ncat.*-e"
    "python.*-c.*socket"
    "perl.*socket"
    "ruby.*socket"
    "php.*fsockopen"
    "/dev/tcp/"
    "mkfifo"
)

echo "--- Checking process command lines ---"
for pattern in "${PATTERNS[@]}"; do
    ps aux 2>/dev/null | grep -E "$pattern" | grep -v grep
done

echo ""
echo "--- Suspicious network connections (outbound to high ports) ---"
ss -tnp 2>/dev/null | grep ESTAB | awk '$5 !~ /:(22|80|443|53)\s/ {print}'
netstat -tnp 2>/dev/null | grep ESTABLISHED | awk '$5 !~ /:(22|80|443|53)$/ {print}'

echo ""
echo "--- Processes with /dev/tcp in cmdline ---"
for pid in $(pgrep -f "bash\|sh"); do
    grep -l "dev/tcp" /proc/$pid/cmdline 2>/dev/null && echo "PID $pid"
done

echo ""
echo "[+] Scan complete"
