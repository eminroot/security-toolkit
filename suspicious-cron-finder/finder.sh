#!/bin/bash
# Suspicious Cron Task Finder
# Finds cron jobs with suspicious patterns

echo "[*] Suspicious Cron Task Finder"
echo ""

SUSPICIOUS=(
    "wget.*-O-.*\|\|"
    "curl.*\|\|"
    "chmod 777"
    "chmod \+s"
    "base64.*decode"
    "/tmp/.*\.sh"
    "/dev/shm"
    "nc -"
    "ncat"
    "python.*-c"
    "perl.*-e"
    "eval"
    "mkfifo"
)

for pattern in "${SUSPICIOUS[@]}"; do
    echo "--- Pattern: $pattern ---"
    grep -r "$pattern" /etc/cron* /var/spool/cron* 2>/dev/null || true
done

echo ""
echo "--- All cron entries with URL fetches ---"
grep -rE "wget|curl|fetch" /etc/cron* /var/spool/cron* 2>/dev/null || true

echo ""
echo "--- Writable cron directories ---"
ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null
