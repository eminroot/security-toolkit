#!/bin/bash
# Cron Job Security Auditor
# Audits crontab entries for security issues

echo "=== Cron Security Audit ==="
echo "Date: $(date)"
echo ""

echo "--- User Crontabs ---"
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^#" | while read line; do
        [ -n "$line" ] && echo "[$user] $line"
    done
done

echo ""
echo "--- System Crontabs ---"
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.daily/ 2>/dev/null

echo ""
echo "--- Suspicious Patterns ---"
grep -r "wget\|curl.*\|\|chmod 777\|/tmp/\|/dev/shm" /etc/cron* 2>/dev/null || echo "None found"
grep -r "base64" /etc/cron* 2>/dev/null || echo "None found"
