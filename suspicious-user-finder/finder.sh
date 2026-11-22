#!/bin/bash
# Suspicious User Account Finder
# Finds potentially compromised or suspicious user accounts

echo "=== Suspicious User Account Finder ==="
echo ""

echo "--- Users with UID 0 (root duplicates) ---"
awk -F: '$3==0 {print $1}' /etc/passwd

echo ""
echo "--- Users with no password ---"
awk -F: '($2=="") {print $1}' /etc/shadow 2>/dev/null || echo "Need root"

echo ""
echo "--- Users with shell access ---"
awk -F: '$7~/(bash|sh|zsh)$/ {print $1, $7}' /etc/passwd

echo ""
echo "--- Recently modified passwd ---"
stat /etc/passwd 2>/dev/null

echo ""
echo "--- Users with failed login count ---"
grep "Failed password" /var/log/auth.log 2>/dev/null | awk -F'for ' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "--- Locked accounts ---"
awk -F: '($2=="!") {print $1}' /etc/shadow 2>/dev/null

echo ""
echo "--- Users last logged in ---"
lastlog 2>/dev/null | grep -v "Never"
