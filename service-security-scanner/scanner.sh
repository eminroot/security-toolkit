#!/bin/bash
# Service Status Security Scanner
# Checks critical services and their security posture

echo "=== Service Security Scanner ==="
echo ""

SERVICES=("sshd" "fail2ban" "ufw" "firewalld" "apache2" "nginx" "mysql" "postgresql")

for svc in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${svc}"; then
        status=$(systemctl is-active "$svc" 2>/dev/null)
        enabled=$(systemctl is-enabled "$svc" 2>/dev/null)
        echo "[$svc] Active: $status | Enabled: $enabled"
    fi
done

echo ""
echo "--- Listening services ---"
ss -tlnp 2>/dev/null | awk 'NR>1 {print $4, $6}'

echo ""
echo "--- Potentially dangerous services ---"
systemctl list-units --type=service --state=running 2>/dev/null | grep -iE "telnet|ftp|rsh|rlogin" || echo "None found"
