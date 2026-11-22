#!/bin/bash
# SSH Configuration Hardening Checker
# Audits sshd_config for security best practices

CONFIG="${1:-/etc/ssh/sshd_config}"

echo "=== SSH Hardening Check ==="
echo "Config: $CONFIG"
echo ""

CHECKS=(
    "PermitRootLogin:no"
    "PasswordAuthentication:no"
    "PubkeyAuthentication:yes"
    "PermitEmptyPasswords:no"
    "X11Forwarding:no"
    "MaxAuthTries:3"
    "ClientAliveInterval:300"
    "AllowUsers"
    "Protocol:2"
)

for check in "${CHECKS[@]}"; do
    key="${check%%:*}"
    expected="${check#*:}"
    current=$(grep -i "^${key}" "$CONFIG" 2>/dev/null | tail -1)
    if [ -z "$current" ]; then
        echo "[MISSING] $key - Should be: $expected"
    else
        echo "[CHECK] $current"
    fi
done

echo ""
echo "--- Full sshd_config (security-relevant) ---"
grep -v "^#" "$CONFIG" 2>/dev/null | grep -v "^$"
