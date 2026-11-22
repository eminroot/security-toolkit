#!/bin/bash
#===============================================================================
# Linux Security Audit Script
# Comprehensive security checklist with scoring, recommendations,
# and export options.
#===============================================================================

set -euo pipefail

OUTPUT="${OUTPUT:-}"
SCORE=0
MAX_SCORE=0

#-------------------------------------------------------------------------------
# Helpers
#-------------------------------------------------------------------------------
section() { echo ""; echo "=== $1 ==="; echo ""; }
pass() { echo "[PASS] $1"; (( SCORE += 1 )) || true; (( MAX_SCORE += 1 )) || true; }
fail() { echo "[FAIL] $1"; (( MAX_SCORE += 1 )) || true; }
warn() { echo "[WARN] $1"; }
info() { echo "[INFO] $1"; }

#-------------------------------------------------------------------------------
# Audit checks
#-------------------------------------------------------------------------------
audit_users() {
    section "1. Users & Groups"
    local roots
    roots=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    if [[ "$roots" == "root" ]]; then
        pass "Only root has UID 0"
    else
        fail "Multiple UID 0: $roots"
    fi
    local nopass
    nopass=$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null | wc -l)
    [[ "$nopass" -eq 0 ]] && pass "No empty passwords" || fail "Accounts with empty password"
}

audit_ports() {
    section "2. Open Ports"
    ss -tuln 2>/dev/null | grep LISTEN || netstat -tuln 2>/dev/null | grep LISTEN
    info "Review for unnecessary services"
}

audit_services() {
    section "3. Running Services"
    systemctl list-units --type=service --state=running 2>/dev/null | head -25
}

audit_suid() {
    section "4. SUID/SGID Files"
    local count
    count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
    info "SUID files: $count"
    find / -perm -4000 -type f 2>/dev/null | head -20
    grep -E "nmap|vim|find|bash|python|perl" <(find / -perm -4000 -type f 2>/dev/null) 2>/dev/null && fail "Risky SUID binaries found" || pass "No known risky SUID"
}

audit_world_writable() {
    section "5. World-Writable Files"
    local count
    count=$(find / -type f -perm -0002 2>/dev/null | grep -v -E "/proc|/sys" | wc -l)
    [[ "$count" -eq 0 ]] && pass "No world-writable files" || fail "World-writable: $count files"
}

audit_updates() {
    section "6. Package Updates"
    if command -v apt &>/dev/null; then
        apt list --upgradable 2>/dev/null | head -10
    elif command -v yum &>/dev/null; then
        yum list updates 2>/dev/null | head -10
    else
        info "No apt/yum found"
    fi
}

audit_ssh() {
    section "7. SSH Configuration"
    local root_login pass_auth
    root_login=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "PermitRootLogin yes")
    pass_auth=$(grep -E "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "PasswordAuthentication yes")
    [[ "$root_login" == *no* ]] && pass "Root login disabled" || fail "Root login enabled"
    [[ "$pass_auth" == *no* ]] && pass "Password auth disabled (keys only)" || warn "Password auth enabled"
}

audit_firewall() {
    section "8. Firewall"
    if iptables -L -n 2>/dev/null | head -5; then
        pass "iptables configured"
    elif ufw status 2>/dev/null | head -5; then
        pass "ufw configured"
    else
        fail "No firewall detected"
    fi
}

audit_fail2ban() {
    section "9. Fail2ban"
    if systemctl is-active fail2ban 2>/dev/null | grep -q active; then
        pass "Fail2ban active"
    else
        warn "Fail2ban not active"
    fi
}

audit_kernel() {
    section "10. Kernel"
    info "Version: $(uname -r)"
    [[ -r /proc/sys/kernel/randomize_va_space ]] && \
        [[ $(cat /proc/sys/kernel/randomize_va_space) -eq 2 ]] && \
        pass "ASLR enabled" || warn "ASLR may be disabled"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    echo "=============================================="
    echo "  LINUX SECURITY AUDIT"
    echo "=============================================="
    echo "Host: $(hostname)"
    echo "Date: $(date -Iseconds)"
    echo ""

    audit_users
    audit_ports
    audit_services
    audit_suid
    audit_world_writable
    audit_updates
    audit_ssh
    audit_firewall
    audit_fail2ban
    audit_kernel

    echo ""
    echo "=============================================="
    echo "  SUMMARY"
    echo "=============================================="
    echo "Score: $SCORE / $MAX_SCORE"
    echo "=============================================="
}

main | tee "${OUTPUT:-/dev/stdout}"
