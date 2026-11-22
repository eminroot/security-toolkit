#!/bin/bash
# Password Strength CLI Checker
# Checks password against common strength criteria

password="${1:-}"

if [ -z "$password" ]; then
    echo "Usage: $0 <password>"
    echo "Or pipe: echo 'password' | $0"
    exit 1
fi

score=0
length=${#password}

echo "=== Password Strength Check ==="
echo "Length: $length"
echo ""

# Length checks
[ $length -ge 8 ] && score=$((score+1)) && echo "[+] 8+ characters"
[ $length -ge 12 ] && score=$((score+1)) && echo "[+] 12+ characters"
[ $length -ge 16 ] && score=$((score+1)) && echo "[+] 16+ characters"

# Character variety
[[ "$password" =~ [a-z] ]] && [[ "$password" =~ [A-Z] ]] && score=$((score+1)) && echo "[+] Upper + Lower case"
[[ "$password" =~ [0-9] ]] && score=$((score+1)) && echo "[+] Contains numbers"
[[ "$password" =~ [^a-zA-Z0-9] ]] && score=$((score+1)) && echo "[+] Contains special chars"

# Common patterns
[[ "$password" =~ (123|abc|qwe|password|admin) ]] && score=$((score-2)) && echo "[-] Contains common patterns"

echo ""
case $score in
    0-2) echo "Strength: WEAK";;
    3-4) echo "Strength: FAIR";;
    5-6) echo "Strength: GOOD";;
    *) echo "Strength: STRONG";;
esac
