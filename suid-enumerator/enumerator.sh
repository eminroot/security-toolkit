#!/bin/bash
# SUID File Enumerator
# Finds files with SUID bit set (potential privilege escalation)

DIR="${1:-/}"
OUTPUT="${2:-/tmp/suid_files.txt}"

echo "[*] SUID File Enumerator"
echo "[*] Scanning $DIR"
echo ""

find "$DIR" -perm -4000 -type f 2>/dev/null > "$OUTPUT"

echo "=== SUID Files Found ==="
while read file; do
    perms=$(ls -la "$file" 2>/dev/null | awk '{print $1}')
    owner=$(ls -la "$file" 2>/dev/null | awk '{print $3}')
    echo "$file (owner: $owner)"
done < "$OUTPUT"

echo ""
echo "[+] Results saved to $OUTPUT ($(wc -l < "$OUTPUT") files)"
echo ""
echo "Known risky SUID binaries to review:"
grep -E "nmap|vim|find|bash|python|perl" "$OUTPUT" 2>/dev/null || echo "None of common risky ones found"
