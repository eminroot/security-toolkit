#!/bin/bash
# Weak Permission Finder (chmod issues)
# Finds files with insecure permissions

DIR="${1:-/}"
OUTPUT="${2:-/tmp/weak_permissions.txt}"

echo "[*] Weak Permission Finder"
echo "[*] Scanning $DIR"
echo "" > "$OUTPUT"

# World-readable sensitive files
echo "=== World-readable config/sensitive files ===" >> "$OUTPUT"
find "$DIR" -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.key" -o -path "*/.ssh/*" \) \
    -perm -0004 2>/dev/null | head -50 >> "$OUTPUT"

# World-writable
echo "" >> "$OUTPUT"
echo "=== World-writable files ===" >> "$OUTPUT"
find "$DIR" -type f -perm -0002 2>/dev/null | grep -v "/proc\|/sys" | head -50 >> "$OUTPUT"

# Directories with exec for all (risky)
echo "" >> "$OUTPUT"
echo "=== Directories mode 777 ===" >> "$OUTPUT"
find "$DIR" -type d -perm 0777 2>/dev/null | grep -v "/proc\|/sys\|/tmp" >> "$OUTPUT"

# Scripts in writable locations
echo "" >> "$OUTPUT"
echo "=== Executables in /tmp or /var/tmp ===" >> "$OUTPUT"
find /tmp /var/tmp -type f -executable 2>/dev/null >> "$OUTPUT"

echo "[+] Report: $OUTPUT"
cat "$OUTPUT"
