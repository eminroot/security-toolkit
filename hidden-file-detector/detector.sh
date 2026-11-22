#!/bin/bash
# Hidden File Detector
# Finds potentially suspicious hidden files

DIR="${1:-/home}"
OUTPUT="${2:-/tmp/hidden_files.txt}"

echo "[*] Hidden File Detector"
echo "[*] Scanning $DIR"
echo ""

# Files/dirs starting with .
find "$DIR" -name ".*" -type f 2>/dev/null | while read file; do
    # Exclude common safe dotfiles
    basename "$file" | grep -qE "^\\.(bashrc|profile|gitignore|ssh)$" && continue
    echo "$file"
    ls -la "$file" 2>/dev/null
done > "$OUTPUT"

# Files in /tmp, /var/tmp with dot prefix
find /tmp /var/tmp -name ".*" 2>/dev/null >> "$OUTPUT"

# Recently modified hidden files (last 24h)
find "$DIR" -name ".*" -mtime -1 2>/dev/null >> "$OUTPUT"

echo "[+] Results: $OUTPUT"
sort -u "$OUTPUT" | head -50
