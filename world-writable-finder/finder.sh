#!/bin/bash
# World-Writable File Finder
# Finds files/directories with overly permissive permissions

DIR="${1:-/}"
EXCLUDE="${2:-/proc:/sys:/dev}"

echo "[*] World-Writable File Finder"
echo "[*] Scanning $DIR (excluding $EXCLUDE)"
echo ""

find "$DIR" -type f -perm -0002 2>/dev/null | while read file; do
    # Skip excluded paths
    echo "$file" | grep -qE "$(echo $EXCLUDE | tr ':' '|')" && continue
    echo "[!] $file"
    ls -la "$file" 2>/dev/null
done

echo ""
echo "[*] World-writable directories:"
find "$DIR" -type d -perm -0002 2>/dev/null | while read dir; do
    echo "$dir" | grep -qE "$(echo $EXCLUDE | tr ':' '|')" && continue
    echo "[!] $dir"
done

echo ""
echo "[+] Scan complete"
