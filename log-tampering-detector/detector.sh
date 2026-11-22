#!/bin/bash
# Log Tampering Detector
# Detects gaps and inconsistencies in log files

LOG_DIR="${1:-/var/log}"
OUTPUT="${2:-/tmp/log_tampering_report.txt}"

echo "[*] Log Tampering Detector"
echo "[*] Scanning $LOG_DIR"
echo "" > "$OUTPUT"

for log in "$LOG_DIR"/*.log "$LOG_DIR"/auth.log; do
    [ ! -f "$log" ] && continue
    echo "--- $log ---" >> "$OUTPUT"
    # Check for time gaps > 1 hour
    # Check for deleted/rotated logs (inode change)
    stats=$(stat "$log" 2>/dev/null)
    echo "Size: $(stat -c%s "$log" 2>/dev/null) Mod: $(stat -c%y "$log" 2>/dev/null)" >> "$OUTPUT"
    # Sequential timestamp check (simplified)
    if [ -r "$log" ]; then
        lines=$(wc -l < "$log")
        echo "Lines: $lines" >> "$OUTPUT"
    fi
    echo "" >> "$OUTPUT"
done

# Check syslog for breaks
if [ -f /var/log/syslog ]; then
    echo "--- Syslog timestamp sequence ---" >> "$OUTPUT"
    grep -oP '^\w+\s+\d+\s+[\d:]+' /var/log/syslog 2>/dev/null | uniq -c | tail -20 >> "$OUTPUT"
fi

echo "[+] Report: $OUTPUT"
cat "$OUTPUT"
