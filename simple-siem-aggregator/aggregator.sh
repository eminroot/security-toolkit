#!/bin/bash
# Simple SIEM-style Log Aggregator
# Aggregates logs from multiple sources with pattern detection

LOG_DIR="${1:-/var/log}"
OUTPUT="${2:-/tmp/siem_report.txt}"
PATTERNS=("Failed password" "Invalid user" "Accepted" "error" "denied" "refused" "attack" "intrusion")

echo "=== SIEM Log Aggregation ==="
echo "Started: $(date)" > "$OUTPUT"
echo "" >> "$OUTPUT"

for pattern in "${PATTERNS[@]}"; do
    echo "--- [$pattern] ---" >> "$OUTPUT"
    grep -r -h "$pattern" "$LOG_DIR" 2>/dev/null | tail -50 >> "$OUTPUT"
    echo "" >> "$OUTPUT"
done

# Aggregate by source
echo "--- Events by file ---" >> "$OUTPUT"
grep -r -l "Failed\|Invalid\|denied" "$LOG_DIR" 2>/dev/null | while read f; do
    count=$(grep -c "Failed\|Invalid\|denied" "$f" 2>/dev/null)
    echo "$count $f" >> "$OUTPUT"
done

echo "[+] SIEM report: $OUTPUT"
wc -l "$OUTPUT"
