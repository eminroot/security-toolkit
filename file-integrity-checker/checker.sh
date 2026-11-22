#!/bin/bash
#===============================================================================
# File Integrity Checker (Hash-based)
# Creates baseline hashes, verifies integrity, supports exclusion patterns,
# multiple algorithms, and diff reporting.
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
ALGORITHM="${ALGORITHM:-sha256}"
EXCLUDE_PATTERNS=(
    "*.log" "*.tmp" "*~" ".git/*" "*.swp" "/proc/*" "/sys/*" "/dev/*"
)

#-------------------------------------------------------------------------------
# Functions
#-------------------------------------------------------------------------------
usage() {
    echo "Usage: $0 create [baseline] [dir]     - Create baseline
       $0 verify [baseline]           - Verify against baseline
       $0 diff [baseline] [dir]      - Show changes
  baseline  - Output file (default: ./baseline.txt)
  dir       - Directory to scan (default: .)
  Algorithm: sha256, sha512, md5 (set ALGORITHM env)"
}

get_hash_cmd() {
    case "$ALGORITHM" in
        sha256) echo "sha256sum" ;;
        sha512) echo "sha512sum" ;;
        md5)    echo "md5sum" ;;
        *)      echo "sha256sum" ;;
    esac
}

build_find_excludes() {
    local excl=""
    for p in "${EXCLUDE_PATTERNS[@]}"; do
        excl="$excl -path '$p' -prune -o"
    done
    echo "$excl"
}

create_baseline() {
    local baseline="$1"
    local dir="$2"
    local hash_cmd
    hash_cmd=$(get_hash_cmd)

    echo "[*] Creating baseline: $baseline (alg: $ALGORITHM)"
    echo "# File Integrity Baseline - $(date -Iseconds) - $ALGORITHM" > "$baseline"
    echo "# Directory: $dir" >> "$baseline"

    find "$dir" -type f \( -path '*/.git/*' -o -path '*/node_modules/*' -o -name '*.log' -o -name '*.tmp' \) -prune -o -type f -print 2>/dev/null | while read -r file; do
        [[ -f "$file" ]] && $hash_cmd "$file" 2>/dev/null
    done >> "$baseline"

    local count
    count=$(grep -c -v '^#' "$baseline" 2>/dev/null || echo 0)
    echo "[+] Baseline created: $count files"
}

verify_integrity() {
    local baseline="$1"
    local hash_cmd
    hash_cmd=$(get_hash_cmd)
    local modified=0 missing=0 added=0

    echo "[*] Verifying against $baseline"

    while read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue

        local hash file
        hash=$(echo "$line" | awk '{print $1}')
        file=$(echo "$line" | cut -d' ' -f3-)
        [[ -z "$file" ]] && file=$(echo "$line" | awk '{print $2}')

        if [[ ! -f "$file" ]]; then
            echo "[MISSING] $file"
            (( missing++ )) || true
            continue
        fi

        local current
        current=$($hash_cmd "$file" 2>/dev/null | awk '{print $1}')
        if [[ "$current" != "$hash" ]]; then
            echo "[MODIFIED] $file"
            (( modified++ )) || true
        fi
    done < "$baseline"

    echo ""
    echo "[+] Verification complete: $modified modified, $missing missing"
}

diff_baseline() {
    local baseline="$1"
    local dir="${2:-.}"
    local temp_base
    temp_base=$(mktemp)
    hash_cmd=$(get_hash_cmd)
    find "$dir" -type f \( -path '*/.git/*' -o -path '*/node_modules/*' \) -prune -o -type f -print 2>/dev/null | while read -r file; do
        [[ -f "$file" ]] && $hash_cmd "$file" 2>/dev/null
    done | grep -v '^#' > "$temp_base"
    echo "[*] Differences:"
    diff <(grep -v '^#' "$baseline" | sort) <(sort "$temp_base") 2>/dev/null || true
    rm -f "$temp_base"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    case "${1:-}" in
        create)
            BASELINE="${2:-./baseline.txt}"
            DIR="${3:-.}"
            create_baseline "$BASELINE" "$DIR"
            ;;
        verify)
            BASELINE="${2:-./baseline.txt}"
            [[ ! -f "$BASELINE" ]] && { echo "Baseline not found: $BASELINE"; exit 1; }
            verify_integrity "$BASELINE"
            ;;
        diff)
            BASELINE="${2:-./baseline.txt}"
            DIR="${3:-.}"
            diff_baseline "$BASELINE" "$DIR"
            ;;
        -h|--help|"")
            usage
            ;;
        *)
            # Legacy: just create
            create_baseline "${1:-./baseline.txt}" "${2:-.}"
            ;;
    esac
}

main "$@"
