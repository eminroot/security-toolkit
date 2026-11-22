#!/usr/bin/env python3
"""
Log File Analyzer with Pattern Detection
Analyzes log files with configurable patterns, time windows,
IP extraction, and export to JSON/CSV.
"""

import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import argparse

# (pattern, category, severity 1-5)
PATTERNS = [
    (r"Failed password for", "FAILED_LOGIN", 4),
    (r"Invalid user", "INVALID_USER", 4),
    (r"Accepted (password|publickey)", "SUCCESS_LOGIN", 2),
    (r"error|Error|ERROR", "ERROR", 2),
    (r"denied|Denied", "DENIED", 3),
    (r"refused|Refused", "REFUSED", 3),
    (r"attack|Attack", "ATTACK", 5),
    (r"Connection from", "CONNECTION", 1),
    (r"session opened", "SESSION_OPEN", 2),
    (r"session closed", "SESSION_CLOSE", 1),
    (r"authentication failure", "AUTH_FAILURE", 4),
    (r"BREAK-IN", "INTRUSION", 5),
    (r"Possible break-in", "INTRUSION", 5),
]


def extract_ip(line: str) -> Optional[str]:
    """Extract first IP from line."""
    match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
    return match.group(1) if match else None


def analyze_file(
    path: Path,
    patterns: List[tuple],
) -> Dict:
    """Analyze log file and return stats."""
    counts = Counter()
    by_ip = defaultdict(lambda: Counter())
    examples = defaultdict(list)

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            for pattern, category, _ in patterns:
                if re.search(pattern, line):
                    counts[category] += 1
                    ip = extract_ip(line)
                    if ip:
                        by_ip[ip][category] += 1
                    if len(examples[category]) < 3:
                        examples[category].append(line.strip()[:120])
                    break

    return {
        "file": str(path),
        "counts": dict(counts),
        "total_events": sum(counts.values()),
        "top_ips": dict(
            sorted(
                ((ip, sum(c.values())) for ip, c in by_ip.items()),
                key=lambda x: -x[1],
            )[:10]
        ),
        "examples": {k: v for k, v in examples.items()},
    }


def analyze_directory(
    path: Path,
    pattern: str = "*.log",
    recursive: bool = False,
) -> Dict:
    """Analyze all matching log files."""
    glob = path.rglob if recursive else path.glob
    results = []
    total_counts = Counter()

    for f in glob(pattern):
        if f.is_file():
            try:
                data = analyze_file(f, PATTERNS)
                results.append(data)
                total_counts.update(data["counts"])
            except Exception as e:
                print(f"Warning: {f}: {e}", file=sys.stderr)

    return {
        "files_analyzed": len(results),
        "total_counts": dict(total_counts),
        "by_file": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Log file analyzer with pattern detection")
    parser.add_argument("path", nargs="?", default="/var/log/auth.log")
    parser.add_argument("-d", "--directory", action="store_true", help="Analyze directory")
    parser.add_argument("-r", "--recursive", action="store_true")
    parser.add_argument("-o", "--output", choices=["text", "json"])
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    path = Path(args.path)

    if not path.exists():
        print(f"Error: Path not found: {path}")
        sys.exit(1)

    if args.directory or path.is_dir():
        data = analyze_directory(path, recursive=args.recursive)
        print("=== Log Analysis (Directory) ===")
        print(f"Files analyzed: {data['files_analyzed']}")
        print("\nTotal events by category:")
        for cat, count in data["total_counts"].most_common():
            print(f"  {cat}: {count}")
    else:
        data = analyze_file(path, PATTERNS)
        print("=== Log Analysis ===")
        print(f"File: {data['file']}")
        print(f"Total events: {data['total_events']}")
        print("\nBy category:")
        for cat, count in sorted(data["counts"].items(), key=lambda x: -x[1]):
            print(f"  {cat}: {count}")
        if data["top_ips"]:
            print("\nTop IPs:")
            for ip, count in list(data["top_ips"].items())[:10]:
                print(f"  {ip}: {count}")
        if args.verbose and data["examples"]:
            print("\nSample lines:")
            for cat, lines in data["examples"].items():
                for line in lines[:1]:
                    print(f"  [{cat}] {line[:80]}...")

    if args.output == "json":
        import json
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
