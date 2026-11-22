#!/usr/bin/env python3
"""
Mini Intrusion Detection System
Pattern-based network IDS with configurable rules, alerting,
and log output. Detects common attack payloads in traffic.
"""

import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import sniff, IP, TCP, Raw
except ImportError:
    print("Error: pip install scapy")
    sys.exit(1)


# Rule format: (pattern, severity, name)
# Severity: 1=info, 2=low, 3=medium, 4=high, 5=critical
RULES = [
    (rb"etc/passwd", 4, "Path disclosure"),
    (rb"/etc/shadow", 5, "Shadow file access"),
    (rb"/bin/bash", 4, "Shell reference"),
    (rb"rm\s+-rf", 3, "Destructive command"),
    (rb"wget\s+.*\|\s*(bash|sh)", 5, "Wget to shell"),
    (rb"curl\s+.*\|\s*(bash|sh)", 5, "Curl to shell"),
    (rb"<script", 4, "XSS payload"),
    (rb"javascript:", 3, "JavaScript protocol"),
    (rb"UNION\s+SELECT", 5, "SQL injection"),
    (rb"OR\s+1\s*=\s*1", 5, "SQL injection"),
    (rb"\.\./\.\./", 4, "Path traversal"),
    (rb"%00", 3, "Null byte injection"),
    (rb"cmd\.exe", 4, "Windows cmd"),
    (rb"powershell", 4, "PowerShell"),
    (rb"eval\s*\(", 4, "Eval function"),
    (rb"base64_decode", 4, "Base64 decode"),
    (rb"document\.cookie", 4, "Cookie theft"),
    (rb"<iframe", 3, "Iframe injection"),
]


class IDSEngine:
    def __init__(self, log_file=None, alert_threshold=3):
        self.log_file = Path(log_file) if log_file else None
        self.alert_threshold = alert_threshold
        self.alert_counts = defaultdict(int)
        self.alerts = []

    def _log_alert(self, src: str, dst: str, rule_name: str, severity: int, match: bytes):
        entry = {
            "time": datetime.now().isoformat(),
            "src": src,
            "dst": dst,
            "rule": rule_name,
            "severity": severity,
            "match": match[:100].decode("utf-8", errors="replace"),
        }
        self.alerts.append(entry)
        line = f"[{entry['time']}] ALERT [{rule_name}] {src} -> {dst} (sev={severity})\n"
        print(line.strip())
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(line)

    def analyze(self, pkt):
        if not pkt.haslayer(IP):
            return
        if not pkt.haslayer(Raw):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        payload = bytes(pkt[Raw].load)

        for pattern, severity, name in RULES:
            if re.search(pattern, payload, re.IGNORECASE):
                key = f"{src}:{name}"
                self.alert_counts[key] += 1
                self._log_alert(src, dst, name, severity, pattern)
                if self.alert_counts[key] >= self.alert_threshold:
                    print(f"  [!] Threshold exceeded: {key} ({self.alert_counts[key]} alerts)")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mini IDS - pattern-based intrusion detection")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-l", "--log", help="Alert log file")
    parser.add_argument("-t", "--threshold", type=int, default=5)
    parser.add_argument("-c", "--count", type=int, default=0)
    args = parser.parse_args()

    engine = IDSEngine(log_file=args.log, alert_threshold=args.threshold)

    print("[*] Mini IDS - Monitoring for suspicious payloads")
    print(f"[*] Rules loaded: {len(RULES)}")
    print("[*] Press Ctrl+C to stop\n")

    def handler(pkt):
        engine.analyze(pkt)

    try:
        sniff(
            iface=args.interface,
            prn=handler,
            count=args.count or 0,
            store=0,
        )
    except KeyboardInterrupt:
        print("\n[*] Stopped")
        print(f"Total alerts: {len(engine.alerts)}")


if __name__ == "__main__":
    main()
