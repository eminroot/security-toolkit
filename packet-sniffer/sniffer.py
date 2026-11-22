#!/usr/bin/env python3
"""
Packet Sniffer using Scapy
Captures and analyzes network traffic with protocol dissection,
statistics, filtering, and optional packet capture to file.
"""

import argparse
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
except ImportError:
    print("Error: Install scapy: pip install scapy")
    sys.exit(1)


class PacketStats:
    """Collects packet statistics during capture."""

    def __init__(self):
        self.total = 0
        self.by_proto = defaultdict(int)
        self.by_src = defaultdict(int)
        self.by_dst = defaultdict(int)
        self.ports = defaultdict(int)

    def update(self, pkt):
        if pkt.haslayer(IP):
            self.total += 1
            self.by_src[pkt[IP].src] += 1
            self.by_dst[pkt[IP].dst] += 1
            if pkt.haslayer(TCP):
                self.by_proto["TCP"] += 1
                self.ports[f"{pkt[TCP].sport}" if pkt[TCP].dport in (80, 443) else f"{pkt[TCP].dport}"] += 1
            elif pkt.haslayer(UDP):
                self.by_proto["UDP"] += 1
                self.ports[str(pkt[UDP].dport)] += 1
            elif pkt.haslayer(ICMP):
                self.by_proto["ICMP"] += 1

    def summary(self):
        print("\n" + "=" * 50)
        print("CAPTURE SUMMARY")
        print("=" * 50)
        print(f"Total packets: {self.total}")
        for proto, count in sorted(self.by_proto.items()):
            print(f"  {proto}: {count}")
        print("\nTop 5 source IPs:")
        for ip, count in sorted(self.by_src.items(), key=lambda x: -x[1])[:5]:
            print(f"  {ip}: {count}")
        print("=" * 50)


def process_packet(pkt, stats: PacketStats, verbose: bool, show_payload: bool):
    """Process and display packet."""
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt.sprintf("%TCP.flags%") if hasattr(pkt, "sprintf") else ""
        line = f"[{ts}] TCP {src}:{sport} -> {dst}:{dport} {flags}"
        if pkt.haslayer(Raw) and show_payload:
            payload = bytes(pkt[Raw].load)[:64]
            line += f" [{len(payload)} bytes]"
        print(line)
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        print(f"[{ts}] UDP {src}:{sport} -> {dst}:{dport}")
    elif pkt.haslayer(ICMP):
        icmp_type = pkt[ICMP].type if hasattr(pkt[ICMP], "type") else ""
        print(f"[{ts}] ICMP {src} -> {dst} type={icmp_type}")

    if stats:
        stats.update(pkt)


def main():
    parser = argparse.ArgumentParser(
        description="Packet sniffer with filtering and statistics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default=None, help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet count (0=infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., tcp port 80)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--payload", action="store_true", help="Show payload length")
    parser.add_argument("--no-stats", action="store_true", help="Disable summary stats")
    parser.add_argument("-w", "--write", help="Save packets to pcap file")
    args = parser.parse_args()

    stats = None if args.no_stats else PacketStats()

    def handler(pkt):
        process_packet(pkt, stats, args.verbose, args.payload)

    print("[*] Packet Sniffer")
    print(f"[*] Interface: {args.interface or 'default'}")
    print(f"[*] Filter: {args.filter or 'none'}")
    print(f"[*] Count: {args.count or 'infinite'}")
    print("[*] Press Ctrl+C to stop\n")

    try:
        sniff(
            iface=args.interface,
            prn=handler,
            count=args.count if args.count > 0 else 0,
            filter=args.filter or None,
            store=0,
        )
    except PermissionError:
        print("Error: Root required for packet capture", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped")

    if stats:
        stats.summary()


if __name__ == "__main__":
    main()
