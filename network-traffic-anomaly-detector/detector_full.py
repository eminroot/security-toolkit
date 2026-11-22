#!/usr/bin/env python3
"""Network Traffic Anomaly Detector - Full Scapy version."""

from scapy.all import sniff, IP, TCP
from collections import defaultdict

conn_counts = defaultdict(int)
threshold = 100

def process(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        conn_counts[src] += 1
        if conn_counts[src] == threshold:
            print(f"[ANOMALY] {src} exceeded {threshold} connections")

if __name__ == '__main__':
    print("[*] Sniffing - anomaly threshold:", threshold)
    sniff(prn=process, store=0)
