#!/usr/bin/env python3
"""WiFi Deauth Detector - Detects deauth frames. Requires Scapy and monitor mode."""

try:
    from scapy.all import sniff, Dot11, Dot11Deauth
except ImportError:
    print("Install: pip install scapy")
    exit(1)

def handler(pkt):
    if pkt.haslayer(Dot11Deauth):
        print(f"[DEAUTH] {pkt[Dot11].addr2} -> {pkt[Dot11].addr1}")

if __name__ == '__main__':
    print("[*] WiFi Deauth Detector - Put interface in monitor mode")
    print("[*] Example: iwconfig wlan0 mode monitor")
    sniff(iface=None, prn=handler, store=0)
