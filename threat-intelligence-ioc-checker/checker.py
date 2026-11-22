#!/usr/bin/env python3
"""Threat Intelligence IOC Checker - Checks IPs/hashes against IOC feeds."""

import urllib.request
import sys

def fetch_iocs(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return set(line.decode().strip() for line in r if line and not line.startswith(b'#'))
    except:
        return set()

def main():
    # Sample feed - replace with real threat intel
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    iocs = fetch_iocs(url)
    target = sys.argv[1] if len(sys.argv) > 1 else input("IP or hash: ")
    if target in iocs or any(target in ioc for ioc in iocs):
        print(f"[ALERT] {target} found in IOC database")
    else:
        print(f"[OK] {target} not in database")

if __name__ == '__main__':
    main()
