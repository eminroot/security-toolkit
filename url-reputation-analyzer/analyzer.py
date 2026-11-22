#!/usr/bin/env python3
"""URL Reputation Analyzer - Checks URLs against blocklists."""

import urllib.request
import sys

BLACKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

def load_blocklist():
    try:
        with urllib.request.urlopen(BLACKLIST_URL, timeout=10) as r:
            return set(line.decode().strip().split()[-1] for line in r if not line.startswith(b'#') and line.strip())
    except:
        return set()

def check_url(url):
    from urllib.parse import urlparse
    domain = urlparse(url).netloc or url
    blocklist = load_blocklist()
    return domain in blocklist or any(d in domain for d in blocklist)

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input("URL: ")
    blocked = check_url(url)
    print(f"[{'BLOCKED' if blocked else 'OK'}] {url}")

if __name__ == '__main__':
    main()
