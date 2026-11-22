#!/usr/bin/env python3
"""HTTP Header Security Checker - Audits security headers."""

import urllib.request
import sys

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy',
]

def check(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as r:
        headers = dict(r.headers)
    print(f"Checking: {url}\n")
    for h in SECURITY_HEADERS:
        val = headers.get(h, 'MISSING')
        status = '[+]' if val != 'MISSING' else '[-]'
        print(f"{status} {h}: {val}")

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    check(url)

if __name__ == '__main__':
    main()
