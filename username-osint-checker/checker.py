#!/usr/bin/env python3
"""Username OSINT Checker - Checks username availability across platforms."""

import urllib.request
import sys

SITES = [
    ("GitHub", "https://github.com/{}"),
    ("Twitter", "https://twitter.com/{}"),
    ("Instagram", "https://www.instagram.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
]

def check(username):
    for name, url in SITES:
        u = url.format(username)
        try:
            req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
            r = urllib.request.urlopen(req, timeout=5)
            print(f"[EXISTS] {name}: {u}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"[FREE]   {name}: {u}")
            else:
                print(f"[?] {name}: {e.code}")
        except Exception as e:
            print(f"[ERROR] {name}: {e}")

def main():
    user = sys.argv[1] if len(sys.argv) > 1 else input("Username: ")
    check(user)

if __name__ == '__main__':
    main()
