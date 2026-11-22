#!/usr/bin/env python3
"""Subdomain Enumerator - Discovers subdomains via common wordlist."""

import socket
import argparse

COMMON_SUBS = ['www','mail','ftp','localhost','webmail','smtp','pop','ns1','webdisk','ns2','cpanel','whm','autodiscover','autoconfig','m','imap','test','ns','blog','pop3','dev','email','news','vpn','admin','shop','proxy','dns','api','cdn','storage','beta','mx','cloud','secure','staging','portal']

def check_sub(domain, sub, timeout=2):
    host = f"{sub}.{domain}"
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False

def main():
    p = argparse.ArgumentParser()
    p.add_argument('domain')
    p.add_argument('-w', '--wordlist', default=None)
    args = p.parse_args()
    wordlist = COMMON_SUBS
    if args.wordlist:
        wordlist = open(args.wordlist).read().splitlines()
    print(f"[*] Enumerating subdomains of {args.domain}")
    for sub in wordlist:
        if check_sub(args.domain, sub):
            print(f"[+] {sub}.{args.domain}")

if __name__ == '__main__':
    main()
