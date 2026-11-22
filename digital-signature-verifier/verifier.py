#!/usr/bin/env python3
"""Digital Signature Verification Tool - Verifies files against signatures."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import argparse

def verify_file(filepath, sigpath, pubkeypath):
    from cryptography.hazmat.backends import default_backend
    with open(pubkeypath, 'rb') as f:
        pubkey = serialization.load_pem_public_key(f.read(), backend=default_backend())
    with open(filepath, 'rb') as f:
        data = f.read()
    with open(sigpath, 'rb') as f:
        sig = f.read()
    try:
        pubkey.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        print("[+] Signature valid")
    except InvalidSignature:
        print("[-] Signature invalid")

def main():
    p = argparse.ArgumentParser()
    p.add_argument('file')
    p.add_argument('-s', '--signature')
    p.add_argument('-k', '--public-key')
    args = p.parse_args()
    verify_file(args.file, args.signature, args.public_key)

if __name__ == '__main__':
    main()
