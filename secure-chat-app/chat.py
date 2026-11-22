#!/usr/bin/env python3
"""Secure Chat App with Encryption - AES encrypted messaging."""

import socket
import threading
from cryptography.fernet import Fernet

def gen_key():
    return Fernet.generate_key()

def server(key, port=9999):
    s = socket.socket()
    s.bind(('0.0.0.0', port))
    s.listen(1)
    print(f"[*] Server on port {port}")
    c, addr = s.accept()
    f = Fernet(key)
    def recv():
        while True:
            data = c.recv(4096)
            if not data: break
            print("<<", f.decrypt(data).decode())
    def send():
        while True:
            msg = input()
            c.send(f.encrypt(msg.encode()))
    t1 = threading.Thread(target=recv)
    t2 = threading.Thread(target=send)
    t1.start()
    t2.start()

def client(key, host, port=9999):
    s = socket.socket()
    s.connect((host, port))
    f = Fernet(key)
    def recv():
        while True:
            data = s.recv(4096)
            if not data: break
            print("<<", f.decrypt(data).decode())
    def send():
        while True:
            msg = input()
            s.send(f.encrypt(msg.encode()))
    t1 = threading.Thread(target=recv)
    t2 = threading.Thread(target=send)
    t1.start()
    t2.start()

if __name__ == '__main__':
    import sys
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['server', 'client'])
    p.add_argument('host', nargs='?')
    p.add_argument('-k', '--key', help='Shared key (from server)')
    args = p.parse_args()
    key = args.key.encode() if args.key else gen_key()
    if not args.key:
        print("Share this key:", key.decode())
    if args.mode == 'server':
        server(key)
    else:
        client(key, args.host or '127.0.0.1')
