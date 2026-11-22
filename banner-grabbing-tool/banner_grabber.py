#!/usr/bin/env python3
"""
Banner Grabbing Tool
Retrieves service banners with protocol-specific probes, timeout handling,
and structured output (JSON/text).
"""

import socket
import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional

# Protocol-specific probes: (send_bytes, recv_size)
PROBES = {
    21: (b"\r\n", 1024),      # FTP
    22: (b"SSH-2.0-\r\n", 2048),  # SSH
    23: (b"\r\n", 512),       # Telnet
    25: (b"EHLO test\r\n", 1024),  # SMTP
    80: (b"GET / HTTP/1.0\r\n\r\n", 4096),  # HTTP
    110: (b"USER test\r\n", 512),   # POP3
    143: (b"a001 LOGOUT\r\n", 512), # IMAP
    443: (b"GET / HTTP/1.0\r\n\r\n", 4096),  # HTTPS
    3306: (b"\x00", 512),     # MySQL
    5432: (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", 512),  # PostgreSQL
    8080: (b"GET / HTTP/1.0\r\n\r\n", 4096),
}

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}


@dataclass
class BannerResult:
    port: int
    service: str
    banner: str
    open: bool
    error: Optional[str] = None


def grab_banner(
    host: str,
    port: int,
    timeout: float = 3.0,
    probe: Optional[tuple] = None,
) -> BannerResult:
    """Grab banner from a single port."""
    service = SERVICE_NAMES.get(port, "unknown")
    send_data, recv_size = probe or PROBES.get(port, (b"\r\n", 1024))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(send_data)
        banner = sock.recv(recv_size).decode("utf-8", errors="replace")
        sock.close()

        banner = banner.strip()
        if len(banner) > 500:
            banner = banner[:500] + "..."
        if not banner:
            banner = "(no banner)"

        return BannerResult(port=port, service=service, banner=banner, open=True)
    except socket.timeout:
        return BannerResult(port=port, service=service, banner="", open=False, error="timeout")
    except ConnectionRefusedError:
        return BannerResult(port=port, service=service, banner="", open=False, error="refused")
    except Exception as e:
        return BannerResult(port=port, service=service, banner="", open=False, error=str(e))


def main():
    parser = argparse.ArgumentParser(
        description="Banner grabbing tool with protocol probes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("host", help="Target host")
    parser.add_argument(
        "-p", "--ports",
        default="21,22,23,25,53,80,110,143,443,3306,5432,8080,8443",
    )
    parser.add_argument("-t", "--timeout", type=float, default=3)
    parser.add_argument("-j", "--threads", type=int, default=5)
    parser.add_argument("-o", "--output", choices=["text", "json"])
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",")]
    results = []

    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(grab_banner, args.host, p, args.timeout): p for p in ports}
            for future in as_completed(futures):
                results.append(future.result())
    else:
        for port in ports:
            results.append(grab_banner(args.host, port, args.timeout))

    results.sort(key=lambda r: r.port)

    if args.json or args.output == "json":
        print(json.dumps([asdict(r) for r in results], indent=2))
        return

    print(f"[*] Banner grabbing: {args.host}")
    print("-" * 70)
    for r in results:
        status = "OPEN" if r.open else "closed"
        err = f" ({r.error})" if r.error else ""
        print(f"[{r.port:5}] {r.service:12} [{status}]{err}")
        if r.banner:
            for line in r.banner.split("\n")[:3]:
                print(f"       {line[:65]}")
    print("-" * 70)


if __name__ == "__main__":
    main()
