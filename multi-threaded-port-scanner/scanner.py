#!/usr/bin/env python3
"""
Multi-threaded Port Scanner
Fast port discovery with banner grabbing, service fingerprinting,
detailed reporting, and export options.
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
import json
from datetime import datetime

# Common port → service mapping
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


@dataclass
class ScanResult:
    port: int
    open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    error: Optional[str] = None


def get_service_name(port: int) -> str:
    """Return known service name for port."""
    return SERVICE_MAP.get(port, "unknown")


def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Attempt to grab service banner from open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else None
    except Exception:
        return None


def scan_port(
    host: str,
    port: int,
    timeout: float,
    grab_banners: bool = False,
) -> ScanResult:
    """Check if a port is open, optionally grabbing banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result != 0:
            return ScanResult(port=port, open=False)

        banner = grab_banner(host, port, timeout) if grab_banners else None
        service = get_service_name(port)
        return ScanResult(
            port=port,
            open=True,
            service=service,
            banner=banner,
        )
    except socket.gaierror as e:
        return ScanResult(port=port, open=False, error=str(e))
    except Exception as e:
        return ScanResult(port=port, open=False, error=str(e))


def parse_port_spec(spec: str) -> list[int]:
    """Parse port specification: 1-1000, 22,80,443, or both."""
    ports = set()
    for part in spec.replace(" ", "").split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def validate_host(host: str) -> bool:
    """Basic host validation."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-threaded port scanner with banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s example.com -p 20-100 -t 200 --banner
  %(prog)s 10.0.0.1 -p 22,80,443,8080 -o results.json
        """,
    )
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="Port range (1-1000) or list (22,80,443)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds",
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Attempt to grab service banners for open ports",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to JSON file",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output",
    )
    args = parser.parse_args()

    if not validate_host(args.host):
        print(f"Error: Cannot resolve host '{args.host}'", file=sys.stderr)
        sys.exit(1)

    try:
        ports = parse_port_spec(args.ports)
    except ValueError as e:
        print(f"Error: Invalid port specification - {e}", file=sys.stderr)
        sys.exit(1)

    if not ports:
        print("Error: No valid ports to scan", file=sys.stderr)
        sys.exit(1)

    if args.threads < 1 or args.threads > 500:
        print("Error: Threads must be between 1 and 500", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning {args.host} ({len(ports)} ports, {args.threads} threads)")
    if args.banner:
        print("[*] Banner grabbing enabled")
    print()

    open_ports: list[ScanResult] = []
    errors = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_port,
                args.host,
                port,
                args.timeout,
                args.banner,
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            if result.open:
                open_ports.append(result)
                if not args.quiet:
                    banner_str = f" | {result.banner[:50]}..." if result.banner else ""
                    print(f"[+] {result.port:5} {result.service:12}{banner_str}")
            elif result.error and not args.quiet:
                errors += 1

    # Summary
    open_ports.sort(key=lambda x: x.port)
    print()
    print("=" * 60)
    print(f"Scan completed: {len(open_ports)} open, {len(ports) - len(open_ports)} closed")
    if errors:
        print(f"Errors: {errors}")
    print("=" * 60)

    # Export
    if args.output:
        report = {
            "host": args.host,
            "scan_time": datetime.now().isoformat(),
            "ports_scanned": len(ports),
            "ports_open": len(open_ports),
            "results": [
                {
                    "port": r.port,
                    "service": r.service,
                    "banner": r.banner,
                }
                for r in open_ports
            ],
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
