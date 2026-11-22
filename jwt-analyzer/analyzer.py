#!/usr/bin/env python3
"""
JWT Token Analyzer
Decodes, validates structure, checks for common vulnerabilities
(alg:none, weak alg, expired, etc.).
"""

import base64
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple, List
import argparse


@dataclass
class JWTResult:
    header: dict
    payload: dict
    signature_raw: str
    valid_structure: bool
    vulnerabilities: List[str]


def decode_jwt(token: str) -> Tuple[Optional[dict], Optional[dict], str, Optional[str]]:
    """Decode JWT parts. Returns (header, payload, signature_b64, error)."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, "", "Invalid JWT format (expected 3 parts)"

    def b64decode(s: str) -> bytes:
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        return base64.urlsafe_b64decode(s)

    try:
        header = json.loads(b64decode(parts[0]).decode())
        payload = json.loads(b64decode(parts[1]).decode())
        return header, payload, parts[2], None
    except Exception as e:
        return None, None, "", str(e)


def check_vulnerabilities(header: dict, payload: dict) -> List[str]:
    """Check for common JWT vulnerabilities."""
    vulns = []

    # alg:none
    if header.get("alg", "").lower() == "none":
        vulns.append("CRITICAL: alg:none - Accepts unsigned tokens")

    # Weak algorithms
    weak_algos = ["hs256", "hs384", "hs512", "rs256"]
    if header.get("alg", "").lower() in weak_algos:
        vulns.append("Info: Consider ES256/EdDSA for asymmetric")

    # jku header (can load key from URL)
    if "jku" in header:
        vulns.append("WARNING: jku in header - Key loading from URL")

    # Expiration
    exp = payload.get("exp")
    if exp:
        try:
            exp_dt = datetime.fromtimestamp(exp)
            if exp_dt < datetime.now():
                vulns.append("Token EXPIRED")
        except (TypeError, OSError):
            pass

    # Not before
    nbf = payload.get("nbf")
    if nbf:
        try:
            if datetime.fromtimestamp(nbf) > datetime.now():
                vulns.append("Token not yet valid (nbf)")
        except (TypeError, OSError):
            pass

    # Sensitive claims
    sensitive = ["password", "secret", "key"]
    for key in payload:
        if any(s in key.lower() for s in sensitive):
            vulns.append(f"Sensitive claim: {key}")

    return vulns


def analyze(token: str) -> JWTResult:
    """Full JWT analysis."""
    header, payload, sig, err = decode_jwt(token)
    if err:
        return JWTResult(
            header={},
            payload={},
            signature_raw="",
            valid_structure=False,
            vulnerabilities=[f"Decode error: {err}"],
        )

    vulns = check_vulnerabilities(header, payload)
    return JWTResult(
        header=header,
        payload=payload,
        signature_raw=sig[:50] + "..." if len(sig) > 50 else sig,
        valid_structure=True,
        vulnerabilities=vulns,
    )


def main():
    parser = argparse.ArgumentParser(description="JWT token analyzer")
    parser.add_argument("token", nargs="?", help="JWT token or - for stdin")
    parser.add_argument("-f", "--file", help="Read token from file")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    from pathlib import Path

    if args.file:
        token = Path(args.file).read_text()
    elif args.token == "-" or (args.token is None and not sys.stdin.isatty()):
        token = sys.stdin.read()
    elif args.token:
        token = args.token
    else:
        token = input("JWT: ")

    result = analyze(token.strip())

    if args.quiet:
        print(json.dumps(result.payload, indent=2))
        return

    print("=" * 55)
    print("JWT ANALYSIS")
    print("=" * 55)
    print("\nHeader:")
    print(json.dumps(result.header, indent=2))
    print("\nPayload:")
    print(json.dumps(result.payload, indent=2))
    print(f"\nSignature (b64): {result.signature_raw}")

    if result.vulnerabilities:
        print("\n[!] Findings:")
        for v in result.vulnerabilities:
            print(f"  - {v}")
    else:
        print("\n[+] No obvious vulnerabilities found")
    print("=" * 55)


if __name__ == "__main__":
    main()
