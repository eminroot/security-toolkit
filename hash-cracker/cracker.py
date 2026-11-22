#!/usr/bin/env python3
"""
Dictionary-based Hash Cracker
Supports multiple algorithms, rule-based mutations, and parallel processing.
Educational/authorized use only.
"""

import hashlib
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def normalize_hash(h: str) -> str:
    """Normalize hash (remove spaces, lowercase)."""
    return h.strip().lower().replace(" ", "")


def check_word(word: str, target_hash: str, alg_name: str) -> bool:
    """Check if word hashes to target."""
    alg = ALGORITHMS.get(alg_name, hashlib.sha256)
    digest = alg(word.encode("utf-8", errors="replace")).hexdigest()
    return digest == target_hash


def mutate(word: str) -> list[str]:
    """Generate common password mutations."""
    mutations = [word]
    if len(word) < 50:
        mutations.extend([
            word + "1", word + "123", word + "!", word + "@",
            word.capitalize(), word.upper(),
            word + "2024", word + "2023",
        ])
    return list(set(mutations))


def crack_single(
    target_hash: str,
    wordlist_path: str,
    alg: str = "sha256",
    mutations: bool = False,
    threads: int = 1,
) -> Optional[str]:
    """Crack hash using wordlist."""
    target_hash = normalize_hash(target_hash)
    words_to_try = []

    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#"):
                words_to_try.append(w)
                if mutations:
                    words_to_try.extend(mutate(w))

    words_to_try = list(dict.fromkeys(words_to_try))

    if threads <= 1:
        for word in words_to_try:
            if check_word(word, target_hash, alg):
                return word
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(check_word, w, target_hash, alg): w for w in words_to_try
        }
        for future in as_completed(futures):
            if future.result():
                return futures[future]
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Dictionary-based hash cracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("hash", help="Hash to crack")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    parser.add_argument(
        "-a", "--alg",
        default="sha256",
        choices=list(ALGORITHMS),
    )
    parser.add_argument("-t", "--threads", type=int, default=4)
    parser.add_argument("-m", "--mutate", action="store_true", help="Try mutations")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not Path(args.wordlist).exists():
        print(f"Error: Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[*] Cracking {args.alg} hash")
        print(f"[*] Wordlist: {args.wordlist}")
        print(f"[*] Threads: {args.threads}")
        print()

    result = crack_single(
        args.hash,
        args.wordlist,
        args.alg,
        args.mutate,
        args.threads,
    )

    if result:
        print(f"[+] Found: {result}")
    else:
        print("[-] Not found in wordlist")


if __name__ == "__main__":
    main()
