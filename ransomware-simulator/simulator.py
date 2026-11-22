#!/usr/bin/env python3
"""
EDUCATIONAL RANSOMWARE SIMULATOR
For authorized lab/learning use only. Do NOT use against systems without permission.
Simulates encryption behavior in a contained test directory.
"""

import os
import hashlib
from pathlib import Path
import argparse

TEST_DIR = "test_ransom_sim"

def simulate_encrypt(target_dir, simulate_only=True):
    """Simulates encryption - only renames/flag files, does NOT actually encrypt."""
    target = Path(target_dir)
    if not target.exists():
        target.mkdir()
    count = 0
    for f in target.rglob("*"):
        if f.is_file() and f.suffix != '.encrypted':
            new_name = f.with_suffix(f.suffix + '.encrypted')
            if simulate_only:
                print(f"[SIM] Would encrypt: {f} -> {new_name}")
            else:
                f.rename(new_name)
            count += 1
    print(f"[*] {'Simulated' if simulate_only else 'Processed'} {count} files")

def main():
    p = argparse.ArgumentParser(description="EDUCATIONAL ransomware simulator")
    p.add_argument('dir', nargs='?', default=TEST_DIR)
    p.add_argument('--execute', action='store_true', help='Actually rename (still no real encryption)')
    args = p.parse_args()
    if not os.path.exists(args.dir):
        os.makedirs(args.dir)
        Path(args.dir, "test.txt").write_text("test content")
    simulate_encrypt(args.dir, simulate_only=not args.execute)

if __name__ == '__main__':
    main()
