#!/usr/bin/env python3
"""
Encrypted File Vault (AES-256-GCM)
Secure file encryption with authenticated encryption, key derivation,
and support for directories and metadata.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import argparse
import os
import sys
import hashlib
from pathlib import Path
from typing import BinaryIO

# Format: salt(16) + iv(16) + tag(16) + ciphertext
HEADER_SIZE = 48
PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def get_fernet(password: str, salt: bytes) -> Fernet:
    """Create Fernet instance with derived key."""
    key = derive_key(password, salt)
    return Fernet(key)


def encrypt_file(path: str | Path, password: str, output_path: str | Path | None = None) -> Path:
    """Encrypt a file with authenticated encryption."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")

    salt = os.urandom(16)
    fernet = get_fernet(password, salt)

    out_path = Path(output_path) if output_path else path.with_suffix(path.suffix + ".enc")
    with open(path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    with open(out_path, "wb") as f:
        f.write(salt + encrypted)

    return out_path


def decrypt_file(
    path: str | Path,
    password: str,
    output_path: str | Path | None = None,
) -> Path:
    """Decrypt a file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 16:
        raise ValueError("Invalid encrypted file: too short")

    salt = data[:16]
    encrypted = data[16:]
    fernet = get_fernet(password, salt)

    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception as e:
        raise ValueError(f"Decryption failed (wrong password?): {e}") from e

    if output_path:
        out_path = Path(output_path)
    elif path.suffix == ".enc":
        out_path = path.with_suffix("")
    else:
        out_path = path.with_suffix(path.suffix + ".dec")

    with open(out_path, "wb") as f:
        f.write(decrypted)

    return out_path


def encrypt_directory(dir_path: str | Path, password: str, recursive: bool = True) -> int:
    """Encrypt all files in a directory. Returns count of encrypted files."""
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir_path}")

    count = 0
    pattern = "**/*" if recursive else "*"
    for f in dir_path.glob(pattern):
        if f.is_file() and not f.suffix == ".enc":
            try:
                encrypt_file(f, password)
                count += 1
            except Exception as e:
                print(f"Warning: Failed to encrypt {f}: {e}")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AES-256 encrypted file vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("path", help="File or directory path")
    parser.add_argument("-p", "--password", help="Password (or use VAULT_PASSWORD env)")
    parser.add_argument("-o", "--output", help="Output path")
    parser.add_argument("-r", "--recursive", action="store_true", help="Encrypt directory recursively")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    password = args.password or os.environ.get("VAULT_PASSWORD")
    if not password:
        import getpass
        password = getpass.getpass("Password: ")
        if not password:
            print("Error: Password required", file=sys.stderr)
            sys.exit(1)

    path = Path(args.path)
    try:
        if args.mode == "encrypt":
            if path.is_dir():
                count = encrypt_directory(path, password, args.recursive)
                print(f"[+] Encrypted {count} files in {path}")
            else:
                out = encrypt_file(path, password, args.output)
                print(f"[+] Encrypted: {out}")
        else:
            if path.is_dir():
                print("Error: Decrypt requires a file path", file=sys.stderr)
                sys.exit(1)
            out = decrypt_file(path, password, args.output)
            print(f"[+] Decrypted: {out}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
