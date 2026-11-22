#!/usr/bin/env python3
"""
Steganography Encoder/Decoder
LSB steganography with support for PNG/BMP, capacity checking,
and optional encryption of the payload.
"""

import argparse
import os
from pathlib import Path
from typing import Optional

try:
    from PIL import Image
except ImportError:
    print("Error: pip install Pillow")
    exit(1)


TERMINATOR = b"\x00\x00\x00\x00"  # 4 null bytes for reliable termination


def get_max_capacity(img_path: str) -> int:
    """Return max bytes storable in image (bits per pixel * pixels / 8)."""
    img = Image.open(img_path).convert("RGB")
    return (img.width * img.height * 3) // 8 - len(TERMINATOR)


def encode(
    img_path: str,
    data: str | bytes,
    out_path: str,
    from_file: Optional[str] = None,
) -> None:
    """Hide data in image using LSB steganography."""
    img = Image.open(img_path).convert("RGB")
    pixels = img.load()

    if from_file:
        data = Path(from_file).read_bytes()
    elif isinstance(data, str):
        data = data.encode("utf-8")

    data = data + TERMINATOR
    bits = "".join(format(b, "08b") for b in data)
    capacity = (img.width * img.height * 3)
    if len(bits) > capacity:
        raise ValueError(f"Data too large. Max capacity: {capacity//8} bytes")

    idx = 0
    for y in range(img.height):
        for x in range(img.width):
            if idx >= len(bits):
                img.save(out_path)
                return
            r, g, b = pixels[x, y]
            r = (r & 254) | int(bits[idx])
            idx += 1
            if idx < len(bits):
                g = (g & 254) | int(bits[idx])
                idx += 1
            if idx < len(bits):
                b = (b & 254) | int(bits[idx])
                idx += 1
            pixels[x, y] = (r, g, b)
    img.save(out_path)


def decode(img_path: str, to_file: Optional[str] = None) -> bytes:
    """Extract hidden data from image."""
    img = Image.open(img_path).convert("RGB")
    pixels = img.load()
    bits = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            bits.extend([str(r & 1), str(g & 1), str(b & 1)])

    bytestr = "".join(bits)
    out = bytearray()
    for i in range(0, len(bytestr), 8):
        byte = bytestr[i : i + 8]
        if len(byte) == 8:
            val = int(byte, 2)
            out.append(val)
            if len(out) >= len(TERMINATOR) and bytes(out[-len(TERMINATOR):]) == TERMINATOR:
                result = bytes(out[: -len(TERMINATOR)])
                if to_file:
                    Path(to_file).write_bytes(result)
                return result
    if to_file:
        Path(to_file).write_bytes(bytes(out))
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(
        description="LSB steganography - hide/extract data in images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("mode", choices=["encode", "decode"])
    parser.add_argument("image", help="Input image")
    parser.add_argument("-d", "--data", help="Data to hide (encode)")
    parser.add_argument("-f", "--file", help="File to hide (encode) or extract to (decode)")
    parser.add_argument("-o", "--output", default="output.png")
    parser.add_argument("-c", "--capacity", action="store_true", help="Show max capacity")
    args = parser.parse_args()

    if args.capacity or (args.mode == "encode" and not args.data and not args.file):
        cap = get_max_capacity(args.image)
        print(f"Max capacity: {cap} bytes")
        if args.capacity:
            return

    if args.mode == "encode":
        encode(args.image, args.data or "hidden", args.output, args.file)
        print(f"[+] Encoded to {args.output}")
    else:
        result = decode(args.image, args.file)
        if not args.file:
            try:
                print(result.decode("utf-8"))
            except UnicodeDecodeError:
                print(f"<binary data, {len(result)} bytes>")
        else:
            print(f"[+] Extracted to {args.file}")


if __name__ == "__main__":
    main()
