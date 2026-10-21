#!/usr/bin/env python3
"""Scan the Zend chunk for a marker placed in a fake HashTable."""

import argparse
import os
import subprocess
import struct


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chunk", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--marker", default="MARK855")
    parser.add_argument("--size", type=lambda value: int(value, 0), default=0x200000)
    args = parser.parse_args()
    pid = int(
        subprocess.check_output(
            ["sh", "-c", "pgrep -P 1 apache2 | head -1"], text=True
        ).strip()
    )
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
        memory.seek(args.chunk)
        data = memory.read(args.size)
    needle = args.marker.encode()
    positions = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1
    print(f"pid={pid} chunk=0x{args.chunk:x} bytes={len(data)}")
    print("MARKER_OFFSETS=" + ",".join(hex(pos) for pos in positions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
