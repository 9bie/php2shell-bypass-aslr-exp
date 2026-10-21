#!/usr/bin/env python3
"""Read PHP worker session globals through /proc/PID/mem."""

from __future__ import annotations

import os
import argparse
import re
import struct
import subprocess


MODULE = "/usr/lib/apache2/modules/libphp8.5.so"
PS_GLOBALS = 0x991FE0
PS_ID = 0x10
PS_SEND_COOKIE = 0x15E
PS_HTTP_SESSION_VARS = 0x168


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    master = int(
        subprocess.check_output(
            ["sh", "-c", "pgrep -P 1 apache2 | head -1"],
            text=True,
        ).strip()
    )
    module_base = None
    with open(f"/proc/{master}/maps", "r", encoding="ascii") as maps:
        for line in maps:
            if line.rstrip().endswith(MODULE):
                module_base = int(line.split("-", 1)[0], 16)
                break
    if module_base is None:
        raise SystemExit("libphp mapping not found")
    ps = module_base + PS_GLOBALS
    with open(f"/proc/{master}/mem", "rb", buffering=0) as memory:
        def read(address: int, size: int) -> bytes:
            memory.seek(address)
            return memory.read(size)

        globals_data = read(ps, 0x180)
        ps_id = struct.unpack_from("<Q", globals_data, PS_ID)[0]
        send_cookie = globals_data[PS_SEND_COOKIE]
        session_vars = struct.unpack_from("<Q", globals_data, PS_HTTP_SESSION_VARS)[0]
        print(
            f"pid={master} modbase=0x{module_base:x} ps=0x{ps:x} "
            f"id=0x{ps_id:x} send_cookie={send_cookie} "
            f"http_session_vars=0x{session_vars:x}"
        )
        if ps_id:
            print("id_header=", read(ps_id, 0x40).hex())
        if session_vars:
            session_data = read(session_vars, 0x40)
            print("session_header=", session_data.hex())
            print("ref_val=0x%x" % struct.unpack_from("<Q", session_data, 8)[0])
        if args.dump:
            for offset in range(0, 0x1C0, 8):
                value = struct.unpack_from("<Q", globals_data, offset)[0]
                if value:
                    print(f"ps+0x{offset:x}=0x{value:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
