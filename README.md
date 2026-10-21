# PHP2Shell ASLR bypass and RCE lab

> **This is the Mac version.** The current checkout is validated for Apple
> Silicon (ARM64 host) using Docker Desktop with `linux/amd64` containers
> executed through Rosetta.

## Versions

| Target | Guide | Status |
|---|---|---|
| Rosetta Mac (ARM64 host, amd64 guest) | [MAC_ROSETTA.md](MAC_ROSETTA.md) | This checkout |
| Ubuntu 26.04 x86-64 (`PHP 8.5.4-0ubuntu1.3`) | [UBUNTU855.md](UBUNTU855.md) | Verified one-shot RCE |

## Table of Contents

### Platform guides

- [Mac / Rosetta (ARM64)](MAC_ROSETTA.md)
- [Ubuntu x86-64 / PHP 8.5.4](UBUNTU855.md)

### Exploit usage

- [English technical guide](readme_en.md)
- [Chinese technical guide](README.zh-CN.md)
- [Executable exploit](exploit.py)
- [Ubuntu 8.5.4 lab](lab/ubuntu-php85/README.md)

### Mechanism documentation

- [Heap leak through `Set-Cookie`](HTTP_HEAP_LEAK.md)
- [Pure HTTP ASLR bypass](ASLR_PURE_HTTP.md)
- [ASLR bypass research notes](ASLR_PURE_HTTP_RESEARCH.md)
- [Display-errors-off research](DISPLAY_ERRORS_OFF.md)
- [Session lifetime analysis](NOTES.md)
- [No-ASLR reference report](NOASLR_REPORT.md)

### Calibration and debugging

- [Ubuntu 8.5.4 stage-1 calibration](calibrate_ubuntu855.py)
- [Live `R0` calibration](tools/calibrate_r0.py)
- [Carrier/fake-HashTable calibration](tools/calibrate_carriers.py)
- [Standalone Ubuntu stage-3 check](tools/try_stage3_855.py)

### Request flow

The successful one-shot path uses 12 HTTP POST requests:

```text
pre-rotation:  2
stage 1 leak:  2
rotation:      2
stage 2 leak:  2
rotation:      2
stage 3 RCE:   2
```

The vulnerable page is intentionally unchanged:

```php
<?php // Silence is golden.
```
