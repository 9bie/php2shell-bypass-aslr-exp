# offsets

| 架构 | 安装命令 | libphp SHA-256 | build-id | zval_ptr_dtor | zif_system | zif_passthru | 状态 | 作者 |
|---|---|---|---|---|---|---|---|---|
| x86_64 | `docker pull php:8.4.26-apache` | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` | `a534a5c4a890b378ef6c227590627d531eafa8ce` | `0x65EB60` | `0x465370` | `0x465380` | ✅ [详情](php-8.4.26-apache-trixie-amd64.md) | - |
| aarch64 | `docker pull --platform linux/arm64 php:8.4.26-apache` | `e160c9d173be0e170add2ab461ba2995d0dd9ac0feb6faf3e763c052c998ab4b` | `b3525423bd3d026677be6de48285e46ae5a5604b` | `0x63812B` | `0x42CD70` | `0x42CD80` | ✅ PR #6（单 worker 10/10、官方 worker 3/3）· 本机 aarch64 实测 1/1 · [日志](../pure/evidence/arm64_stock_20261023.log) | ideacatlab |

> aarch64 的 `0x63812B` 是泄漏窗口里重复指针的偏移；ELF 符号在 `0x638120`（+0xB）。libphp SHA-256 / build-id 由本机 arm64 镜像实测补全。

# pr

欢迎 PR：新架构、新版本或其它安装方式的偏移记录，附 `libphp.so` 的 SHA-256、build-id 和跑通证据即可。
