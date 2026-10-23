# php:8.4.26-apache / Debian 13 (trixie) / x86_64

记录日期：2026-10-23
状态：端到端验证通过（`uid=33(www-data)`）

## 构建身份

| 字段 | 值 |
|---|---|
| 镜像 | `php:8.4.26-apache` |
| 镜像 digest（记录时） | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| image ID | `46b195b6378e` |
| 发行版 | Debian GNU/Linux 13 (trixie) |
| 架构 | x86_64 |
| PHP | 8.4.26 (NTS, mod_php)，build Oct 21 2026 00:31:19 |
| Apache | 2.4.69 (Debian) |
| libphp.so | `/usr/lib/apache2/modules/libphp.so` |
| libphp SHA-256 | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |
| libphp GNU build-id | `a534a5c4a890b378ef6c227590627d531eafa8ce` |

匹配时优先看 `libphp.so` 的 SHA-256 / build-id；镜像 tag 会随 registry
重新构建而变化。

## libphp 符号偏移

相对 libphp 加载基址：

| 符号 | 偏移 | 绑定 |
|---|---|---|
| `zval_ptr_dtor` | `0x65EB60` | GLOBAL |
| `zif_system` | `0x465370` | LOCAL |
| `zif_passthru` | `0x465380` | LOCAL |

运行时地址 = `libphp_base + offset`。链上通过越界窗口里重复出现的
`zval_ptr_dtor` 反推 `libphp_base = value - 0x65EB60`。

## 堆 / 结构偏移

当前 128M 官方配置、`files` session handler、单 worker 基线/官方 worker
固定同一 child 的链：

| 名称 | 表达式 | 说明 |
|---|---|---|
| fake zend_array `S` | `main_chunk + 0xF8398` | stage-3 伪造 HashTable |
| A2 后的 `hsv` | `main_chunk + 0x7D720` | `PS(hash_serialize_verifier)` 指向堆 |
| `PS(id)` | `ps_globals + 0x10` | |
| `PS(mod_data)` | `ps_globals + 0x60` | 40B `ps_files` |
| `PS(send_cookie)` | `ps_globals + 0x15E` | 1 字节 |
| `PS(hash_serialize_verifier)` | `ps_globals + 0x168` | |
| main chunk 指纹 | 2MiB 簇内 87 个指针 | 泄漏窗口里取计数 87 的簇 |
| id chunk / libphp 簇 | 7495 / 1095 个指针 | 0xC8000 (800KB) 窗口 |

这些堆偏移绑定当前 PHP 构建和 128M 配置；换版本/配置需要重新标定。

## 目标配置

- 官方 `php.ini-production`：`display_errors=Off`、`memory_limit=128M`、
  `post_max_size=8M`、`max_input_vars=1000`
- 官方 prefork：`StartServers 5`、`MaxRequestWorkers 150`
- 利用时 `--workers 150`（占住 149 个 child，把 A1/B1/A2/B2 固定到
  同一个 child）；单 worker 基线用 `--workers 1`

## 验证

- 官方 worker 模式：10/10
- 单 worker 基线：20/20
- 按 README 全新 clone 后执行：2/2
- proof：`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

复现：

```bash
./pure/run_pure.sh
python3 exploit.py --port 18110
```

日志：

- `pure/evidence/official_workers_20261022.log`
- `pure/evidence/pwn_pure_batch_20261022.log`
- `pure/evidence/clone_readme_20261023.log`

## 注意

- 这些偏移只对上面这个 `libphp.so`（SHA-256/build-id）有效。换 PHP
  补丁版本、发行版、镜像构建或 CPU 架构（例如 arm64）都要新建记录。
- `zif_system` / `zif_passthru` 是 LOCAL 符号；用 `nm --defined-only`
  或 `readelf -sW` 读，不要只依赖 `nm -D`。
- 用错偏移可能让 worker 直接崩溃；仅在授权环境验证。
