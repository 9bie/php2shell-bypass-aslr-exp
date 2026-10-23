#!/bin/bash
# Isolated lab target: official php:8.4.26-apache + stock php.ini-production.
#
# Default: the image's own prefork configuration (official workers:
# StartServers 5 / MaxRequestWorkers 150).  The exploit pins one child by
# holding MaxRequestWorkers-1 partial requests open, so run it with
# `--workers 150` (the default).
#
# The target keeps the official config untouched:
#   display_errors=Off, memory_limit=128M, post_max_size=8M.
# The exploit path is HTTP only; gdb is not required and is not used.
#
# Container: p2s-pure-18110, port 18110, workspace ./out (proof files).
#
# usage:
#   ./run_pure.sh             # official workers, stock official image
#   ./run_pure.sh --single    # mount pure/docker/apache-single-worker.conf (one worker)
#   ./run_pure.sh --dbg       # same build with symbols + gdb (calibration only)
#   IMAGE=... ./run_pure.sh   # explicit image override
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
R=$(cd "$HERE/.." && pwd)

if [ -n "${DOCKER:-}" ]; then
  :
elif docker info >/dev/null 2>&1; then
  DOCKER=docker
else
  DOCKER="sudo docker"
fi
IMAGE=${IMAGE:-php:8.4.26-apache}
NAME=${NAME:-p2s-pure-18110}
PORT=${PORT:-18110}
CAP=""
SINGLE=0
MOUNT=""

for arg in "$@"; do
  case "$arg" in
    --dbg)
      IMAGE=${IMAGE_DBG:-php2shell-dbg:gdb}
      CAP="--cap-add=SYS_PTRACE"
      ;;
    --single)
      SINGLE=1
      MOUNT="-v $R/pure/docker/apache-single-worker.conf:/etc/apache2/conf-enabled/zz-p2s.conf:ro"
      ;;
    *)
      echo "usage: $0 [--dbg] [--single]" >&2
      exit 2
      ;;
  esac
done

# shellcheck disable=SC2086
$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
mkdir -p "$R/out"

# shellcheck disable=SC2086
$DOCKER run -d --name "$NAME" $CAP $MOUNT \
  -p "127.0.0.1:$PORT:80" \
  -v "$R/pure/docker/www:/var/www/html:ro" \
  -v "$R/out:/out" \
  "$IMAGE" /bin/sh -c \
  'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini;
   chown -R www-data:www-data /out 2>/dev/null || true;
   exec apache2-foreground' >/dev/null

for _ in $(seq 1 40); do
  if curl -s -m 2 "http://127.0.0.1:$PORT/index.php" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
echo "target: $(curl -s -m 3 "http://127.0.0.1:$PORT/index.php")"
ARCH=$($DOCKER exec "$NAME" uname -m)
echo "architecture: $ARCH (run exploit with --arch $ARCH)"
$DOCKER exec "$NAME" php -v | head -1
$DOCKER exec "$NAME" php -i 2>/dev/null | \
  grep -E '^display_errors|^display_startup_errors|^memory_limit|^post_max_size|^output_buffering|^session.sid_length|^session.use_strict_mode|^session.save_path|^max_file_uploads|^max_input_vars|^max_multipart_body_parts' | head -20
echo "--- MPM:"
if [ "$SINGLE" = 1 ]; then
  echo "workers: 1 (pure/docker/apache-single-worker.conf; non-official; run exploit with --workers 1)"
else
  $DOCKER exec "$NAME" sh -c \
    "grep -v '^#' /etc/apache2/mods-enabled/mpm_prefork.conf | sed '/^$/d'"
  echo "workers: official (run exploit with --workers 150)"
fi
