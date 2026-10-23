# Legacy 8M / display_errors=On line (archived)

This directory keeps the earlier one-shot exploit (`exploit.py`), its
mechanism notes, and the old build/run configuration:

- `exploit.py` — the custom-ini one-shot
- `docker/php.ini` — `display_errors=On`, `memory_limit=8M`,
  `max_input_vars=1000`
- `docker/docker-compose.yml` — old `127.0.0.1:8088` target; its volume
  paths were adjusted to this archive location
- `docker/offsets.py` — libphp offset reader used by the old exploit
- `lab/apache2_aslr.conf` — old lab Apache configuration

That target used a **custom** `php.ini`, not the stock official
`php.ini-production`. The current target of this repository is the official
`php:8.4.26-apache` image with the untouched official `php.ini-production`
(`display_errors=Off`, `memory_limit=128M`) and the official prefork
workers; see [../../README.md](../../README.md) and
[../../pure/RESEARCH_PURE_128M.md](../../pure/RESEARCH_PURE_128M.md).

The archived paths were adjusted so the old flow still resolves the
repository-root `out/` and the current `pure/docker/www` +
`pure/docker/apache-single-worker.conf` that the repository still ships for
the `--single` lab mode. `tools/`,
`logs/`, and the untracked `bwcal/` tree were not moved; some old tools may
still refer to the original locations.
