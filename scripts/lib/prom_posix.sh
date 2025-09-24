#!/usr/bin/env sh
# Minimal POSIX-compatible Prometheus scraper utilities.
# The fallback strict CI path uses this when bash>=4 is unavailable.

prom_dump_by_prefix() {
  addr="${1:-127.0.0.1:9090}"
  prefix="${2:-proxy_select_params}"
  curl -fsS "http://$addr/metrics" 2>/dev/null | awk -v p="$prefix" 'index($0,p)==1 { print }'
}
