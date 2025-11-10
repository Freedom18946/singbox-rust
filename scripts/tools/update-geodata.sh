#!/usr/bin/env bash
set -euo pipefail

# Download latest sing-geoip and sing-geosite databases
#
# Usage:
#   scripts/tools/update-geodata.sh [--dest dir] [--geoip-url URL] [--geosite-url URL]
#
# Defaults:
#   --dest ./data
#   --geoip-url   https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db
#   --geosite-url https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db

DEST_DIR="./data"
GEOIP_URL="https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
GEOSITE_URL="https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
# Optional integrity (if provided, verify after download)
GEOIP_SHA256=""
GEOSITE_SHA256=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest) DEST_DIR="$2"; shift 2;;
    --geoip-url) GEOIP_URL="$2"; shift 2;;
    --geosite-url) GEOSITE_URL="$2"; shift 2;;
    --geoip-sha256) GEOIP_SHA256="$2"; shift 2;;
    --geosite-sha256) GEOSITE_SHA256="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$DEST_DIR"

echo "[+] Downloading geoip.db → $DEST_DIR ..."
curl -fL "$GEOIP_URL" -o "$DEST_DIR/geoip.db"
if [[ -n "$GEOIP_SHA256" ]]; then
  echo "$GEOIP_SHA256  $DEST_DIR/geoip.db" | (shasum -a 256 -c - 2>/dev/null || sha256sum -c -)
fi

echo "[+] Downloading geosite.db → $DEST_DIR ..."
curl -fL "$GEOSITE_URL" -o "$DEST_DIR/geosite.db"
if [[ -n "$GEOSITE_SHA256" ]]; then
  echo "$GEOSITE_SHA256  $DEST_DIR/geosite.db" | (shasum -a 256 -c - 2>/dev/null || sha256sum -c -)
fi

echo "[✓] Done. Files:"
ls -l "$DEST_DIR/geoip.db" "$DEST_DIR/geosite.db"
