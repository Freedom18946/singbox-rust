#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

echo "[docs-links] checking markdown links in docs/"
./scripts/tools/check-doc-links.sh docs
