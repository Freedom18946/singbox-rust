#!/usr/bin/env bash
set -euo pipefail
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}
mkdir -p .e2e/artifacts
scripts/release
cp target/rc/manifest/sha256.txt .e2e/artifacts/sha1.txt
sleep 1
scripts/release
diff -u .e2e/artifacts/sha1.txt target/rc/manifest/sha256.txt && echo "[repro] OK"