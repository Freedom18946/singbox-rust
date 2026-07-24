#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "${REPO_ROOT}"

exec cargo run --quiet -p interop-lab -- \
  --cases-dir "${REPO_ROOT}/labs/interop-lab/cases" \
  ledger validate \
  --spec "${REPO_ROOT}/labs/interop-lab/docs/dual_kernel_golden_spec.md"
