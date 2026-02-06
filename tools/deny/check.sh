#!/usr/bin/env bash
set -euo pipefail

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
ADVISORY_DB_DIR="${CARGO_HOME_DIR}/advisory-db"
REGISTRY_INDEX_DIR="${CARGO_HOME_DIR}/registry/index"
REGISTRY_CACHE_DIR="${CARGO_HOME_DIR}/registry/cache"

missing=0

if [ ! -d "${ADVISORY_DB_DIR}" ]; then
  echo "Missing advisory DB: ${ADVISORY_DB_DIR}"
  missing=1
fi

if [ ! -d "${REGISTRY_INDEX_DIR}" ] || [ ! -d "${REGISTRY_CACHE_DIR}" ]; then
  echo "Missing Cargo registry cache under: ${CARGO_HOME_DIR}/registry"
  missing=1
fi

if [ "${missing}" -ne 0 ]; then
  echo "Prerequisites not met. When online, run:"
  echo "  cargo fetch --locked"
  echo "  cargo deny fetch"
  exit 2
fi

export CARGO_NET_OFFLINE=true
exec cargo deny --offline check
