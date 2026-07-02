#!/usr/bin/env bash
set -euo pipefail

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
ADVISORY_DB_DIR="${CARGO_HOME_DIR}/advisory-db"
ADVISORY_DBS_DIR="${CARGO_HOME_DIR}/advisory-dbs"
REGISTRY_INDEX_DIR="${CARGO_HOME_DIR}/registry/index"
REGISTRY_CACHE_DIR="${CARGO_HOME_DIR}/registry/cache"

missing=0

has_advisory_db=0
if [ -d "${ADVISORY_DB_DIR}" ]; then
  has_advisory_db=1
elif find "${ADVISORY_DBS_DIR}" -mindepth 1 -maxdepth 1 -type d -name 'advisory-db-*' 2>/dev/null | grep -q .; then
  has_advisory_db=1
fi

if [ "${has_advisory_db}" -eq 0 ]; then
  echo "Missing advisory DB under: ${ADVISORY_DB_DIR} or ${ADVISORY_DBS_DIR}/advisory-db-*"
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
exec cargo deny --offline --locked check
