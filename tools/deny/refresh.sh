#!/usr/bin/env bash
set -euo pipefail

cargo fetch --locked
cargo deny fetch
