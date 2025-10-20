#!/usr/bin/env bash
# Forbid naked unwrap/expect/panic in core crates (sb-core, sb-transport, sb-adapters)
# Usage: ./scripts/lint/no-unwrap-core.sh
# Exit 0 if clean, 1 if violations found

set -euo pipefail

echo "[no-unwrap-core] Scanning core crates for forbidden calls..."

# Search for forbidden patterns in core crates
# Allow tests (cfg(test)) and safe variants (unwrap_or, unwrap_or_else, unwrap_or_default)
VIOLATIONS=$(rg -n \
  -g '!**/tests/**' \
  -g '!**/benches/**' \
  -g '!**/examples/**' \
  '(?<!unwrap_or)(?<!unwrap_or_else)(?<!unwrap_or_default)\.(unwrap|expect)\(|panic!\(|unimplemented!\(|todo!\(|unreachable!\(' \
  crates/sb-core crates/sb-transport crates/sb-adapters 2>/dev/null || true)

if [ -n "$VIOLATIONS" ]; then
  echo "$VIOLATIONS" | tee /tmp/unwrap_hotspots.txt
  echo ""
  echo "[FAIL] Found forbidden calls in core crates:"
  echo "  - Use '?' with anyhow::Context instead of .unwrap()/.expect()"
  echo "  - Use anyhow::bail!() instead of panic!()"
  echo "  - Replace todo!() with proper error handling"
  echo "  - Safe variants (.unwrap_or, .unwrap_or_else, .unwrap_or_default) are allowed"
  exit 1
fi

echo "[PASS] No forbidden calls found in core crates"

# WARN-level scan for unwrap_or variants (informational only, does not fail)
echo ""
echo "[INFO] Scanning for unwrap_or variants (informational - may mask errors)..."
UNWRAP_OR_USAGE=$(rg -n \
  -g '!**/tests/**' \
  -g '!**/benches/**' \
  -g '!**/examples/**' \
  '\.(unwrap_or|unwrap_or_else|unwrap_or_default)\(' \
  crates/sb-core crates/sb-transport crates/sb-adapters 2>/dev/null || true)

if [ -n "$UNWRAP_OR_USAGE" ]; then
  echo "[WARN] Found unwrap_or variants (review for potential error masking):"
  echo "$UNWRAP_OR_USAGE" | sed 's/^/  [WARN unwrap_or] /' | head -20
  COUNT=$(echo "$UNWRAP_OR_USAGE" | wc -l | tr -d ' ')
  echo "  ... ($COUNT total occurrences, showing first 20)"
  echo ""
  echo "  Note: These patterns do not cause panics but may hide error conditions."
  echo "  Consider using '?' with proper error propagation where appropriate."
else
  echo "[INFO] No unwrap_or variants found"
fi

exit 0

