# Phase-8: RC (Release Candidate) Preparation & Quality Guards

> Rust 1.90; No git history changes; Keep current features & acceptance suite

## Prerequisites

```bash
# Verify toolchain
rustc --version  # Must be 1.90.x
cargo --version

# Verify Phase-7 completion
./scripts/tools/validation/guard-no-unwrap.sh  # Must pass
cargo +1.90 clippy --workspace --exclude xtests -- -D warnings  # Must pass
```

---

## A) Release Artifacts (man + shell completions + version metadata)

### A1. Generate manpage (if feature enabled)

```bash
# Check if manpage feature exists
cargo +1.90 build -p app --features "acceptance,manpage" --release 2>&1 | grep -i "feature"

# If manpage output goes to stdout:
mkdir -p dist/man
target/release/app --help-man > dist/man/app.1 || echo "manpage generation not implemented"

# Alternative: If using clap_mangen, output may be in target/release/build/*/out/*.1
find target/release/build -name "*.1" -exec cp {} dist/man/ \; 2>/dev/null || true
```

### A2. Generate shell completions

```bash
mkdir -p dist/completions/{bash,zsh,fish}

# If gen-completions subcommand exists:
target/release/app gen-completions --dir dist/completions 2>/dev/null || {
  echo "Shell completion generation not implemented"
  echo "# Placeholder" > dist/completions/bash/app.bash
  echo "# Placeholder" > dist/completions/zsh/_app
  echo "# Placeholder" > dist/completions/fish/app.fish
}
```

### A3. Version metadata snapshot

```bash
target/release/app version --format json > dist/version.json
cat dist/version.json  # Verify keys: name, version, commit, date, features[]
```

**Expected format:**
```json
{
  "name": "singbox-rust",
  "version": "0.1.0",
  "commit": "abc1234",
  "date": "2025-10-18",
  "features": ["acceptance", "router", ...]
}
```

---

## B) Release Binary Matrix (local build only)

### B1. Linux x86_64 (gnu)

```bash
mkdir -p dist/bin/x86_64-unknown-linux-gnu
RUSTFLAGS="-C target-cpu=x86-64-v3" \
  cargo +1.90 build -p app --features acceptance --release
cp target/release/app dist/bin/x86_64-unknown-linux-gnu/
strip dist/bin/x86_64-unknown-linux-gnu/app
```

### B2. Linux x86_64 (musl - optional)

```bash
rustup target add x86_64-unknown-linux-musl
mkdir -p dist/bin/x86_64-unknown-linux-musl
cargo +1.90 build -p app --features acceptance --release \
  --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/app dist/bin/x86_64-unknown-linux-musl/
```

### B3. macOS (if available)

```bash
# On macOS only:
rustup target add aarch64-apple-darwin
mkdir -p dist/bin/aarch64-apple-darwin
cargo +1.90 build -p app --features acceptance --release \
  --target aarch64-apple-darwin
cp target/aarch64-apple-darwin/release/app dist/bin/aarch64-apple-darwin/
```

### B4. Generate checksums

```bash
cd dist/bin
find . -name "app" -type f -exec shasum -a 256 {} \; > ../checksums.txt
cd ../..
cat dist/checksums.txt
```

---

## C) Supply Chain & Security Checks

### C1. cargo-deny (license/vulnerability/ban)

```bash
# If deny.toml exists:
cargo deny check bans licenses sources advisories || {
  echo "WARN: cargo-deny not configured or failed"
  echo "Manual audit required for Phase-8 sign-off"
}
```

### C2. cargo-audit (known vulnerabilities)

```bash
cargo audit || {
  echo "WARN: cargo-audit failed or unavailable"
  echo "Manual security review required"
}
```

### C3. Minimal attack surface: unwrap_or audit (non-blocking)

```bash
# Add to scripts/tools/validation/guard-no-unwrap.sh or run separately:
echo "=== Audit: unwrap_or usage (informational) ==="
rg -n "unwrap_or" crates/sb-core crates/sb-transport crates/sb-adapters \
  | sed 's/^/[INFO unwrap_or] /' \
  | tee /tmp/unwrap_or_audit.txt
echo "Review /tmp/unwrap_or_audit.txt for potential error-masking patterns"
```

---

## D) Go/Rust Replay Alignment (sample vectors)

### D1. Route explain sample vectors

Create test vectors for common scenarios:

```bash
mkdir -p app/tests/data/route_vectors
```

**Files to create:** See `route_vectors/` templates below.

### D2. Check field mismatch vectors

Enhance `app/tests/data/bad.json` or create additional test cases:
- Field type mismatch
- Range violations
- Unknown fields (with/without --allow-unknown)

### D3. Run alignment tests

```bash
cargo +1.90 test -p app --features acceptance route_parity
cargo +1.90 test -p app --features acceptance check_
```

---

## E) Performance & Robustness Smoke Tests

### E1. Route explain 1k loop (ignore by default)

Add to `app/tests/route_parity.rs`:
```rust
#[tokio::test]
#[ignore]
async fn route_explain_stability_1k_loop() {
    // Run 1000 iterations, verify no panic/leak
}
```

### E2. Check large config (ignore by default)

Add to `app/tests/check_*.rs`:
```rust
#[test]
#[ignore]
fn check_large_config_no_oom() {
    // Generate config with 10k rules, verify completion
}
```

Run manually:
```bash
cargo +1.90 test -p app --features acceptance -- --ignored
```

---

## F) Documentation / Changelog / RC Notes

### F1. Documentation alignment

**README.md quick start:**
```bash
# Build with acceptance features
cargo +1.90 build -p app --features acceptance --release

# CLI examples
target/release/app version --format json
target/release/app check -c config.json --schema-v2-validate
target/release/app route -c config.json --dest example.com:443 --explain
target/release/app run -c config.json
```

### F2. Create ROUTE_EXPLAIN.md

See template below.

### F3. Update CHANGELOG.md

See template below.

---

## G) Final RC Package

### G1. Final regression

```bash
./scripts/dev/ci-acceptance.sh
```

### G2. Generate RC manifest

```bash
cat > dist/RC_MANIFEST.txt <<EOF
singbox-rust Release Candidate Build Info
==========================================
Build Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Rust Version: $(rustc --version)
Cargo Version: $(cargo --version)
Git Commit: $(git rev-parse HEAD 2>/dev/null || echo "N/A")
Git Branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "N/A")
Features: acceptance,router,dns,tls,metrics
Build Command: cargo +1.90 build -p app --features acceptance --release
Toolchain Lock: 1.90 (no nightly features)
Platform: $(uname -s)/$(uname -m)
EOF
```

### G3. Package RC tarball

```bash
tar -czf singbox-rust-rc.tar.gz dist/
ls -lh singbox-rust-rc.tar.gz
echo "RC package ready: singbox-rust-rc.tar.gz"
```

---

## Checklist

- [ ] A) Release artifacts generated (man, completions, version.json)
- [ ] B) Binary matrix built (at least one target)
- [ ] C) Security checks run (deny/audit)
- [ ] D) Go/Rust alignment tests pass
- [ ] E) Smoke tests added (even if ignored)
- [ ] F) Docs updated (README, ROUTE_EXPLAIN, CHANGELOG)
- [ ] G) RC package created with manifest

---

## Additional Recommendations (Future)

1. **Audit whitelist**: Enumerate allowed `unwrap_or*` calls with business justification
2. **Migration golden test**: `--migrate` → `--schema-v2-validate` should pass
3. **Binary signing**: Add GPG/minisign signatures to dist/checksums.txt
4. **Docker image**: Multi-stage build with final musl binary

