# Phase-8 Quick Checklist

Use this checklist to track Phase-8 RC preparation progress.

## Pre-flight

- [ ] Rust 1.90 installed and active
- [ ] Phase-7 complete (all todos checked)
- [ ] No-unwrap guard passes
- [ ] Clippy workspace clean

## A) Release Artifacts

- [ ] Manpage generated (or stub created)
- [ ] Shell completions generated (bash/zsh/fish)
- [ ] Version metadata JSON created
- [ ] Artifacts in `dist/` directory

## B) Binary Matrix

- [ ] Linux x86_64-gnu built
- [ ] Binary stripped (if applicable)
- [ ] Checksums generated
- [ ] Optional: musl/macOS builds

## C) Security Checks

- [ ] cargo-deny run (or documented as N/A)
- [ ] cargo-audit run (or documented as N/A)
- [ ] unwrap_or audit reviewed
- [ ] No high-severity issues found

## D) Alignment Tests

- [ ] Route parity tests pass
- [ ] Check validation tests pass
- [ ] Route vectors tested (direct/blackhole/selector/geoip)
- [ ] Field structure validated

## E) Performance Smoke

- [ ] Route explain 1k loop added (ignore)
- [ ] Check large config test added (ignore)
- [ ] Optional: Ran ignored tests locally

## F) Documentation

- [ ] CLI_EXIT_CODES.md verified (0/1/2 only)
- [ ] ROUTE_EXPLAIN.md created
- [ ] CHANGELOG.md updated
- [ ] README quick start updated

## G) RC Package

- [ ] RC_MANIFEST.txt generated
- [ ] Tarball created: `singbox-rust-rc.tar.gz`
- [ ] Package contents verified
- [ ] Checksums included

## Final Validation

- [ ] `./scripts/dev/ci-acceptance.sh` passes
- [ ] `./scripts/tools/release/phase8-quick-start.sh` passes
- [ ] RC package extracted and tested
- [ ] Documentation reviewed

## Sign-off

- [ ] All security checks documented
- [ ] Known issues documented in CHANGELOG
- [ ] RC ready for deployment testing

---

## Quick Commands

```bash
# Pre-flight
./scripts/tools/release/phase8-quick-start.sh

# Full RC build
./scripts/tools/release/phase8-rc.sh

# Step-by-step
./scripts/tools/release/phase8-rc.sh artifacts
./scripts/tools/release/phase8-rc.sh build
./scripts/tools/release/phase8-rc.sh security
./scripts/tools/release/phase8-rc.sh test
./scripts/tools/release/phase8-rc.sh package

# Final validation
./scripts/dev/ci-acceptance.sh
```

## Troubleshooting

### "Rust 1.90 required"
```bash
rustup install 1.90
rustup default 1.90
```

### "no-unwrap guard failed"
```bash
./scripts/tools/validation/guard-no-unwrap.sh
# Review violations and fix or document exceptions
```

### "Tests timeout"
```bash
# Run with longer timeout
TEST_TIMEOUT_SECS=120 cargo test -p app --features acceptance
```

### "Binary build fails"
```bash
# Check feature flags
cargo +1.90 build -p app --features acceptance --release -vv
```

