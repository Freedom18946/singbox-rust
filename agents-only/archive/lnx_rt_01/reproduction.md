<!-- tier: B -->
# LNX-RT-01 reproduction

Use `../../06-scripts/run-linux-runtime.sh` after archival for every command. Raw caches and
artifacts default to `/private/tmp/singbox-rust-lnx-rt-01/<arch>/`.

## Toolchain and Go oracle

```bash
agents-only/06-scripts/run-linux-runtime.sh \
  'uname -m; rustc --version; go version; protoc --version'

agents-only/06-scripts/run-linux-runtime.sh \
  'cd go_fork_source/sing-box-1.13.13 && \
   go build -tags with_clash_api -ldflags "-s -w" \
     -o /linux-state/go-bin/sing-box ./cmd/sing-box'
```

## T1

```bash
agents-only/06-scripts/run-linux-runtime.sh \
  'cargo test -p app --test multiplex_vmess_e2e --all-features'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo test --workspace --all-features'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo check --workspace --all-targets --all-features'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo clippy --workspace --all-targets --all-features'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo fmt --all -- --check'
```

## T2

Build the oracle, interop runner, and dedicated acceptance app before replay. Prebuilding the
dedicated target keeps cold compilation outside the case startup budget.

```bash
agents-only/06-scripts/run-linux-runtime.sh \
  'cd go_fork_source/sing-box-1.13.13 && \
   go build -tags with_clash_api -ldflags "-s -w" \
     -o /linux-state/go-bin/sing-box ./cmd/sing-box'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo build -p interop-lab --bin interop-lab'

agents-only/06-scripts/run-linux-runtime.sh \
  'CARGO_TARGET_DIR="$INTEROP_ACCEPTANCE_APP_TARGET_DIR" \
   cargo build -p app --features acceptance,clash_api,adapters --bin app'

agents-only/06-scripts/run-linux-runtime.sh '
  export INTEROP_GO_BINARY=/workspace/go_fork_source/sing-box-1.13.13/sing-box
  /linux-state/target/debug/interop-lab \
    --artifacts-dir /linux-state/interop-artifacts/lnx-rt-01-vmess \
    case run p2_vmess_dual_dataplane_local --kernel both
'
```

The committed case uses `run_acceptance_app.sh`; do not copy or weaken its assertions for final
evidence. Raw artifacts stay in the architecture bind-cache.

## T3

```bash
SINGBOX_LINUX_PLATFORM=linux/arm64 \
agents-only/06-scripts/run-linux-runtime.sh \
  'cargo test -p app --test multiplex_vmess_e2e --all-features'
```
