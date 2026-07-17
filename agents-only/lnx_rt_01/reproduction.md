<!-- tier: B -->
# LNX-RT-01 reproduction

Use `../06-scripts/run-linux-runtime.sh` for every command. Raw caches and artifacts default
to `/private/tmp/singbox-rust-lnx-rt-01/<arch>/`.

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
  'cargo test -p app --test multiplex_vless_e2e --all-features'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo test -p sb-adapters -p sb-core -p sb-transport --all-features'

agents-only/06-scripts/run-linux-runtime.sh \
  'cargo test --workspace --all-features'
```

## T2

Build `interop-lab`, then invoke its binary directly so replay never changes the acceptance
binary profile. `INTEROP_RUST_BIN` points legacy `target/debug/app` cases at the Linux target.

```bash
agents-only/06-scripts/run-linux-runtime.sh \
  'cargo build -p interop-lab --bin interop-lab'

agents-only/06-scripts/run-linux-runtime.sh '
  export INTEROP_GO_BINARY=/workspace/go_fork_source/sing-box-1.13.13/sing-box
  /linux-state/target/debug/interop-lab \
    --artifacts-dir /linux-state/interop-artifacts/lnx-rt-01-core \
    case run p0_clash_api_contract_strict --kernel both
'
```

Protocol-local cases normally use `run_acceptance_app.sh`. When a full-feature Linux app is
already built, copy the case YAML files under `/linux-state/tmp`, replace that launcher with
`/linux-state/target/debug/app`, and pass the copied directory through `--cases-dir`. Case
assertions, oracle rules, and S4 registry remain unchanged.

## T3

```bash
agents-only/06-scripts/run-linux-runtime.sh \
  'cargo test -p sb-adapters --no-default-features \
   --features redirect,tproxy,router --lib \
   linux_redirect_listener_binds_and_stops'

SINGBOX_LINUX_CAP_NET_ADMIN=1 \
agents-only/06-scripts/run-linux-runtime.sh \
  '/linux-state/target/debug/deps/<sb_adapters-test-bin> \
   linux_tproxy_listener_binds_and_stops_with_net_admin --ignored --nocapture'
```

The NET_ADMIN lane intentionally starts as root because Docker drops effective capabilities
when it starts directly as the host's non-root UID.
