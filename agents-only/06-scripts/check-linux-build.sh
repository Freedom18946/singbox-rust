#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${SINGBOX_LINUX_RUST_IMAGE:-rust:1.92-bookworm}"

command -v docker >/dev/null 2>&1 || {
  echo "check-linux-build: docker CLI not found" >&2
  exit 127
}
docker info >/dev/null 2>&1 || {
  echo "check-linux-build: Docker daemon unavailable" >&2
  exit 1
}

run_check() {
  local platform="$1"
  local target="$2"

  echo "check-linux-build: ${platform} ${target}"
  # Docker Desktop can block `_apt` sandbox signature reads; root keeps
  # verification enabled while avoiding that container-only permission fault.
  docker run --rm \
    --platform "${platform}" \
    --mount "type=bind,src=${repo_root},dst=/workspace" \
    --mount type=volume,src=singbox-rust-cargo-registry,dst=/usr/local/cargo/registry \
    --mount type=volume,src=singbox-rust-cargo-git,dst=/usr/local/cargo/git \
    --mount type=volume,src=singbox-rust-target,dst=/workspace/target \
    --workdir /workspace \
    --env CARGO_TERM_COLOR=always \
    --env RUSTUP_TOOLCHAIN=1.92.0 \
    "${image}" \
    bash -c "apt-get -o APT::Sandbox::User=root update -qq && \
      apt-get -o APT::Sandbox::User=root install -y -qq protobuf-compiler >/dev/null && \
      cargo check --workspace --all-features --target ${target}"
}

run_check linux/amd64 x86_64-unknown-linux-gnu
run_check linux/arm64 aarch64-unknown-linux-gnu

echo "check-linux-build: PASS"
