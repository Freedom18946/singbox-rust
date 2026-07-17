#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-linux-runtime.sh '<command>'

Environment:
  SINGBOX_LINUX_PLATFORM       linux/amd64 (default) or linux/arm64
  SINGBOX_LINUX_RUNTIME_IMAGE Override the architecture-specific image tag
  SINGBOX_LINUX_STATE_ROOT     Host bind-cache root (default: /private/tmp/...)
  SINGBOX_LINUX_REBUILD_IMAGE  Set to 1 to rebuild the toolchain image
  SINGBOX_LINUX_CAP_NET_ADMIN  Set to 1 to add NET_ADMIN for Linux inbound smoke
EOF
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
task_dir="${repo_root}/agents-only/lnx_rt_01"
dockerfile="${task_dir}/Dockerfile"
platform="${SINGBOX_LINUX_PLATFORM:-linux/amd64}"
command="$1"

case "${platform}" in
  linux/amd64) arch="amd64" ;;
  linux/arm64) arch="arm64" ;;
  *)
    echo "run-linux-runtime: unsupported platform: ${platform}" >&2
    exit 2
    ;;
esac

image="${SINGBOX_LINUX_RUNTIME_IMAGE:-singbox-rust-lnx-rt:rust1.92-go1.24.7-bookworm-${arch}}"
state_root="${SINGBOX_LINUX_STATE_ROOT:-/private/tmp/singbox-rust-lnx-rt-01/${arch}}"
container_name="singbox-lnx-rt-01-${arch}-$$"
go_binary="${state_root}/go-bin/sing-box"

command -v docker >/dev/null 2>&1 || {
  echo "run-linux-runtime: docker CLI not found" >&2
  exit 127
}
docker info >/dev/null 2>&1 || {
  echo "run-linux-runtime: Docker daemon unavailable" >&2
  exit 1
}
[[ -f "${dockerfile}" ]] || {
  echo "run-linux-runtime: Dockerfile missing: ${dockerfile}" >&2
  exit 1
}

mkdir -p \
  "${state_root}/cargo" \
  "${state_root}/go-bin" \
  "${state_root}/go-build" \
  "${state_root}/go-mod" \
  "${state_root}/interop-artifacts" \
  "${state_root}/target" \
  "${state_root}/tmp"

if [[ "${SINGBOX_LINUX_REBUILD_IMAGE:-0}" == "1" ]] \
  || ! docker image inspect "${image}" >/dev/null 2>&1; then
  echo "run-linux-runtime: building image=${image} platform=${platform}"
  DOCKER_BUILDKIT=1 docker build \
    --platform "${platform}" \
    --tag "${image}" \
    --file "${dockerfile}" \
    "${task_dir}"
fi

mount_args=(
  --mount "type=bind,src=${repo_root},dst=/workspace"
  --mount "type=bind,src=${state_root},dst=/linux-state"
)
if [[ -f "${go_binary}" ]]; then
  mount_args+=(
    --mount "type=bind,src=${go_binary},dst=/workspace/go_fork_source/sing-box-1.13.13/sing-box,readonly"
  )
fi

cap_args=()
user_args=(--user "$(id -u):$(id -g)")
if [[ "${SINGBOX_LINUX_CAP_NET_ADMIN:-0}" == "1" ]]; then
  cap_args+=(--cap-add NET_ADMIN)
  # Docker drops effective capabilities when starting directly as a non-root
  # UID. Keep privileged smoke isolated to the opt-in NET_ADMIN lane.
  user_args=(--user 0:0)
fi

echo "run-linux-runtime: platform=${platform} image=${image} state=${state_root}"
docker run --rm --init \
  --name "${container_name}" \
  --label "singbox-rust.task=lnx-rt-01" \
  --platform "${platform}" \
  "${user_args[@]}" \
  "${mount_args[@]}" \
  "${cap_args[@]}" \
  --workdir /workspace \
  --env HOME=/tmp \
  --env CARGO_HOME=/linux-state/cargo \
  --env CARGO_INCREMENTAL=0 \
  --env CARGO_PROFILE_DEV_DEBUG=0 \
  --env CARGO_PROFILE_TEST_DEBUG=0 \
  --env CARGO_TARGET_DIR=/linux-state/target \
  --env GOCACHE=/linux-state/go-build \
  --env GOMODCACHE=/linux-state/go-mod \
  --env INTEROP_ACCEPTANCE_APP_TARGET_DIR=/linux-state/target/interop-acceptance-app \
  --env INTEROP_PROTOCOL_APP_TARGET_DIR=/linux-state/target/interop-acceptance-app \
  --env INTEROP_RUST_BIN=/linux-state/target/debug/app \
  --env PROTOC_INCLUDE=/usr/include \
  --env RUSTUP_TOOLCHAIN=1.92.0 \
  --env TEST_TMPDIR=/linux-state/tmp \
  "${image}" \
  bash -c "${command}"
