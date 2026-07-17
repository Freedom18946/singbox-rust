FROM rust:1.92-bookworm

ARG TARGETARCH
ARG GO_VERSION=1.24.7

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get -o APT::Sandbox::User=root update -qq \
    && apt-get -o APT::Sandbox::User=root install -y -qq --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        file \
        git \
        iproute2 \
        iptables \
        jq \
        libcap2-bin \
        libclang-dev \
        libprotobuf-dev \
        libssl-dev \
        lsof \
        make \
        netcat-openbsd \
        nftables \
        ninja-build \
        pkg-config \
        procps \
        protobuf-compiler \
        python3 \
        python3-yaml \
        tcpdump \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        amd64) go_sha256="da18191ddb7db8a9339816f3e2b54bdded8047cdc2a5d67059478f8d1595c43f" ;; \
        arm64) go_sha256="fd2bccce882e29369f56c86487663bb78ba7ea9e02188a5b0269303a0c3d33ab" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 2 ;; \
    esac \
    && curl -fsSLo /tmp/go.tar.gz \
        "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" \
    && printf '%s  %s\n' "${go_sha256}" /tmp/go.tar.gz | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/usr/local/cargo/bin:${PATH}" \
    RUSTUP_TOOLCHAIN="1.92.0" \
    PROTOC_INCLUDE="/usr/include" \
    CARGO_TERM_COLOR="always" \
    RUST_BACKTRACE="1"

WORKDIR /workspace

RUN rustup component add clippy rustfmt \
    && rustc --version \
    && cargo --version \
    && cargo clippy --version \
    && cargo fmt --version \
    && go version \
    && protoc --version \
    && test -f "${PROTOC_INCLUDE}/google/protobuf/empty.proto"
