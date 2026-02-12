# Production Dockerfile for singbox-rust
# Validation hints:
#   docker build -f deployments/docker/Dockerfile -t singbox-rust:local .
#   docker image inspect singbox-rust:local --format '{{ .Size }}' | awk '{mb=$1/1024/1024; printf "image_size_mb=%.2f\n", mb; exit(mb<50?0:1)}'

ARG RUST_VERSION=1.92
ARG ALPINE_VERSION=3.20

# Stage 1: build
FROM rust:${RUST_VERSION}-alpine AS builder

ARG BUILD_FEATURES="parity"

RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    git \
    perl \
    make

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY app ./app
COPY benches ./benches
COPY xtask ./xtask

RUN cargo build --locked --release --package app \
    --features "${BUILD_FEATURES}" \
    --bin run \
    && strip /build/target/release/run

# Stage 2: runtime
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    tini

RUN addgroup -S singbox && adduser -S singbox -G singbox

COPY --from=builder /build/target/release/run /usr/local/bin/singbox-rust

RUN mkdir -p /etc/singbox /var/lib/singbox /var/log/singbox \
    && chown -R singbox:singbox /etc/singbox /var/lib/singbox /var/log/singbox

ENTRYPOINT ["/sbin/tini", "--"]
USER singbox
WORKDIR /etc/singbox

CMD ["singbox-rust", "run", "--config", "/etc/singbox/config.json"]

# busybox wget is available in alpine base image
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -T 3 -O /dev/null http://127.0.0.1:9090/services/health || exit 1

LABEL maintainer="singbox-rust team"
LABEL org.opencontainers.image.source="https://github.com/nicekid1/singbox-rust"
LABEL org.opencontainers.image.description="singbox-rust: Rust implementation of sing-box proxy platform"

EXPOSE 1080 8080 443 9090
