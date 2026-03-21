# Production Dockerfile for the current repository CLI.

ARG RUST_VERSION=1.92
ARG ALPINE_VERSION=3.20

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
    --bin app \
    && strip /build/target/release/app

FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    tini \
    wget

RUN addgroup -S singbox && adduser -S singbox -G singbox

COPY --from=builder /build/target/release/app /usr/local/bin/app
RUN ln -s /usr/local/bin/app /usr/local/bin/singbox-rust

RUN mkdir -p /etc/singbox /var/lib/singbox /var/log/singbox \
    && chown -R singbox:singbox /etc/singbox /var/lib/singbox /var/log/singbox

ENV ADMIN_LISTEN=0.0.0.0:19090

ENTRYPOINT ["/sbin/tini", "--"]
USER singbox
WORKDIR /etc/singbox

CMD ["app", "run", "-c", "/etc/singbox/config.json"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -T 3 -O /dev/null http://127.0.0.1:19090/healthz || exit 1

LABEL org.opencontainers.image.source="https://github.com/Freedom18946/singbox-rust"
LABEL org.opencontainers.image.description="singbox-rust current app CLI image"

EXPOSE 1080 19090
