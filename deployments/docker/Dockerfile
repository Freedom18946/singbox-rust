# Production Dockerfile for singbox-rust
# Multi-stage build for minimal final image

ARG RUST_VERSION=1.82
ARG ALPINE_VERSION=3.20

# Stage 1: Build
FROM rust:${RUST_VERSION}-alpine AS builder

ARG BUILD_FEATURES="parity"

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    git \
    perl \
    make

WORKDIR /build

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY app ./app
COPY benches ./benches
COPY xtask ./xtask

# Build release binary
RUN cargo build --release --package app \
    --features "${BUILD_FEATURES}" \
    --bin run \
    && strip /build/target/release/run

# Stage 2: Runtime
FROM alpine:${ALPINE_VERSION}

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    tini \
    curl

# Create non-root user
RUN addgroup -S singbox && adduser -S singbox -G singbox

# Copy binary from builder
COPY --from=builder /build/target/release/run /usr/local/bin/singbox-rust

# Create directories
RUN mkdir -p /etc/singbox /var/lib/singbox /var/log/singbox \
    && chown -R singbox:singbox /etc/singbox /var/lib/singbox /var/log/singbox

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run as non-root user
USER singbox

WORKDIR /etc/singbox

# Default command
CMD ["singbox-rust", "run", "--config", "/etc/singbox/config.json"]

# Health check using the health API endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:9090/services/health || exit 1

# Metadata
LABEL maintainer="singbox-rust team"
LABEL org.opencontainers.image.source="https://github.com/nicekid1/singbox-rust"
LABEL org.opencontainers.image.description="singbox-rust: Rust implementation of sing-box proxy platform"

# Expose common ports
EXPOSE 1080 8080 443 9090
