# Production Dockerfile for singbox-rust
# Multi-stage build for minimal final image

# Stage 1: Build
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    git

WORKDIR /build

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY app ./app
COPY benches ./benches
COPY xtask ./xtask

# Build release binary with full optimizations
RUN cargo build --release --package app \
    --features "router,adapters,observe,admin_debug" \
    --bin run

# Strip binary to reduce size
RUN strip /build/target/release/run

# Stage 2: Runtime  
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    tini

# Create non-root user
RUN addgroup -S singbox && adduser -S singbox -G singbox

# Copy binary from builder
COPY --from=builder /build/target/release/run /usr/local/bin/singbox-rust

# Create config directory
RUN mkdir -p /etc/singbox && chown -R singbox:singbox /etc/singbox

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Run as non-root user
USER singbox

# Default command
CMD ["singbox-rust", "run", "--config", "/etc/singbox/config.json"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD singbox-rust version || exit 1

# Metadata
LABEL maintainer="singbox-rust team"
LABEL org.opencontainers.image.source="https://github.com/Freedom18946/singbox-rust"
LABEL org.opencontainers.image.description="singbox-rust: High-performance proxy in Rust"
LABEL org.opencontainers.image.version="1.0.0"

# Expose common ports (adjust as needed)
EXPOSE 1080 8080 443
