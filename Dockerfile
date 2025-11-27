# Multi-stage build for minimal production image
FROM rust:1.75-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY app ./app
COPY benches ./benches

# Build release binary
RUN cargo build --release --bin singbox-rust --features adapters

# Production stage
FROM alpine:3.19

LABEL org.opencontainers.image.title="SingBox Rust"
LABEL org.opencontainers.image.description="High-performance proxy server (Trojan, Shadowsocks)"
LABEL org.opencontainers.image.vendor="Freedom18946"
LABEL org.opencontainers.image.version="1.0.0"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 singbox \
    && adduser -D -u 1000 -G singbox singbox

# Create directories
RUN mkdir -p \
    /etc/singbox-rust \
    /var/log/singbox-rust \
    && chown -R singbox:singbox /var/log/singbox-rust

# Copy binary from builder
COPY --from=builder /build/target/release/singbox-rust /usr/local/bin/singbox-rust
RUN chmod +x /usr/local/bin/singbox-rust

# Copy default configuration (optional)
# COPY configs/trojan-server.json /etc/singbox-rust/config.json.example

# Switch to non-root user
USER singbox

# Expose common ports
EXPOSE 443 8388 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:9090/health || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/singbox-rust"]
CMD ["run", "-c", "/etc/singbox-rust/config.json"]
