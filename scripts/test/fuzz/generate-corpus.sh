#!/bin/bash
# Generate fuzz corpus seeds for various protocols

set -e

FUZZ_DIR="fuzz"
CORPUS_DIR="$FUZZ_DIR/corpus"

echo "Generating fuzz corpus seeds..."

# Create corpus directories
mkdir -p "$CORPUS_DIR/fuzz_vmess"
mkdir -p "$CORPUS_DIR/fuzz_vless_parsing"
mkdir -p "$CORPUS_DIR/fuzz_trojan"
mkdir -p "$CORPUS_DIR/fuzz_shadowsocks"
mkdir -p "$CORPUS_DIR/fuzz_tun_packet"
mkdir -p "$CORPUS_DIR/fuzz_mixed_protocol"

# VMess corpus
echo "Generating VMess corpus..."
# Valid VMess header (version + timestamp + HMAC)
printf '\x01' > "$CORPUS_DIR/fuzz_vmess/valid_header.bin"
head -c 8 /dev/urandom >> "$CORPUS_DIR/fuzz_vmess/valid_header.bin"
head -c 16 /dev/urandom >> "$CORPUS_DIR/fuzz_vmess/valid_header.bin"

# Edge cases
echo -n "" > "$CORPUS_DIR/fuzz_vmess/empty.bin"
head -c 1 /dev/urandom > "$CORPUS_DIR/fuzz_vmess/single_byte.bin"
head -c 10000 /dev/urandom > "$CORPUS_DIR/fuzz_vmess/large.bin"

# VLESS corpus
echo "Generating VLESS corpus..."
# Valid VLESS request (version + UUID + additional + command + address)
printf '\x01' > "$CORPUS_DIR/fuzz_vless_parsing/valid.bin"
head -c 16 /dev/urandom >> "$CORPUS_DIR/fuzz_vless_parsing/valid.bin"
printf '\x00\x01\x01\x7f\x00\x00\x01\x1f\x90' >> "$CORPUS_DIR/fuzz_vless_parsing/valid.bin"

# Edge cases
echo -n "" > "$CORPUS_DIR/fuzz_vless_parsing/empty.bin"
head -c 1 /dev/urandom > "$CORPUS_DIR/fuzz_vless_parsing/single_byte.bin"
head -c 1000 /dev/urandom > "$CORPUS_DIR/fuzz_vless_parsing/large.bin"

# Trojan corpus
echo "Generating Trojan corpus..."
# Valid Trojan password hash (56 hex chars)
printf 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890' > "$CORPUS_DIR/fuzz_trojan/valid_hash.bin"
printf '\r\n\x01\x01\x7f\x00\x00\x01\x1f\x90\r\n' >> "$CORPUS_DIR/fuzz_trojan/valid_hash.bin"

# Edge cases
echo -n "" > "$CORPUS_DIR/fuzz_trojan/empty.bin"
head -c 1 /dev/urandom > "$CORPUS_DIR/fuzz_trojan/single_byte.bin"
head -c 1000 /dev/urandom > "$CORPUS_DIR/fuzz_trojan/large.bin"

# Shadowsocks corpus
echo "Generating Shadowsocks corpus..."
# Valid AEAD packet (salt + encrypted data + auth tag)
head -c 16 /dev/urandom > "$CORPUS_DIR/fuzz_shadowsocks/valid_aead.bin"
head -c 100 /dev/urandom >> "$CORPUS_DIR/fuzz_shadowsocks/valid_aead.bin"
head -c 16 /dev/urandom >> "$CORPUS_DIR/fuzz_shadowsocks/valid_aead.bin"

# Address encoding
printf '\x01\x7f\x00\x00\x01\x1f\x90' > "$CORPUS_DIR/fuzz_shadowsocks/valid_address.bin"

# Edge cases
echo -n "" > "$CORPUS_DIR/fuzz_shadowsocks/empty.bin"
head -c 1 /dev/urandom > "$CORPUS_DIR/fuzz_shadowsocks/single_byte.bin"
head -c 1000 /dev/urandom > "$CORPUS_DIR/fuzz_shadowsocks/large.bin"

# TUN packet corpus
echo "Generating TUN packet corpus..."
# Valid IPv4 packet
printf '\x00\x02\x00\x00' > "$CORPUS_DIR/fuzz_tun_packet/valid_ipv4.bin"
printf '\x45\x00\x00\x14\x00\x00\x40\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01' >> "$CORPUS_DIR/fuzz_tun_packet/valid_ipv4.bin"

# Valid IPv6 packet
printf '\x00\x0a\x00\x00' > "$CORPUS_DIR/fuzz_tun_packet/valid_ipv6.bin"
printf '\x60\x00\x00\x00\x00\x08\x3a\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' >> "$CORPUS_DIR/fuzz_tun_packet/valid_ipv6.bin"

# Edge cases
echo -n "" > "$CORPUS_DIR/fuzz_tun_packet/empty.bin"
head -c 1 /dev/urandom > "$CORPUS_DIR/fuzz_tun_packet/single_byte.bin"
head -c 1000 /dev/urandom > "$CORPUS_DIR/fuzz_tun_packet/large.bin"

# Mixed protocol corpus
echo "Generating Mixed protocol corpus..."
# TLS handshake
printf '\x16\x03\x01\x00\x04' > "$CORPUS_DIR/fuzz_mixed_protocol/tls_handshake.bin"

# SOCKS5
printf '\x05\x01\x00' > "$CORPUS_DIR/fuzz_mixed_protocol/socks5.bin"

# HTTP
printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$CORPUS_DIR/fuzz_mixed_protocol/http.bin"

# Edge cases
echo -n "" > "$CORPUS_DIR/fuzz_mixed_protocol/empty.bin"
head -c 1 /dev/urandom > "$CORPUS_DIR/fuzz_mixed_protocol/single_byte.bin"
head -c 1000 /dev/urandom > "$CORPUS_DIR/fuzz_mixed_protocol/large.bin"

echo "Fuzz corpus generation complete!"
echo "Generated corpus files:"
find "$CORPUS_DIR" -type f | wc -l
echo "Total corpus size:"
du -sh "$CORPUS_DIR"
