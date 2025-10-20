#!/bin/bash
# Advanced corpus generation script for singbox-rust fuzz testing

set -e

FUZZ_DIR="$(dirname "$0")/.."
CORPUS_DIR="$FUZZ_DIR/corpus"
SEEDS_DIR="$CORPUS_DIR/seeds"
GENERATED_DIR="$CORPUS_DIR/generated"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Advanced Corpus Generation for singbox-rust${NC}"
echo "=================================================="

# Create corpus directories
mkdir -p "$SEEDS_DIR"/{vmess,vless,trojan,shadowsocks,hysteria,tuic,socks5,http,tun,mixed,config}
mkdir -p "$GENERATED_DIR"/{valid,malformed,edge_cases}

# Function to generate protocol-specific corpus
generate_protocol_corpus() {
    local protocol="$1"
    local target_dir="$SEEDS_DIR/$protocol"
    
    echo -e "${YELLOW}📦 Generating $protocol corpus...${NC}"
    
    case "$protocol" in
        "vmess")
            # Valid VMess header
            printf '\x01' > "$target_dir/valid_header.bin"
            head -c 8 /dev/urandom >> "$target_dir/valid_header.bin"
            head -c 16 /dev/urandom >> "$target_dir/valid_header.bin"
            
            # VMess request with different address types
            printf '\x01' > "$target_dir/valid_ipv4.bin"
            head -c 8 /dev/urandom >> "$target_dir/valid_ipv4.bin"
            head -c 16 /dev/urandom >> "$target_dir/valid_ipv4.bin"
            printf '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x7f\x00\x00\x01\x1f\x90' >> "$target_dir/valid_ipv4.bin"
            ;;
            
        "vless")
            # Valid VLESS request
            printf '\x01' > "$target_dir/valid.bin"
            head -c 16 /dev/urandom >> "$target_dir/valid.bin"
            printf '\x00\x01\x01\x7f\x00\x00\x01\x1f\x90' >> "$target_dir/valid.bin"
            ;;
            
        "trojan")
            # Valid Trojan password hash
            printf 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890' > "$target_dir/valid_hash.bin"
            printf '\r\n\x01\x01\x7f\x00\x00\x01\x1f\x90\r\n' >> "$target_dir/valid_hash.bin"
            ;;
            
        "shadowsocks")
            # Valid AEAD packet
            head -c 16 /dev/urandom > "$target_dir/valid_aead.bin"
            head -c 100 /dev/urandom >> "$target_dir/valid_aead.bin"
            head -c 16 /dev/urandom >> "$target_dir/valid_aead.bin"
            
            # Address encoding
            printf '\x01\x7f\x00\x00\x01\x1f\x90' > "$target_dir/valid_address.bin"
            ;;
            
        "hysteria")
            # Hysteria v1 handshake
            printf '\x00\x01\x00\x08' > "$target_dir/v1_handshake.bin"
            head -c 8 /dev/urandom >> "$target_dir/v1_handshake.bin"
            
            # Hysteria v2 handshake
            printf '\x00\x02\x00\x10' > "$target_dir/v2_handshake.bin"
            head -c 16 /dev/urandom >> "$target_dir/v2_handshake.bin"
            ;;
            
        "tuic")
            # TUIC handshake
            printf '\x05\x00\x00\x10' > "$target_dir/handshake.bin"
            head -c 16 /dev/urandom >> "$target_dir/handshake.bin"
            ;;
            
        "socks5")
            # SOCKS5 method negotiation
            printf '\x05\x01\x00' > "$target_dir/method_negotiation.bin"
            
            # SOCKS5 request
            printf '\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90' > "$target_dir/connect_request.bin"
            ;;
            
        "http")
            # HTTP CONNECT request
            printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' > "$target_dir/connect.bin"
            
            # HTTP GET request
            printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$target_dir/get.bin"
            ;;
            
        "tun")
            # IPv4 packet
            printf '\x00\x02\x00\x00' > "$target_dir/ipv4.bin"
            printf '\x45\x00\x00\x14\x00\x00\x40\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01' >> "$target_dir/ipv4.bin"
            
            # IPv6 packet
            printf '\x00\x0a\x00\x00' > "$target_dir/ipv6.bin"
            printf '\x60\x00\x00\x00\x00\x08\x3a\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' >> "$target_dir/ipv6.bin"
            ;;
            
        "mixed")
            # TLS handshake
            printf '\x16\x03\x01\x00\x04' > "$target_dir/tls.bin"
            
            # SOCKS5
            printf '\x05\x01\x00' > "$target_dir/socks5.bin"
            
            # HTTP
            printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$target_dir/http.bin"
            ;;
            
        "config")
            # JSON config
            printf '{"log":{"level":"info"},"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}],"outbounds":[{"type":"direct"}]}' > "$target_dir/valid.json"
            
            # YAML config
            printf 'log:\n  level: info\ninbounds:\n  - type: socks\n    listen: 127.0.0.1\n    port: 1080\noutbounds:\n  - type: direct\n' > "$target_dir/valid.yaml"
            ;;
    esac
    
    # Generate edge cases
    echo -n "" > "$target_dir/empty.bin"
    head -c 1 /dev/urandom > "$target_dir/single_byte.bin"
    head -c 1000 /dev/urandom > "$target_dir/large.bin"
    head -c 10000 /dev/urandom > "$target_dir/very_large.bin"
    
    echo -e "${GREEN}✅ $protocol corpus generated${NC}"
}

# Generate corpus for all protocols
for protocol in vmess vless trojan shadowsocks hysteria tuic socks5 http tun mixed config; do
    generate_protocol_corpus "$protocol"
done

# Generate malformed corpus
echo -e "${YELLOW}🔧 Generating malformed corpus...${NC}"
MALFORMED_DIR="$GENERATED_DIR/malformed"

# Malformed JSON
printf '{"log":{"level":' > "$MALFORMED_DIR/incomplete_json.bin"
printf '{"log":{"level":null' > "$MALFORMED_DIR/invalid_json.bin"

# Malformed binary protocols
printf '\x00' > "$MALFORMED_DIR/invalid_version.bin"
printf '\x05\x01' > "$MALFORMED_DIR/incomplete_socks5.bin"

# Malformed HTTP
printf 'CONNECT' > "$MALFORMED_DIR/incomplete_http.bin"
printf 'INVALID / HTTP/1.1\r\n\r\n' > "$MALFORMED_DIR/invalid_method.bin"

echo -e "${GREEN}✅ Malformed corpus generated${NC}"

# Generate edge cases
echo -e "${YELLOW}🎯 Generating edge cases...${NC}"
EDGE_DIR="$GENERATED_DIR/edge_cases"

# Very large inputs
head -c 1048576 /dev/urandom > "$EDGE_DIR/1mb_random.bin"
head -c 10485760 /dev/urandom > "$EDGE_DIR/10mb_random.bin"

# All zeros
dd if=/dev/zero bs=1024 count=1 > "$EDGE_DIR/all_zeros.bin" 2>/dev/null

# All ones
dd if=/dev/zero bs=1024 count=1 | tr '\000' '\377' > "$EDGE_DIR/all_ones.bin" 2>/dev/null

# Repeated patterns
printf 'A%.0s' {1..1000} > "$EDGE_DIR/repeated_A.bin"
printf 'AB%.0s' {1..500} > "$EDGE_DIR/repeated_AB.bin"

echo -e "${GREEN}✅ Edge cases generated${NC}"

# Generate statistics
echo -e "${BLUE}📊 Corpus Statistics${NC}"
echo "=================="
echo "Total files generated: $(find "$CORPUS_DIR" -type f | wc -l)"
echo "Total size: $(du -sh "$CORPUS_DIR" | cut -f1)"
echo ""
echo "By protocol:"
for protocol in vmess vless trojan shadowsocks hysteria tuic socks5 http tun mixed config; do
    count=$(find "$SEEDS_DIR/$protocol" -type f | wc -l)
    size=$(du -sh "$SEEDS_DIR/$protocol" 2>/dev/null | cut -f1 || echo "0B")
    echo "  $protocol: $count files ($size)"
done

echo ""
echo -e "${GREEN}🎉 Corpus generation complete!${NC}"
echo "Generated corpus is ready for fuzz testing."
echo ""
echo "Usage:"
echo "  make -f Makefile.fuzz fuzz-corpus    # Regenerate corpus"
echo "  make -f Makefile.fuzz fuzz-all       # Run all fuzz tests"
echo "  make -f Makefile.fuzz fuzz-quick     # Quick smoke test"
