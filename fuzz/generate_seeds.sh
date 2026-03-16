#!/usr/bin/env bash
set -euo pipefail

SEEDS="$(cd "$(dirname "$0")" && pwd)/corpus/seeds"

# ========== sniff_tls (5 seeds) ==========
mkdir -p "$SEEDS/sniff_tls"

# TLS 1.2 ClientHello with SNI "example.com"
printf '\x16\x03\x01\x00\x43\x01\x00\x00\x3f\x03\x03' > "$SEEDS/sniff_tls/tls12_sni.bin"
printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' >> "$SEEDS/sniff_tls/tls12_sni.bin"
printf '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' >> "$SEEDS/sniff_tls/tls12_sni.bin"
printf '\x00\x00\x02\x00\x2f\x01\x00' >> "$SEEDS/sniff_tls/tls12_sni.bin"
printf '\x00\x14\x00\x00\x00\x10\x00\x0e\x00\x00\x0b' >> "$SEEDS/sniff_tls/tls12_sni.bin"
printf 'example.com' >> "$SEEDS/sniff_tls/tls12_sni.bin"

# TLS 1.3 ClientHello with SNI + supported_versions ext
printf '\x16\x03\x01\x00\x4a\x01\x00\x00\x46\x03\x03' > "$SEEDS/sniff_tls/tls13_sni.bin"
printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' >> "$SEEDS/sniff_tls/tls13_sni.bin"
printf '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' >> "$SEEDS/sniff_tls/tls13_sni.bin"
printf '\x00\x00\x02\x13\x01\x01\x00' >> "$SEEDS/sniff_tls/tls13_sni.bin"
printf '\x00\x1b\x00\x00\x00\x10\x00\x0e\x00\x00\x0b' >> "$SEEDS/sniff_tls/tls13_sni.bin"
printf 'example.com' >> "$SEEDS/sniff_tls/tls13_sni.bin"
printf '\x00\x2b\x00\x03\x02\x03\x04' >> "$SEEDS/sniff_tls/tls13_sni.bin"

# No SNI — ClientHello with no extensions
printf '\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03' > "$SEEDS/sniff_tls/no_sni.bin"
printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' >> "$SEEDS/sniff_tls/no_sni.bin"
printf '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' >> "$SEEDS/sniff_tls/no_sni.bin"
printf '\x00\x00\x02\x00\x2f\x01\x00\x00\x00' >> "$SEEDS/sniff_tls/no_sni.bin"

# Truncated — first 10 bytes of a valid TLS record
printf '\x16\x03\x01\x00\x43\x01\x00\x00\x3f\x03' > "$SEEDS/sniff_tls/truncated.bin"

# Empty
> "$SEEDS/sniff_tls/empty.bin"

# ========== sniff_quic (6 seeds) ==========
mkdir -p "$SEEDS/sniff_quic"

# QUIC v1 Initial long header (0xC0 = form=1,fixed=1,type=00,reserved=00,pn_len=00)
# Version: 00000001, DCID len: 08, DCID: 0102030405060708, SCID len: 00
# Token len: 00 (varint), Length: 0x4100 (varint = 256), PN: 00, then 255 zero payload
printf '\xc0\x00\x00\x00\x01\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x41\x00\x00' > "$SEEDS/sniff_quic/v1_initial.bin"
dd if=/dev/zero bs=1 count=255 >> "$SEEDS/sniff_quic/v1_initial.bin" 2>/dev/null

# QUIC v2 Initial (version 0x6b3343cf, type=01 in v2 → first byte 0xD0)
printf '\xd0\x6b\x33\x43\xcf\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x41\x00\x00' > "$SEEDS/sniff_quic/v2_initial.bin"
dd if=/dev/zero bs=1 count=255 >> "$SEEDS/sniff_quic/v2_initial.bin" 2>/dev/null

# Draft-29 (version 0xff00001d)
printf '\xc0\xff\x00\x00\x1d\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x41\x00\x00' > "$SEEDS/sniff_quic/draft29_initial.bin"
dd if=/dev/zero bs=1 count=255 >> "$SEEDS/sniff_quic/draft29_initial.bin" 2>/dev/null

# Short header (not Initial — should be detected but not parsed for SNI)
printf '\x40\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00' > "$SEEDS/sniff_quic/short_header.bin"

# Single byte
printf '\xc0' > "$SEEDS/sniff_quic/single_byte.bin"

# Empty
> "$SEEDS/sniff_quic/empty.bin"

# ========== sniff_stream (8 seeds) ==========
mkdir -p "$SEEDS/sniff_stream"

# SSH banner
printf 'SSH-2.0-OpenSSH_8.9\r\n' > "$SEEDS/sniff_stream/ssh_banner.bin"

# HTTP GET request
printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$SEEDS/sniff_stream/http_get.bin"

# TLS record prefix (reuse for stream sniff)
printf '\x16\x03\x01\x00\x43\x01\x00\x00\x3f\x03' > "$SEEDS/sniff_stream/tls_prefix.bin"

# STUN binding request: type=0x0001, length=0, magic=0x2112a442, txn_id(12 bytes)
printf '\x00\x01\x00\x00\x21\x12\xa4\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c' > "$SEEDS/sniff_stream/stun_binding.bin"

# BitTorrent handshake: 0x13 + "BitTorrent protocol"
printf '\x13BitTorrent protocol' > "$SEEDS/sniff_stream/bittorrent.bin"

# DTLS record: content_type=22(handshake), version=DTLS1.2(0xFEFD), epoch=0, seq=0, len=16
printf '\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10' > "$SEEDS/sniff_stream/dtls.bin"
dd if=/dev/zero bs=1 count=16 >> "$SEEDS/sniff_stream/dtls.bin" 2>/dev/null

# DNS query for example.com (A record)
printf '\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > "$SEEDS/sniff_stream/dns_query.bin"

# Empty
> "$SEEDS/sniff_stream/empty.bin"

# ========== sniff_http (6 seeds) ==========
mkdir -p "$SEEDS/sniff_http"

# GET with Host
printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > "$SEEDS/sniff_http/get_with_host.bin"

# CONNECT
printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' > "$SEEDS/sniff_http/connect.bin"

# POST with Host and Content-Length
printf 'POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n' > "$SEEDS/sniff_http/post.bin"

# No Host header
printf 'GET / HTTP/1.1\r\n\r\n' > "$SEEDS/sniff_http/no_host.bin"

# HTTP/1.0
printf 'GET / HTTP/1.0\r\nHost: legacy.example.com\r\n\r\n' > "$SEEDS/sniff_http/http10.bin"

# Empty
> "$SEEDS/sniff_http/empty.bin"

# ========== route_decide (6 seeds) ==========
mkdir -p "$SEEDS/route_decide"

# TLS prefix
printf '\x16\x03\x01\x00\x43\x01\x00\x00\x3f\x03' > "$SEEDS/route_decide/tls_prefix.bin"

# HTTP request
printf 'GET / HTTP/1.1\r\nHost: route-test.example.com\r\n\r\n' > "$SEEDS/route_decide/http.bin"

# SSH banner
printf 'SSH-2.0-OpenSSH_8.9\r\n' > "$SEEDS/route_decide/ssh.bin"

# DNS query
printf '\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > "$SEEDS/route_decide/dns.bin"

# QUIC v1 Initial
printf '\xc0\x00\x00\x00\x01\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x41\x00\x00' > "$SEEDS/route_decide/quic.bin"
dd if=/dev/zero bs=1 count=255 >> "$SEEDS/route_decide/quic.bin" 2>/dev/null

# Empty
> "$SEEDS/route_decide/empty.bin"

# ========== dns_message (7 seeds) ==========
mkdir -p "$SEEDS/dns_message"

# Standard A query for example.com
printf '\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > "$SEEDS/dns_message/query_a.bin"

# AAAA query
printf '\xcc\xdd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x1c\x00\x01' > "$SEEDS/dns_message/query_aaaa.bin"

# DNS response with A record (example.com -> 93.184.216.34)
printf '\xaa\xbb\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' > "$SEEDS/dns_message/response_a.bin"
printf '\x07example\x03com\x00\x00\x01\x00\x01' >> "$SEEDS/dns_message/response_a.bin"
printf '\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x5d\xb8\xd8\x22' >> "$SEEDS/dns_message/response_a.bin"

# DNS with EDNS0 OPT record
printf '\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01' > "$SEEDS/dns_message/edns0.bin"
printf '\x07example\x03com\x00\x00\x01\x00\x01' >> "$SEEDS/dns_message/edns0.bin"
# OPT: name=root(00), type=OPT(0029), udp=4096(1000), rcode=0, ver=0, flags=DO(8000), rdlen=0
printf '\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00' >> "$SEEDS/dns_message/edns0.bin"

# DNS with EDNS0 Client Subnet (ECS)
printf '\xee\xff\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01' > "$SEEDS/dns_message/edns0_ecs.bin"
printf '\x07example\x03com\x00\x00\x01\x00\x01' >> "$SEEDS/dns_message/edns0_ecs.bin"
# OPT with ECS option: code=0008, len=0007, family=IPv4(0001), src_prefix=24, scope=0, addr=c0a801
printf '\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x0b' >> "$SEEDS/dns_message/edns0_ecs.bin"
printf '\x00\x08\x00\x07\x00\x01\x18\x00\xc0\xa8\x01' >> "$SEEDS/dns_message/edns0_ecs.bin"

# NXDOMAIN response
printf '\xaa\xbb\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x0anotthere\x03com\x00\x00\x01\x00\x01' > "$SEEDS/dns_message/nxdomain.bin"

# Empty
> "$SEEDS/dns_message/empty.bin"

# ========== v2ray_api (6 seeds) ==========
mkdir -p "$SEEDS/v2ray_api"

printf '{"type":"StatsService","method":"GetStats","request":{"name":"user>>>test@example.com>>>traffic>>>uplink","reset":false}}' > "$SEEDS/v2ray_api/stats_request.json"

printf '{"type":"StatsService","method":"QueryStats","request":{"pattern":"","reset":false}}' > "$SEEDS/v2ray_api/query_stats.json"

printf '{}' > "$SEEDS/v2ray_api/empty_object.json"
printf '[]' > "$SEEDS/v2ray_api/empty_array.json"
> "$SEEDS/v2ray_api/empty.bin"
printf 'not json at all' > "$SEEDS/v2ray_api/invalid.bin"

# ========== http_connect (6 seeds) ==========
mkdir -p "$SEEDS/http_connect"

# SOCKS5-style IPv4 address block (atyp=1, ip=93.184.216.34, port=80)
printf '\x01\x5d\xb8\xd8\x22\x00\x50' > "$SEEDS/http_connect/addr_ipv4.bin"

# SOCKS5-style domain address block (atyp=3, len=11, "example.com", port=443)
printf '\x03\x0b' > "$SEEDS/http_connect/addr_domain.bin"
printf 'example.com' >> "$SEEDS/http_connect/addr_domain.bin"
printf '\x01\xbb' >> "$SEEDS/http_connect/addr_domain.bin"

# SOCKS5-style IPv6 address block (atyp=4, ::1, port=8080)
printf '\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f\x90' > "$SEEDS/http_connect/addr_ipv6.bin"

# Trojan-format request (56-byte hex hash + CRLF + cmd=1 + addr + CRLF)
printf '0123456789abcdef0123456789abcdef0123456789abcdef01234567\r\n\x01\x03\x0b' > "$SEEDS/http_connect/trojan_request.bin"
printf 'example.com' >> "$SEEDS/http_connect/trojan_request.bin"
printf '\x01\xbb\r\n' >> "$SEEDS/http_connect/trojan_request.bin"

# SOCKS5 UDP datagram (RSV=0000, FRAG=00, atyp=3, domain, port, payload)
printf '\x00\x00\x00\x03\x0b' > "$SEEDS/http_connect/socks5_udp.bin"
printf 'example.com' >> "$SEEDS/http_connect/socks5_udp.bin"
printf '\x00\x50hello' >> "$SEEDS/http_connect/socks5_udp.bin"

# Empty
> "$SEEDS/http_connect/empty.bin"

echo "All seed files created successfully."
