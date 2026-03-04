#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_JSON="${ROOT}/reports/security/tls_fingerprint_baseline.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

if [[ "$#" -gt 0 ]]; then
  PROFILES=("$@")
else
  PROFILES=("chrome" "firefox" "randomized")
fi

mkdir -p "${ROOT}/reports/security"

echo "[tls-fp-baseline] collecting Rust ClientHello samples..."
for profile in "${PROFILES[@]}"; do
  (
    cd "${ROOT}"
    cargo run --quiet -p sb-tls --example tls_clienthello_probe -- "${profile}"
  ) > "${TMP_DIR}/rust_${profile}.json"
done

GO_PROBE="${TMP_DIR}/go_tls_clienthello_probe.go"
cat > "${GO_PROBE}" <<'GOEOF'
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
)

type probeOutput struct {
	Engine          string `json:"engine"`
	ProfileRequested string `json:"profile_requested"`
	ProfileEffective string `json:"profile_effective"`
	ClientHelloB64  string `json:"client_hello_b64"`
	RecordLen       int    `json:"record_len"`
}

func mapProfile(name string) (utls.ClientHelloID, string, error) {
	switch strings.ToLower(name) {
	case "chrome":
		return utls.HelloChrome_Auto, "HelloChrome_Auto", nil
	case "firefox":
		return utls.HelloFirefox_Auto, "HelloFirefox_Auto", nil
	case "randomized":
		id := utls.HelloRandomized
		seed := utls.PRNGSeed{}
		copy(seed[:], []byte("l20-randomized-seed-20260305-fixed"))
		id.Seed = &seed
		weights := utls.DefaultWeights
		weights.TLSVersMax_Set_VersionTLS13 = 1
		id.Weights = &weights
		return id, "HelloRandomized(seed:l20)", nil
	default:
		return utls.ClientHelloID{}, "", fmt.Errorf("unsupported profile: %s", name)
	}
}

func capture(id utls.ClientHelloID) ([]byte, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	type result struct {
		record []byte
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			ch <- result{err: err}
			return
		}
		n := int(header[3])<<8 | int(header[4])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			ch <- result{err: err}
			return
		}
		record := append(header, body...)
		ch <- result{record: record}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	cfg := &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	uconn := utls.UClient(conn, cfg, id)
	_ = uconn.Handshake()

	select {
	case r := <-ch:
		return r.record, r.err
	case <-time.After(4 * time.Second):
		return nil, errors.New("capture timeout")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run go_tls_clienthello_probe.go <profile>")
		os.Exit(2)
	}
	profile := os.Args[1]
	id, effective, err := mapProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	record, err := capture(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture failed for %s: %v\n", profile, err)
		os.Exit(1)
	}

	out := probeOutput{
		Engine:           "go",
		ProfileRequested: profile,
		ProfileEffective: effective,
		ClientHelloB64:   base64.StdEncoding.EncodeToString(record),
		RecordLen:        len(record),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}
GOEOF

echo "[tls-fp-baseline] collecting Go ClientHello samples..."
for profile in "${PROFILES[@]}"; do
  (
    cd "${ROOT}/go_fork_source/sing-box-1.12.14"
    go run "${GO_PROBE}" "${profile}"
  ) > "${TMP_DIR}/go_${profile}.json"
done

python3 - "${OUT_JSON}" "${TMP_DIR}" "${PROFILES[@]}" <<'PYEOF'
from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

logging.getLogger().setLevel(logging.CRITICAL)
import hashlib


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A


def parse_ja3(record: bytes) -> dict[str, Any]:
    if len(record) < 5 or record[0] != 0x16:
        raise ValueError("not a TLS handshake record")
    rec_len = int.from_bytes(record[3:5], "big")
    hs = record[5 : 5 + rec_len]
    if len(hs) < 4 or hs[0] != 0x01:
        raise ValueError("not a ClientHello")
    pos = 4
    version = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2 + 32
    sid_len = hs[pos]
    pos += 1 + sid_len
    c_len = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2
    ciphers: list[int] = []
    for i in range(pos, pos + c_len, 2):
        if i + 2 > len(hs):
            break
        val = int.from_bytes(hs[i : i + 2], "big")
        if not is_grease(val):
            ciphers.append(val)
    pos += c_len
    comp_len = hs[pos]
    pos += 1 + comp_len
    ext_total = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2
    ext_end = pos + ext_total

    exts: list[int] = []
    groups: list[int] = []
    point_formats: list[int] = []
    while pos + 4 <= ext_end and pos + 4 <= len(hs):
        et = int.from_bytes(hs[pos : pos + 2], "big")
        el = int.from_bytes(hs[pos + 2 : pos + 4], "big")
        pos += 4
        body = hs[pos : pos + el]
        if not is_grease(et):
            exts.append(et)
            if et == 10 and len(body) >= 2:
                glen = int.from_bytes(body[0:2], "big")
                gp = 2
                while gp + 2 <= min(len(body), 2 + glen):
                    g = int.from_bytes(body[gp : gp + 2], "big")
                    if not is_grease(g):
                        groups.append(g)
                    gp += 2
            if et == 11 and len(body) >= 1:
                plen = body[0]
                point_formats.extend(body[1 : 1 + plen])
        pos += el

    ja3_str = "{},{},{},{},{}".format(
        version,
        "-".join(map(str, ciphers)),
        "-".join(map(str, exts)),
        "-".join(map(str, groups)),
        "-".join(map(str, point_formats)),
    )
    return {
        "version": version,
        "cipher_suites": ciphers,
        "extensions": exts,
        "supported_groups": groups,
        "ec_point_formats": point_formats,
        "ja3_string": ja3_str,
        "ja3_hash": hashlib.md5(ja3_str.encode("utf-8")).hexdigest(),
    }


def load_probe(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    raw = base64.b64decode(data["client_hello_b64"])
    parsed = parse_ja3(raw)
    return {
        "engine": data["engine"],
        "profile_requested": data["profile_requested"],
        "profile_effective": data["profile_effective"],
        "record_len": data["record_len"],
        "extension_order_summary": [f"0x{ext:04x}" for ext in parsed["extensions"][:16]],
        **parsed,
    }


out_json = Path(sys.argv[1])
tmp_dir = Path(sys.argv[2])
profiles = sys.argv[3:]
results: list[dict[str, Any]] = []
ja3_match_count = 0
order_match_count = 0

for profile in profiles:
    go_probe = load_probe(tmp_dir / f"go_{profile}.json")
    rust_probe = load_probe(tmp_dir / f"rust_{profile}.json")
    cmp = {
        "ja3_hash_match": go_probe["ja3_hash"] == rust_probe["ja3_hash"],
        "ja3_string_match": go_probe["ja3_string"] == rust_probe["ja3_string"],
        "extension_order_match": go_probe["extensions"] == rust_probe["extensions"],
        "cipher_suite_count_delta": len(rust_probe["cipher_suites"]) - len(go_probe["cipher_suites"]),
    }
    if cmp["ja3_hash_match"]:
        ja3_match_count += 1
    if cmp["extension_order_match"]:
        order_match_count += 1

    results.append(
        {
            "profile": profile,
            "go": go_probe,
            "rust": rust_probe,
            "comparison": cmp,
        }
    )

doc = {
    "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "workpackage": "L20.1.1",
    "method": "loopback_clienthello_capture",
    "profiles": results,
    "summary": {
        "profile_count": len(profiles),
        "ja3_hash_match_count": ja3_match_count,
        "extension_order_match_count": order_match_count,
    },
}

out_json.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"[tls-fp-baseline] wrote {out_json}")
PYEOF

echo "[tls-fp-baseline] done"
