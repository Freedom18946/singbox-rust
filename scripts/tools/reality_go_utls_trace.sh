#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_SRC="${ROOT}/go_fork_source/sing-box-1.12.14"

SERVER_NAME="${SB_REALITY_SERVER_NAME:-www.apple.com}"
FINGERPRINT="${SB_REALITY_FINGERPRINT:-chrome}"
PUBLIC_KEY="${SB_REALITY_PUBLIC_KEY:-ERERERERERERERERERERERERERERERERERERERERERE}"
SHORT_ID="${SB_REALITY_SHORT_ID:-01ab}"

TMP_BASE="$(mktemp -p "${GO_SRC}" tmp-reality-trace-XXXXXX)"
TMP_GO="${TMP_BASE}.go"
mv "${TMP_BASE}" "${TMP_GO}"
cleanup() {
  rm -f "${TMP_GO}"
}
trap cleanup EXIT

cat >"${TMP_GO}" <<'EOF'
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type recordingConn struct {
	buf    []byte
	writes [][]byte
}

func (c *recordingConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error) {
	chunk := append([]byte(nil), p...)
	c.writes = append(c.writes, chunk)
	c.buf = append(c.buf, p...)
	return len(p), nil
}
func (c *recordingConn) Close() error                { return nil }
func (c *recordingConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

type writeChunk struct {
	Index         int    `json:"index"`
	Len           int    `json:"len"`
	RecordType    string `json:"record_type,omitempty"`
	RecordVersion string `json:"record_version,omitempty"`
	Hex           string `json:"hex"`
}

type traceOutput struct {
	WriteCount  int          `json:"write_count"`
	TotalLen    int          `json:"total_len"`
	Writes      []writeChunk `json:"writes"`
	CombinedHex string       `json:"combined_hex"`
}

func main() {
	serverName := os.Getenv("SB_REALITY_SERVER_NAME")
	fingerprint := os.Getenv("SB_REALITY_FINGERPRINT")
	publicKey := os.Getenv("SB_REALITY_PUBLIC_KEY")
	shortID := os.Getenv("SB_REALITY_SHORT_ID")

	cfg, err := sbtls.NewRealityClient(context.Background(), serverName, option.OutboundTLSOptions{
		ServerName: serverName,
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fingerprint,
		},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: publicKey,
			ShortID:   shortID,
		},
	})
	if err != nil {
		panic(err)
	}

	conn := &recordingConn{}
	_, err = cfg.ClientHandshake(context.Background(), conn)
	if err == nil {
		panic("expected handshake to stop after client write trace")
	}
	if len(conn.writes) == 0 {
		panic("captured empty client write trace")
	}

	chunks := make([]writeChunk, 0, len(conn.writes))
	for index, chunk := range conn.writes {
		item := writeChunk{
			Index: index,
			Len:   len(chunk),
			Hex:   hex.EncodeToString(chunk),
		}
		if len(chunk) >= 1 {
			item.RecordType = fmt.Sprintf("0x%02x", chunk[0])
		}
		if len(chunk) >= 3 {
			item.RecordVersion = fmt.Sprintf("0x%02x%02x", chunk[1], chunk[2])
		}
		chunks = append(chunks, item)
	}

	output := traceOutput{
		WriteCount:  len(chunks),
		TotalLen:    len(conn.buf),
		Writes:      chunks,
		CombinedHex: hex.EncodeToString(conn.buf),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		panic(err)
	}
}
EOF

(
  cd "${GO_SRC}"
  SB_REALITY_SERVER_NAME="${SERVER_NAME}" \
  SB_REALITY_FINGERPRINT="${FINGERPRINT}" \
  SB_REALITY_PUBLIC_KEY="${PUBLIC_KEY}" \
  SB_REALITY_SHORT_ID="${SHORT_ID}" \
  go run -tags with_utls "$(basename "${TMP_GO}")"
)
