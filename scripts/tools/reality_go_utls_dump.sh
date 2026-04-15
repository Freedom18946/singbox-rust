#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_SRC="${ROOT}/go_fork_source/sing-box-1.12.14"

SERVER_NAME="${SB_REALITY_SERVER_NAME:-www.apple.com}"
FINGERPRINT="${SB_REALITY_FINGERPRINT:-chrome}"
PUBLIC_KEY="${SB_REALITY_PUBLIC_KEY:-ERERERERERERERERERERERERERERERERERERERERERE}"
SHORT_ID="${SB_REALITY_SHORT_ID:-01ab}"

TMP_GO="$(mktemp -p "${GO_SRC}" tmp-reality-probe-XXXX.go)"
cleanup() {
  rm -f "${TMP_GO}"
}
trap cleanup EXIT

cat >"${TMP_GO}" <<'EOF'
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type recordingConn struct {
	buf []byte
}

func (c *recordingConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error) { c.buf = append(c.buf, p...); return len(p), nil }
func (c *recordingConn) Close() error                { return nil }
func (c *recordingConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

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
		panic("expected handshake to stop after client hello capture")
	}
	if len(conn.buf) == 0 {
		panic("captured empty client hello")
	}

	fmt.Println(hex.EncodeToString(conn.buf))
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
