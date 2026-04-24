#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_SRC="${ROOT}/go_fork_source/sing-box-1.12.14"

SERVER_NAME="${SB_REALITY_SERVER_NAME:-www.apple.com}"
FINGERPRINT="${SB_REALITY_FINGERPRINT:-chrome}"
PUBLIC_KEY="${SB_REALITY_PUBLIC_KEY:-ERERERERERERERERERERERERERERERERERERERERERE}"
SHORT_ID="${SB_REALITY_SHORT_ID:-01ab}"
TRACE_ADDR="${SB_REALITY_TRACE_ADDR:-127.0.0.1:443}"

TMP_BASE="$(mktemp -p "${GO_SRC}" tmp-reality-remote-socket-trace-XXXXXX)"
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
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type traceEvent struct {
	OffsetMicros uint64 `json:"offset_micros"`
	Kind         string `json:"kind"`
	Len          *int   `json:"len,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type traceOutput struct {
	RemoteAddr                    string       `json:"remote_addr"`
	ClientError                   string       `json:"client_error,omitempty"`
	ClientConnectElapsedMicros    *uint64      `json:"client_connect_elapsed_micros,omitempty"`
	ClientHandshakeElapsedMicros  *uint64      `json:"client_handshake_elapsed_micros,omitempty"`
	ClientFirstWriteAfterConnectMicros *uint64 `json:"client_first_write_after_connect_micros,omitempty"`
	ClientFirstReadAfterConnectMicros  *uint64 `json:"client_first_read_after_connect_micros,omitempty"`
	ClientEventTrace              []traceEvent `json:"client_event_trace"`
}

type tracedConn struct {
	net.Conn
	startedAt  time.Time
	mu         sync.Mutex
	events     []traceEvent
	firstWrite *uint64
	firstRead  *uint64
}

func newTracedConn(inner net.Conn) *tracedConn {
	return &tracedConn{
		Conn:      inner,
		startedAt: time.Now(),
	}
}

func (c *tracedConn) record(kind string, n *int, detail string) {
	offset := uint64(time.Since(c.startedAt).Microseconds())
	c.mu.Lock()
	defer c.mu.Unlock()
	if kind == "write" && c.firstWrite == nil {
		value := offset
		c.firstWrite = &value
	}
	if (kind == "read" || kind == "read_eof") && c.firstRead == nil {
		value := offset
		c.firstRead = &value
	}
	c.events = append(c.events, traceEvent{
		OffsetMicros: offset,
		Kind:         kind,
		Len:          n,
		Detail:       detail,
	})
}

func (c *tracedConn) snapshot() ([]traceEvent, *uint64, *uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := append([]traceEvent(nil), c.events...)
	return events, c.firstWrite, c.firstRead
}

func (c *tracedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		size := n
		c.record("write", &size, "")
	}
	if err != nil {
		c.record("write_error", nil, err.Error())
	}
	return n, err
}

func (c *tracedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		size := n
		c.record("read", &size, "")
	}
	if err != nil {
		kind := "read_error"
		if err.Error() == "EOF" {
			kind = "read_eof"
		}
		c.record(kind, nil, err.Error())
	}
	return n, err
}

func (c *tracedConn) Close() error {
	err := c.Conn.Close()
	if err != nil {
		c.record("close_error", nil, err.Error())
		return err
	}
	c.record("close", nil, "")
	return nil
}

func (c *tracedConn) SetDeadline(t time.Time) error {
	err := c.Conn.SetDeadline(t)
	if err != nil {
		c.record("set_deadline_error", nil, err.Error())
		return err
	}
	c.record("set_deadline", nil, "")
	return nil
}

func (c *tracedConn) SetReadDeadline(t time.Time) error {
	err := c.Conn.SetReadDeadline(t)
	if err != nil {
		c.record("set_read_deadline_error", nil, err.Error())
		return err
	}
	c.record("set_read_deadline", nil, "")
	return nil
}

func (c *tracedConn) SetWriteDeadline(t time.Time) error {
	err := c.Conn.SetWriteDeadline(t)
	if err != nil {
		c.record("set_write_deadline_error", nil, err.Error())
		return err
	}
	c.record("set_write_deadline", nil, "")
	return nil
}

func main() {
	serverName := os.Getenv("SB_REALITY_SERVER_NAME")
	fingerprint := os.Getenv("SB_REALITY_FINGERPRINT")
	publicKey := os.Getenv("SB_REALITY_PUBLIC_KEY")
	shortID := os.Getenv("SB_REALITY_SHORT_ID")
	traceAddr := os.Getenv("SB_REALITY_TRACE_ADDR")

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

	dialStartedAt := time.Now()
	conn, err := net.Dial("tcp", traceAddr)
	if err != nil {
		panic(err)
	}
	connectElapsed := uint64(time.Since(dialStartedAt).Microseconds())

	traced := newTracedConn(conn)
	clientStartedAt := time.Now()
	_, clientErr := cfg.ClientHandshake(context.Background(), traced)
	clientElapsed := uint64(time.Since(clientStartedAt).Microseconds())

	events, firstWrite, firstRead := traced.snapshot()
	output := traceOutput{
		RemoteAddr:                    traceAddr,
		ClientConnectElapsedMicros:    &connectElapsed,
		ClientHandshakeElapsedMicros:  &clientElapsed,
		ClientFirstWriteAfterConnectMicros: firstWrite,
		ClientFirstReadAfterConnectMicros:  firstRead,
		ClientEventTrace:              events,
	}
	if clientErr != nil {
		output.ClientError = clientErr.Error()
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
  SB_REALITY_TRACE_ADDR="${TRACE_ADDR}" \
  go run -tags with_utls "$(basename "${TMP_GO}")"
)
