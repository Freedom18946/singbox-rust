#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_SRC="${ROOT}/go_fork_source/sing-box-1.12.14"

SERVER_NAME="${SB_REALITY_SERVER_NAME:-www.apple.com}"
FINGERPRINT="${SB_REALITY_FINGERPRINT:-chrome}"
PUBLIC_KEY="${SB_REALITY_PUBLIC_KEY:-ERERERERERERERERERERERERERERERERERERERERERE}"
SHORT_ID="${SB_REALITY_SHORT_ID:-01ab}"

TMP_BASE="$(mktemp -p "${GO_SRC}" tmp-reality-socket-trace-XXXXXX)"
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
	"net"
	"os"
	"sync"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type traceChunk struct {
	Index         int    `json:"index"`
	Len           int    `json:"len"`
	OffsetMicros  uint64 `json:"offset_micros"`
	RecordType    string `json:"record_type,omitempty"`
	RecordVersion string `json:"record_version,omitempty"`
	Hex           string `json:"hex"`
}

type traceEvent struct {
	OffsetMicros uint64 `json:"offset_micros"`
	Kind         string `json:"kind"`
	Len          *int   `json:"len,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type traceOutput struct {
	ListenerAddr                 string       `json:"listener_addr"`
	ClientError                  string       `json:"client_error,omitempty"`
	ClientConnectElapsedMicros   *uint64      `json:"client_connect_elapsed_micros,omitempty"`
	ClientHandshakeElapsedMicros *uint64      `json:"client_handshake_elapsed_micros,omitempty"`
	ClientFirstWriteAfterConnectMicros *uint64 `json:"client_first_write_after_connect_micros,omitempty"`
	ClientFirstReadAfterConnectMicros  *uint64 `json:"client_first_read_after_connect_micros,omitempty"`
	ClientEventTrace             []traceEvent `json:"client_event_trace"`
	ServerReadCount              int          `json:"server_read_count"`
	ServerTotalLen               int          `json:"server_total_len"`
	ServerFirstReadDelayMicros   *uint64      `json:"server_first_read_delay_micros,omitempty"`
	ServerTraceElapsedMicros     uint64       `json:"server_trace_elapsed_micros"`
	ServerFirstReadToEndMicros   *uint64      `json:"server_first_read_to_end_micros,omitempty"`
	ServerEndReason              string       `json:"server_end_reason"`
	ServerTimedOutWaitingForMore bool         `json:"server_timed_out_waiting_for_more"`
	ServerChunks                 []traceChunk `json:"server_chunks"`
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

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	traceCh := make(chan traceOutput, 1)
	errCh := make(chan error, 1)
	readyCh := make(chan struct{}, 1)
	go func() {
		readyCh <- struct{}{}
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		acceptAt := time.Now()
		buf := make([]byte, 4096)
		var total []byte
		var chunks []traceChunk
		var firstDelay *uint64
		timedOutWaitingForMore := false
		endReason := "eof"

		for {
			wait := 500 * time.Millisecond
			if len(chunks) > 0 {
				wait = 25 * time.Millisecond
			}
			if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
				errCh <- err
				return
			}
			n, err := conn.Read(buf)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				timedOutWaitingForMore = len(chunks) > 0
				endReason = "timeout"
				break
			}
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				errCh <- err
				return
			}
			if firstDelay == nil {
				delay := uint64(time.Since(acceptAt).Microseconds())
				firstDelay = &delay
			}
			payload := append([]byte(nil), buf[:n]...)
			item := traceChunk{
				Index:        len(chunks),
				Len:          len(payload),
				OffsetMicros: uint64(time.Since(acceptAt).Microseconds()),
				Hex:          hex.EncodeToString(payload),
			}
			if len(payload) >= 1 {
				item.RecordType = fmt.Sprintf("0x%02x", payload[0])
			}
			if len(payload) >= 3 {
				item.RecordVersion = fmt.Sprintf("0x%02x%02x", payload[1], payload[2])
			}
			chunks = append(chunks, item)
			total = append(total, payload...)
		}

		traceElapsed := uint64(time.Since(acceptAt).Microseconds())
		var firstReadToEnd *uint64
		if firstDelay != nil {
			value := traceElapsed - *firstDelay
			firstReadToEnd = &value
		}
		traceCh <- traceOutput{
			ListenerAddr:                 listener.Addr().String(),
			ServerReadCount:              len(chunks),
			ServerTotalLen:               len(total),
			ServerFirstReadDelayMicros:   firstDelay,
			ServerTraceElapsedMicros:     traceElapsed,
			ServerFirstReadToEndMicros:   firstReadToEnd,
			ServerEndReason:              endReason,
			ServerTimedOutWaitingForMore: timedOutWaitingForMore,
			ServerChunks:                 chunks,
		}
	}()
	<-readyCh

	dialStartedAt := time.Now()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		panic(err)
	}
	connectElapsed := uint64(time.Since(dialStartedAt).Microseconds())
	traced := newTracedConn(conn)
	clientStartedAt := time.Now()
	_, clientErr := cfg.ClientHandshake(context.Background(), traced)
	clientElapsed := uint64(time.Since(clientStartedAt).Microseconds())

	var output traceOutput
	select {
	case traceErr := <-errCh:
		panic(traceErr)
	case output = <-traceCh:
	}
	if clientErr != nil {
		output.ClientError = clientErr.Error()
	}
	output.ClientConnectElapsedMicros = &connectElapsed
	output.ClientHandshakeElapsedMicros = &clientElapsed
	output.ClientEventTrace, output.ClientFirstWriteAfterConnectMicros, output.ClientFirstReadAfterConnectMicros = traced.snapshot()

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
