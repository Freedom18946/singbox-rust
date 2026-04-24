#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    port = listener.getsockname()[1]
    print(port, flush=True)

    conn, addr = listener.accept()
    accept_at = time.monotonic_ns()
    chunks = []
    total_len = 0
    first_read_delay_micros = None
    timed_out_waiting_for_more = False
    end_reason = "eof"

    try:
        while True:
            wait = 0.5 if not chunks else 0.025
            conn.settimeout(wait)
            try:
                payload = conn.recv(4096)
            except socket.timeout:
                timed_out_waiting_for_more = bool(chunks)
                end_reason = "timeout"
                break

            if not payload:
                break

            now_us = (time.monotonic_ns() - accept_at) // 1000
            if first_read_delay_micros is None:
                first_read_delay_micros = now_us
            chunks.append(
                {
                    "index": len(chunks),
                    "len": len(payload),
                    "offset_micros": now_us,
                    "record_type": f"0x{payload[0]:02x}" if payload else None,
                    "record_version": f"0x{payload[1]:02x}{payload[2]:02x}"
                    if len(payload) >= 3
                    else None,
                    "hex": payload.hex(),
                }
            )
            total_len += len(payload)
    finally:
        conn.close()
        listener.close()

    trace_elapsed_us = (time.monotonic_ns() - accept_at) // 1000
    result = {
        "listener_addr": f"127.0.0.1:{port}",
        "peer_addr": f"{addr[0]}:{addr[1]}",
        "server_read_count": len(chunks),
        "server_total_len": total_len,
        "server_first_read_delay_micros": first_read_delay_micros,
        "server_trace_elapsed_micros": trace_elapsed_us,
        "server_first_read_to_end_micros": None
        if first_read_delay_micros is None
        else max(trace_elapsed_us - first_read_delay_micros, 0),
        "server_end_reason": end_reason,
        "server_timed_out_waiting_for_more": timed_out_waiting_for_more,
        "server_chunks": chunks,
    }

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
