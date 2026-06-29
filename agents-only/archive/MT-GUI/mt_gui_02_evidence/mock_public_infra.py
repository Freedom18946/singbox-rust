#!/usr/bin/env python3
# mock_public_infra.py -- MT-GUI-02 local public-internet simulator.
#
# Serves a small but representative slice of "public internet" on 127.0.0.1 so the
# GUI + dual-kernel acceptance can exercise the already-declared-done features
# without touching the real network.
#
# Exposed surface:
#   - HTTP  on --http-port     (default 18080)
#   - HTTPS on --https-port    (default 18443, self-signed cert under --cert-dir)
#   - WS    on --ws-port       (default 18081, raw RFC 6455 echo + hello frame)
#   - TCP   on --tcp-port      (default 18083, single-line echo)
#
# HTTP(S) endpoints:
#   GET /                       banner text
#   GET /get                    JSON echo of request {method, path, headers}
#   GET /headers                JSON echo of request headers
#   GET /status/{code}          return exact integer status
#   GET /redirect               single 302 -> /get
#   GET /redirect/{n}           chain of n 302 hops ending at /get
#   GET /chunked                Transfer-Encoding: chunked, 5 chunks
#   GET /large[?bytes=N]        fixed-length payload, default 1 MiB
#   GET /slow[?ms=N]            delay then 200
#   GET /sse                    Server-Sent Events, 5 ticks
#   GET /early-close            send headers with Content-Length but close before body
#   GET /reset                  close socket without writing anything
#   GET /sub/version            subscription metadata {version,etag}
#   GET /sub/clash.json         subscription body; ETag, Cache-Control, 304 on If-None-Match
#                               auth model: missing Authorization = 200, wrong Bearer = 401,
#                               correct Bearer = 200
#
# The handler is deliberately small and deterministic. All paths return identical
# bytes across runs so dual-kernel diff can focus on kernel behavior, not content.

import argparse
import hashlib
import json
import os
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

BANNER_BODY = b"MT-GUI-02 mock public OK\n"

SUB_CLASH_JSON = (
    b"{\n"
    b'  "log": {\n'
    b'    "level": "warn"\n'
    b"  },\n"
    b'  "outbounds": [\n'
    b"    {\n"
    b'      "default": "direct",\n'
    b'      "outbounds": [\n'
    b'        "direct"\n'
    b"      ],\n"
    b'      "tag": "remote",\n'
    b'      "type": "selector"\n'
    b"    },\n"
    b"    {\n"
    b'      "tag": "direct",\n'
    b'      "type": "direct"\n'
    b"    }\n"
    b"  ],\n"
    b'  "route": {\n'
    b'    "final": "remote",\n'
    b'    "rules": []\n'
    b"  }\n"
    b"}\n"
)
SUB_CLASH_ETAG = '"' + hashlib.sha256(SUB_CLASH_JSON).hexdigest()[:16] + '"'
SUB_BEARER = "mt-gui-02-sub-bearer"


def ensure_self_signed_cert(cert_dir: str) -> str:
    os.makedirs(cert_dir, exist_ok=True)
    pem_path = os.path.join(cert_dir, "server.pem")
    if os.path.exists(pem_path) and os.path.getsize(pem_path) > 0:
        return pem_path
    key_path = os.path.join(cert_dir, "_key.pem")
    crt_path = os.path.join(cert_dir, "_crt.pem")
    subj = "/CN=mock-public.local"
    ext = (
        "subjectAltName=DNS:mock-public.local,DNS:localhost,"
        "IP:127.0.0.1,IP:::1"
    )
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path,
            "-out",
            crt_path,
            "-days",
            "90",
            "-subj",
            subj,
            "-addext",
            ext,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(pem_path, "wb") as out:
        with open(key_path, "rb") as k:
            out.write(k.read())
        with open(crt_path, "rb") as c:
            out.write(c.read())
    os.remove(key_path)
    os.remove(crt_path)
    return pem_path


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, separators=(", ", ": ")).encode()


class MockHTTPHandler(BaseHTTPRequestHandler):
    server_version = "MockPublic/1.0"

    def log_message(self, fmt, *args):
        ts = time.strftime("[%H:%M:%S]")
        sys.stderr.write(
            "%s %s - %s\n" % (ts, self.address_string(), fmt % args)
        )

    def _echo_payload(self):
        return {
            "method": self.command,
            "path": self.path,
            "headers": {
                k: v
                for k, v in self.headers.items()
                if k.lower() in ("host", "user-agent", "accept", "authorization")
            },
        }

    def _write_simple(self, status: int, body: bytes, ctype: str = "text/plain",
                      extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _write_json(self, status: int, obj, extra_headers=None):
        self._write_simple(status, _json_bytes(obj), "application/json",
                           extra_headers=extra_headers)

    def do_GET(self):  # noqa: N802 (stdlib contract)
        path = self.path
        if path == "/":
            self._write_simple(200, BANNER_BODY)
            return
        if path == "/get":
            self._write_json(200, self._echo_payload())
            return
        if path == "/headers":
            self._write_json(
                200, {"headers": self._echo_payload()["headers"]}
            )
            return
        if path.startswith("/status/"):
            try:
                code = int(path.rsplit("/", 1)[1])
            except ValueError:
                code = 400
            body = ("status %d\n" % code).encode()
            self._write_simple(code, body)
            return
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/get")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/redirect/"):
            try:
                n = int(path.rsplit("/", 1)[1])
            except ValueError:
                self._write_simple(400, b"bad redirect\n")
                return
            next_loc = "/get" if n <= 1 else "/redirect/%d" % (n - 1)
            self.send_response(302)
            self.send_header("Location", next_loc)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for i in range(5):
                    payload = ("chunk-%d\n" % i).encode()
                    size = ("%x\r\n" % len(payload)).encode()
                    self.wfile.write(size)
                    self.wfile.write(payload)
                    self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path.startswith("/large"):
            # default 1 MiB, override via ?bytes=N
            size = 1048576
            if "?" in path:
                q = path.split("?", 1)[1]
                for part in q.split("&"):
                    if part.startswith("bytes="):
                        try:
                            size = int(part[6:])
                        except ValueError:
                            size = 1048576
            payload = b"A" * size
            self._write_simple(200, payload, "application/octet-stream")
            return
        if path.startswith("/slow"):
            ms = 500
            if "?" in path:
                q = path.split("?", 1)[1]
                for part in q.split("&"):
                    if part.startswith("ms="):
                        try:
                            ms = int(part[3:])
                        except ValueError:
                            ms = 500
            time.sleep(ms / 1000.0)
            body = ("slow %d ms\n" % ms).encode()
            self._write_simple(200, body)
            return
        if path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for i in range(5):
                    frame = (
                        "id: %d\nevent: tick\ndata: %s\n\n"
                        % (i, json.dumps({"i": i, "ts": time.time()}))
                    ).encode()
                    self.wfile.write(frame)
                    self.wfile.flush()
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if path == "/early-close":
            # send headers claiming 1024 bytes of body, then close without body.
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "1024")
                self.end_headers()
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            return
        if path == "/reset":
            # close the socket without any reply
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            return
        if path == "/sub/version":
            self._write_json(
                200,
                {"version": "1.0", "etag": SUB_CLASH_ETAG},
            )
            return
        if path == "/sub/clash.json":
            auth = self.headers.get("Authorization", "")
            # No auth header = public. If Authorization present it must equal
            # "Bearer {SUB_BEARER}", otherwise 401.
            if auth and auth != "Bearer " + SUB_BEARER:
                self._write_simple(401, b"unauthorized\n")
                return
            inm = self.headers.get("If-None-Match", "")
            if inm and inm.strip() == SUB_CLASH_ETAG:
                self.send_response(304)
                self.send_header("ETag", SUB_CLASH_ETAG)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._write_simple(
                200,
                SUB_CLASH_JSON,
                "application/json",
                extra_headers=[
                    ("ETag", SUB_CLASH_ETAG),
                    ("Cache-Control", "max-age=60, public"),
                ],
            )
            return
        self._write_simple(404, b"not found\n")


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------- WebSocket echo ----------

_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_accept_key(key: str) -> str:
    import base64

    digest = hashlib.sha1((key + _WS_MAGIC).encode()).digest()
    return base64.b64encode(digest).decode()


def _ws_recv_frame(sock: socket.socket):
    hdr = b""
    while len(hdr) < 2:
        chunk = sock.recv(2 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    b1, b2 = hdr[0], hdr[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    plen = b2 & 0x7F
    if plen == 126:
        ext = sock.recv(2)
        plen = struct.unpack("!H", ext)[0]
    elif plen == 127:
        ext = sock.recv(8)
        plen = struct.unpack("!Q", ext)[0]
    mask = b""
    if masked:
        mask = sock.recv(4)
    data = b""
    while len(data) < plen:
        chunk = sock.recv(plen - len(data))
        if not chunk:
            return None
        data += chunk
    if masked:
        data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
    return opcode, data


def _ws_send_text(sock: socket.socket, text: str):
    payload = text.encode()
    plen = len(payload)
    header = bytearray([0x81])
    if plen < 126:
        header.append(plen)
    elif plen < (1 << 16):
        header.append(126)
        header += struct.pack("!H", plen)
    else:
        header.append(127)
        header += struct.pack("!Q", plen)
    sock.sendall(bytes(header) + payload)


def _ws_send_close(sock: socket.socket):
    try:
        sock.sendall(b"\x88\x00")
    except Exception:
        pass


def ws_serve(bind: str, port: int, stop: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(32)
    srv.settimeout(0.5)
    sys.stderr.write("[infra] WS   listening ws://%s:%d/\n" % (bind, port))

    def handle(client: socket.socket):
        client.settimeout(10)
        try:
            req = b""
            while b"\r\n\r\n" not in req and len(req) < 8192:
                chunk = client.recv(1024)
                if not chunk:
                    return
                req += chunk
            headers = {}
            for line in req.split(b"\r\n")[1:]:
                if b":" not in line:
                    continue
                k, _, v = line.partition(b":")
                headers[k.strip().lower().decode()] = v.strip().decode()
            key = headers.get("sec-websocket-key", "")
            accept = _ws_accept_key(key)
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n" % accept
            )
            client.sendall(resp.encode())
            # proactively push a hello frame so read-only clients see data
            _ws_send_text(client, "hello-ws")
            while not stop.is_set():
                frame = _ws_recv_frame(client)
                if frame is None:
                    return
                opcode, data = frame
                if opcode == 0x8:  # close
                    _ws_send_close(client)
                    return
                if opcode == 0x9:  # ping
                    client.sendall(b"\x8a" + bytes([len(data)]) + data)
                    continue
                if opcode == 0x1:  # text
                    try:
                        _ws_send_text(client, data.decode())
                    except Exception:
                        return
        except Exception:
            return
        finally:
            try:
                client.close()
            except Exception:
                pass

    while not stop.is_set():
        try:
            cli, _addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        t = threading.Thread(target=handle, args=(cli,), daemon=True)
        t.start()
    srv.close()


# ---------- TCP line echo ----------

def tcp_serve(bind: str, port: int, stop: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(32)
    srv.settimeout(0.5)
    sys.stderr.write("[infra] TCP  listening tcp://%s:%d\n" % (bind, port))

    def handle(client: socket.socket):
        client.settimeout(5)
        try:
            data = b""
            while True:
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break
            if data:
                try:
                    client.sendall(data)
                except Exception:
                    pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    while not stop.is_set():
        try:
            cli, _addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        t = threading.Thread(target=handle, args=(cli,), daemon=True)
        t.start()
    srv.close()


# ---------- top level ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=18080)
    ap.add_argument("--https-port", type=int, default=18443)
    ap.add_argument("--ws-port", type=int, default=18081)
    ap.add_argument("--tcp-port", type=int, default=18083)
    ap.add_argument(
        "--cert-dir",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "mock_public_certs"
        ),
    )
    args = ap.parse_args()

    cert = ensure_self_signed_cert(args.cert_dir)

    http_srv = ThreadingHTTPServer((args.bind, args.http_port), MockHTTPHandler)
    sys.stderr.write("[infra] HTTP listening http://%s:%d\n" % (args.bind, args.http_port))

    https_srv = ThreadingHTTPServer((args.bind, args.https_port), MockHTTPHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=cert)
    https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)
    sys.stderr.write(
        "[infra] HTTPS listening https://%s:%d (self-signed)\n"
        % (args.bind, args.https_port)
    )

    stop = threading.Event()

    http_t = threading.Thread(target=http_srv.serve_forever, daemon=True)
    https_t = threading.Thread(target=https_srv.serve_forever, daemon=True)
    ws_t = threading.Thread(
        target=ws_serve, args=(args.bind, args.ws_port, stop), daemon=True
    )
    tcp_t = threading.Thread(
        target=tcp_serve, args=(args.bind, args.tcp_port, stop), daemon=True
    )
    http_t.start()
    https_t.start()
    ws_t.start()
    tcp_t.start()

    ready = {
        "bind": args.bind,
        "http": args.http_port,
        "https": args.https_port,
        "ws": args.ws_port,
        "tcp": args.tcp_port,
        "cert": cert,
        "sub_bearer": SUB_BEARER,
        "sub_etag": SUB_CLASH_ETAG,
        "ts": time.time(),
    }
    # Machine-readable ready line on stdout so orchestrators can gate on it.
    sys.stdout.write(json.dumps(ready) + "\n")
    sys.stdout.flush()
    sys.stderr.write("[infra] all servers up; SIGTERM to stop\n")

    def _sigterm(_signum, _frame):
        sys.stderr.write("[infra] received signal, stopping\n")
        stop.set()
        try:
            http_srv.shutdown()
        except Exception:
            pass
        try:
            https_srv.shutdown()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
    sys.stderr.write("[infra] shutdown\n")


if __name__ == "__main__":
    main()
