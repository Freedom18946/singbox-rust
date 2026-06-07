#!/usr/bin/env python3
"""Transparent TCP ClientHello recorder for the REALITY ClientHello-parity harness.

Inserts a byte-transparent relay in front of the local REALITY fixture server:
    client -> Recorder(listen) -> reality_server -> tls_dest -> http_target
Per connection it captures the FIRST client->server TLS record (the ClientHello), writes
the raw bytes to a TEMPORARY directory, then relays bidirectionally so the functional
request still succeeds.

Raw ClientHello records may contain REALITY authentication material (the session_id and
random carry the REALITY auth). They are therefore written to a tempfile.TemporaryDirectory
by default and removed on exit (normal or abnormal). `--debug-retain-raw` keeps them and
prints a loud warning. The recorder never writes into committed evidence and never needs
root / tcpdump / openssl / socat. The listener port is configurable (not hard-coded).
"""
import os
import signal
import socket
import threading

RAW_WARNING = (
    "!!! WARNING: raw ClientHello records retained on disk. They may contain REALITY "
    "authentication material (session_id / random). Do NOT commit them. Delete after use."
)


class Recorder:
    def __init__(self, listen_port, upstream_host, upstream_port, raw_dir):
        self.listen_port = int(listen_port)
        self.upstream = (upstream_host, int(upstream_port))
        self.raw_dir = raw_dir
        self.kernel = None
        self.count = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._srv = None
        self._thread = None
        self.captures = []  # metadata (no raw bytes inline)

    # --- one TLS record (5-byte header + body) ---
    @staticmethod
    def _recv_record(sock):
        hdr = b""
        while len(hdr) < 5:
            b = sock.recv(5 - len(hdr))
            if not b:
                return None
            hdr += b
        length = (hdr[3] << 8) | hdr[4]
        body = b""
        while len(body) < length:
            b = sock.recv(length - len(body))
            if not b:
                return None
            body += b
        return hdr + body

    @staticmethod
    def _pump(a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _handle(self, client):
        try:
            up = socket.create_connection(self.upstream, timeout=5.0)
        except OSError:
            client.close()
            return
        try:
            rec = self._recv_record(client)
            if rec is not None:
                with self._lock:
                    self.count += 1
                    kernel, idx = self.kernel, self.count
                kdir = os.path.join(self.raw_dir, kernel or "unknown")
                os.makedirs(kdir, exist_ok=True)
                path = os.path.join(kdir, f"conn_{idx:02d}.bin")
                with open(path, "wb") as f:
                    f.write(rec)
                with self._lock:
                    self.captures.append({"kernel": kernel, "run_index": idx, "raw_path": path})
                up.sendall(rec)
            t1 = threading.Thread(target=self._pump, args=(client, up), daemon=True)
            t2 = threading.Thread(target=self._pump, args=(up, client), daemon=True)
            t1.start(); t2.start(); t1.join(); t2.join()
        finally:
            client.close()
            try:
                up.close()
            except OSError:
                pass

    def _serve(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.listen_port))
        self._srv.listen(64)
        self._srv.settimeout(0.5)
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()
        self._srv.close()

    def start(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def set_kernel(self, kernel):
        with self._lock:
            self.kernel = kernel
            self.count = 0


def wait_port(port, timeout_s=12.0):
    import time
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False
