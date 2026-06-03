<!-- tier: B -->
# MT-GUI-02 Mock Public Infrastructure

**Purpose**: a single-file, stdlib-only, project-local simulator of the public-internet surface a
real GUI workflow would touch. Used by MT-GUI-02 to drive identical traffic through the Rust and
Go kernels without relying on outbound connectivity or third-party services.

**Authoritative runner**: [mt_gui_02_evidence/mock_public_infra.py](./mt_gui_02_evidence/mock_public_infra.py)
(~450 lines, no third-party deps, Python ≥ 3.10).

---

## 1. Why this exists

MT-GUI-01 ran its data plane through a bare `python3 -m http.server`, which only covered
`GET /` over HTTP. That was enough to show SOCKS5 relay worked, but it left the following
GUI-realistic scenarios untested:

- TLS (certificate validation paths, self-signed tolerance)
- Streaming protocols: WebSocket, SSE, chunked transfer-encoding
- Variable-latency / large-body / slow upstream
- Subscription endpoint with Bearer auth, ETag, `Cache-Control`, and `304 Not Modified`
- Fault-injection shapes: early-close, RST, dead port, TLS-failure

All of the above are things GUI.for.SingBox can drive through the kernel in a normal user session.
The mock makes them reproducible locally without any external dependency.

---

## 2. Endpoints

### 2.1 HTTP (port `18080`)

| Path | Purpose |
|------|---------|
| `GET /` | banner (`MT-GUI-02 mock public OK`) |
| `GET /get` | JSON echo of query/headers/method/path (analog of httpbin `/get`) |
| `GET /status/{code}` | respond with the requested status code |
| `GET /redirect/{n}` | N-step 302 chain, terminating at `/get` |
| `GET /chunked` | 5 × `Transfer-Encoding: chunked` frames (`chunk-0`..`chunk-4`) |
| `GET /large[?bytes=N]` | configurable body, default **1 MiB** |
| `GET /slow?ms=N` | sleep N ms then 200 |
| `GET /sse` | 5 `text/event-stream` events, 100 ms apart |
| `GET /sub/clash.json` | **subscription endpoint** (see 2.3) |
| `GET /early-close` | send headers + `Content-Length: 1024`, then shutdown before body |
| `GET /reset` | immediate shutdown, no response |

### 2.2 HTTPS (port `18443`)

Same handler wrapped in an `ssl.SSLContext` backed by a **self-signed cert** auto-generated on
first run (`mock_public_certs/server.pem`). SANs: `DNS:mock-public.local`, `DNS:localhost`,
`IP:127.0.0.1`, `IP:::1`.

Clients must use `-k` (or install the cert) — the purpose of the strict TLS test is exactly to
show that both kernels relay the TCP stream while the client enforces PKI.

### 2.3 Subscription endpoint

Bearer model matches the specific sequence MT-GUI-01 §5 evidence baselined:

| Request | Response |
|---------|----------|
| No `Authorization` header | 200 + body (public fetch, for cold-boot GUI) |
| `Authorization: Bearer <wrong>` | **401** (present-but-invalid is rejected) |
| `Authorization: Bearer mt-gui-02-sub-bearer` | 200 + `ETag` + `Cache-Control: max-age=60, public` |
| Same auth + `If-None-Match: "<etag>"` | **304** |

The `ETag` is `sha256(body)[:16]` wrapped in quotes (stable across restarts because the body is
a literal constant), which is why the "ready JSON" printed on stdout (§3) includes
`sub_etag=\"34f2f416ae8fc084\"`.

The body is a minimal GUI-shape Clash profile: one direct outbound, one `final: direct` route,
no real protocol nodes. It is deliberately small (311 bytes) because the point is the
cache/refresh contract, not profile richness.

### 2.4 WebSocket (port `18081`)

Pure-stdlib RFC 6455 implementation (handshake via
`Sec-WebSocket-Accept = base64(sha1(key + MAGIC))`, masked client frames, unmasked server
frames). Behavior:

1. On handshake: push one opcode-1 text frame `hello-ws`.
2. For every client frame received: echo the payload.
3. On close: respond with opcode-8, shut down.

A buffered reader (`_read`/`_read_until`) is used on both server and client sides to handle the
case where the socket recv for the HTTP upgrade response overshoots into the first WS frame.

### 2.5 Raw TCP echo (port `18083`)

`socket.recv(4096)` → `socket.send(...)` loop. Used for SOCKS5 CONNECT→raw TCP coverage.

### 2.6 Dead port (`18499`)

Reserved but **not bound**. Data-plane D15 confirms both kernels surface connection refusal
identically.

---

## 3. Lifecycle

```bash
python3 mock_public_infra.py     # starts all servers in threads
```

On start, the script prints a single JSON line to **stdout** (the "ready line"), e.g.

```json
{"bind": "127.0.0.1", "http": 18080, "https": 18443, "ws": 18081, "tcp": 18083,
 "cert": "…/mock_public_certs/server.pem",
 "sub_bearer": "mt-gui-02-sub-bearer",
 "sub_etag": "\"34f2f416ae8fc084\"", "ts": 1775942948.661588}
```

The orchestrator ([run_acceptance.sh](./mt_gui_02_evidence/run_acceptance.sh)) waits for this
line (up to 3 s) before starting the kernels.

Shutdown: `SIGTERM` / `SIGINT` / orchestrator `cleanup()` trap escalates to `SIGKILL` after
0.5 s. Individual socket servers listen on `SO_REUSEADDR` so a crashed prior run does not block
re-binding.

---

## 4. Reproducing standalone

```bash
# One-shot smoke test (no kernels involved):
bash agents-only/mt_gui_02_evidence/mock_infra_smoke.sh

# Manual:
python3 agents-only/mt_gui_02_evidence/mock_public_infra.py &
MOCK_PID=$!
curl -s http://127.0.0.1:18080/get
curl -sk https://127.0.0.1:18443/get
curl -sI http://127.0.0.1:18080/sub/clash.json  # HEAD intentionally unsupported (501)
kill -TERM $MOCK_PID
```

---

## 5. Non-goals

- **Not a fuzzer**: payloads are fixed, not randomized.
- **Not a real HTTP/2 or QUIC endpoint**: intentionally only HTTP/1.1 for comparability with how
  GUI.for.SingBox drives the kernel today.
- **Not a replacement for `p0_clash_api_contract*`** cases: those remain the authoritative source
  of WS framing / Clash API contract truth. This mock exists to give MT-GUI-02 deterministic,
  repeatable raw traffic.
- **Does not make network calls**: everything resolves to `127.0.0.1`; `mock-public.local` is
  deliberately a non-resolvable name, which is how Scenario 13 (`/dns/query`) exposes the
  non-resolvable-domain design divergence between kernels.

---

## 6. Security notes

- The self-signed cert is auto-generated on first run via the `openssl` CLI. It lives under
  `mock_public_certs/server.pem` and is specific to this evidence directory — do not trust it,
  do not install it into the system trust store.
- The Bearer token (`mt-gui-02-sub-bearer`) is a fixed test-only constant documented in this
  file and embedded in `mock_public_infra.py`. It is not a secret.
- Everything binds `127.0.0.1` only. No listener is reachable from the local network.
