# Sprint 14 Implementation Plan: Clash API Endpoints

**Sprint Duration**: 2025-10-12 (Estimated 2-3 weeks)
**Priority**: P1 - Critical for dashboard compatibility
**Theme**: Implement core Clash API endpoints for monitoring and control

---

## Executive Summary

Sprint 14 focuses on implementing essential Clash API endpoints to enable dashboard compatibility and real-time monitoring capabilities. This is the highest priority feature based on user demand (40% effort allocation).

### Goals

1. Implement core Clash API endpoints (GET /proxies, /connections, /logs, /configs, /version)
2. Add WebSocket support for real-time monitoring
3. Enable basic provider API (/providers/proxies, /providers/rules)
4. Achieve dashboard compatibility with Clash-compatible frontends

### Success Criteria

- ✅ Minimum 5 core endpoints implemented and tested
- ✅ WebSocket support for /logs and /connections
- ✅ Integration with existing metrics system
- ✅ API documentation complete
- ✅ Example dashboard configuration provided

---

## Current Status Analysis

### Existing Infrastructure

From GO_PARITY_MATRIX.md:
- ✅ V2Ray StatsService fully implemented (`crates/sb-api/src/v2ray`)
- ✅ Metrics system exists (`crates/sb-metrics`)
- ❌ 42/43 Clash API endpoints missing (2.3% complete)

### Dependencies Available

- ✅ Router engine (30.95% complete - sufficient for basic routing info)
- ✅ Connection tracking infrastructure
- ✅ Outbound adapters (64.7% complete)
- ✅ Protocol implementations (VMess, VLESS, Trojan, etc.)

---

## Implementation Plan

### Phase 1: Core Endpoints (Week 1)

#### 1.1 GET /version ✓
**Priority**: P0
**Complexity**: Low
**Implementation**: `crates/sb-api/src/clash/version.rs`

```rust
#[derive(Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub premium: bool,
    pub meta: bool,
}

pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        premium: false,
        meta: true,
    })
}
```

**Tests**: Unit test for version format validation

---

#### 1.2 GET /configs ✓
**Priority**: P0
**Complexity**: Medium
**Implementation**: `crates/sb-api/src/clash/configs.rs`

```rust
#[derive(Serialize)]
pub struct ConfigResponse {
    pub port: u16,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub allow_lan: bool,
    pub mode: String,
    pub log_level: String,
}

pub async fn get_configs(
    State(state): State<Arc<AppState>>
) -> Json<ConfigResponse> {
    // Extract from runtime config
}
```

**Tests**: Integration test with real config parsing

---

#### 1.3 GET /proxies ✓
**Priority**: P0
**Complexity**: High
**Implementation**: `crates/sb-api/src/clash/proxies.rs`

```rust
#[derive(Serialize)]
pub struct ProxyInfo {
    pub name: String,
    pub r#type: String,
    pub udp: bool,
    pub history: Vec<DelayHistory>,
    pub alive: bool,
    pub now: Option<String>,
}

#[derive(Serialize)]
pub struct ProxiesResponse {
    pub proxies: HashMap<String, ProxyInfo>,
}

pub async fn get_proxies(
    State(state): State<Arc<AppState>>
) -> Json<ProxiesResponse> {
    // Query from outbound manager
    // Include delay history from health check
}
```

**Dependencies**:
- Outbound manager integration
- Health check system (delay measurement)
- Proxy type mapping (vmess → VMess, vless → VLESS, etc.)

**Tests**:
- Unit test for proxy info serialization
- Integration test with multiple outbounds

---

#### 1.4 GET /proxies/{name} ✓
**Priority**: P0
**Complexity**: Medium
**Implementation**: Same file as 1.3

```rust
pub async fn get_proxy(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>
) -> Result<Json<ProxyInfo>, StatusCode> {
    // Query specific proxy by name
    // Return 404 if not found
}
```

**Tests**:
- Test existing proxy retrieval
- Test non-existent proxy (404)
- Test special characters in name

---

#### 1.5 GET /connections ✓
**Priority**: P0
**Complexity**: High
**Implementation**: `crates/sb-api/src/clash/connections.rs`

```rust
#[derive(Serialize)]
pub struct Connection {
    pub id: String,
    pub metadata: Metadata,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

#[derive(Serialize)]
pub struct Metadata {
    pub network: String,
    pub r#type: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: String,
    pub destination_port: String,
    pub host: String,
    pub dns_mode: String,
    pub process_path: String,
}

#[derive(Serialize)]
pub struct ConnectionsResponse {
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Vec<Connection>,
}
```

**Dependencies**:
- Connection tracking system (needs implementation)
- Traffic statistics per connection
- Rule matching result tracking

**Tests**:
- Test active connections listing
- Test traffic statistics accuracy
- Test metadata extraction

---

### Phase 2: Real-time Monitoring (Week 2)

#### 2.1 GET /logs (WebSocket) ✓
**Priority**: P1
**Complexity**: High
**Implementation**: `crates/sb-api/src/clash/logs.rs`

```rust
use axum::extract::ws::{WebSocket, WebSocketUpgrade};

pub async fn logs_websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>
) -> Response {
    ws.on_upgrade(|socket| handle_logs_socket(socket, state))
}

async fn handle_logs_socket(
    mut socket: WebSocket,
    state: Arc<AppState>
) {
    // Subscribe to log broadcast channel
    let mut rx = state.log_broadcast.subscribe();

    while let Ok(log_entry) = rx.recv().await {
        let msg = serde_json::to_string(&log_entry).unwrap();
        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }
    }
}
```

**Dependencies**:
- Log broadcast channel (tokio::sync::broadcast)
- Tracing subscriber integration
- WebSocket connection management

**Tests**:
- WebSocket connection lifecycle
- Log message format validation
- Multiple concurrent subscribers

---

#### 2.2 GET /traffic (WebSocket) ✓
**Priority**: P1
**Complexity**: Medium
**Implementation**: `crates/sb-api/src/clash/traffic.rs`

```rust
#[derive(Serialize)]
pub struct TrafficData {
    pub up: u64,
    pub down: u64,
}

pub async fn traffic_websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>
) -> Response {
    ws.on_upgrade(|socket| handle_traffic_socket(socket, state))
}

async fn handle_traffic_socket(
    mut socket: WebSocket,
    state: Arc<AppState>
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let stats = state.traffic_stats.get_current();
        let data = TrafficData {
            up: stats.upload,
            down: stats.download,
        };

        if socket.send(Message::Text(serde_json::to_string(&data).unwrap())).await.is_err() {
            break;
        }
    }
}
```

**Tests**:
- Traffic statistics accumulation
- WebSocket push interval accuracy
- Connection cleanup on disconnect

---

### Phase 3: Provider API (Week 2-3)

#### 3.1 GET /providers/proxies ✓
**Priority**: P1
**Complexity**: Medium
**Implementation**: `crates/sb-api/src/clash/providers.rs`

```rust
#[derive(Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub r#type: String,
    pub vehicle_type: String,
    pub proxies: Vec<ProxyInfo>,
    pub updated_at: String,
}

pub async fn get_proxy_providers(
    State(state): State<Arc<AppState>>
) -> Json<HashMap<String, ProviderInfo>> {
    // Query from provider manager
}
```

**Tests**:
- Provider listing
- Proxy enumeration within provider
- Update timestamp accuracy

---

#### 3.2 PUT /providers/proxies/{name} ✓
**Priority**: P1
**Complexity**: High
**Implementation**: Same file as 3.1

```rust
pub async fn update_proxy_provider(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>
) -> Result<StatusCode, StatusCode> {
    // Trigger provider update
    // Health check for all proxies in provider
}
```

**Dependencies**:
- Provider update mechanism
- Health check orchestration
- Async update notification

**Tests**:
- Manual provider update
- Health check triggered
- Update failure handling

---

### Phase 4: Control Endpoints (Week 3)

#### 4.1 PUT /proxies/{name} ✓
**Priority**: P1
**Complexity**: Medium
**Implementation**: `crates/sb-api/src/clash/proxies.rs`

```rust
#[derive(Deserialize)]
pub struct ProxySelection {
    pub name: String,
}

pub async fn update_proxy(
    Path(selector): Path<String>,
    Json(selection): Json<ProxySelection>,
    State(state): State<Arc<AppState>>
) -> Result<StatusCode, StatusCode> {
    // Update selector proxy to use selected proxy
    // Common for proxy groups (select, url-test, fallback)
}
```

**Tests**:
- Selector update success
- Invalid proxy name (404)
- Invalid selector (400)

---

#### 4.2 DELETE /connections ✓
**Priority**: P1
**Complexity**: Low
**Implementation**: `crates/sb-api/src/clash/connections.rs`

```rust
pub async fn close_all_connections(
    State(state): State<Arc<AppState>>
) -> StatusCode {
    state.connection_manager.close_all().await;
    StatusCode::NO_CONTENT
}
```

**Tests**:
- All connections closed
- New connections allowed after close

---

#### 4.3 DELETE /connections/{id} ✓
**Priority**: P1
**Complexity**: Low
**Implementation**: Same file as 4.2

```rust
pub async fn close_connection(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>
) -> Result<StatusCode, StatusCode> {
    match state.connection_manager.close(&id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}
```

**Tests**:
- Close existing connection
- Close non-existent connection (404)

---

## Infrastructure Requirements

### Connection Tracking System

**New Module**: `crates/sb-core/src/connection/tracker.rs`

```rust
pub struct ConnectionTracker {
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
    next_id: Arc<AtomicU64>,
}

impl ConnectionTracker {
    pub fn register(&self, metadata: Metadata) -> String;
    pub fn update_traffic(&self, id: &str, upload: u64, download: u64);
    pub fn unregister(&self, id: &str);
    pub fn list_all(&self) -> Vec<Connection>;
    pub fn close(&self, id: &str) -> Result<()>;
    pub fn close_all(&self);
}
```

---

### Log Broadcast Channel

**New Module**: `crates/sb-api/src/clash/log_broadcaster.rs`

```rust
pub struct LogBroadcaster {
    tx: broadcast::Sender<LogEntry>,
}

#[derive(Clone, Serialize)]
pub struct LogEntry {
    pub r#type: String,
    pub payload: String,
    pub timestamp: String,
}

impl LogBroadcaster {
    pub fn new(capacity: usize) -> Self;
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry>;
    pub fn publish(&self, level: Level, message: String);
}
```

**Integration**: Connect with tracing-subscriber layer

---

### Traffic Statistics

**Enhancement**: `crates/sb-metrics/src/traffic.rs`

```rust
pub struct TrafficStats {
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl TrafficStats {
    pub fn add_upload(&self, bytes: u64);
    pub fn add_download(&self, bytes: u64);
    pub fn get_current(&self) -> (u64, u64);
    pub fn reset(&self);
}
```

---

## API Server Setup

### Axum Router Configuration

**File**: `crates/sb-api/src/clash/mod.rs`

```rust
use axum::{
    Router,
    routing::{get, put, delete},
};

pub fn clash_router() -> Router<Arc<AppState>> {
    Router::new()
        // Core endpoints
        .route("/", get(hello))
        .route("/version", get(get_version))
        .route("/configs", get(get_configs))

        // Proxies
        .route("/proxies", get(get_proxies))
        .route("/proxies/:name", get(get_proxy).put(update_proxy))
        .route("/proxies/:name/delay", get(get_proxy_delay))

        // Connections
        .route("/connections", get(get_connections).delete(close_all_connections))
        .route("/connections/:id", delete(close_connection))

        // Real-time
        .route("/logs", get(logs_websocket))
        .route("/traffic", get(traffic_websocket))

        // Providers
        .route("/providers/proxies", get(get_proxy_providers))
        .route("/providers/proxies/:name", get(get_proxy_provider).put(update_proxy_provider))
        .route("/providers/rules", get(get_rule_providers))
}
```

---

## Testing Strategy

### Unit Tests

- ✅ Response serialization format validation
- ✅ Error handling for invalid inputs
- ✅ WebSocket message format validation

### Integration Tests

**File**: `crates/sb-api/tests/clash_api_integration.rs`

```rust
#[tokio::test]
async fn test_get_proxies() {
    let app = create_test_app().await;

    let response = app
        .oneshot(Request::builder()
            .uri("/proxies")
            .body(Body::empty())
            .unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let proxies: ProxiesResponse = serde_json::from_slice(&body).unwrap();

    assert!(!proxies.proxies.is_empty());
}
```

### E2E Tests

- Dashboard connection test (manual)
- WebSocket streaming test
- Multi-client concurrent access test

---

## Documentation

### API Documentation

**File**: `docs/api/CLASH_API.md`

```markdown
# Clash API Documentation

## Endpoints

### GET /version
Returns version information.

**Response**:
```json
{
  "version": "1.0.0",
  "premium": false,
  "meta": true
}
```

### GET /proxies
Returns all proxies with delay history.

**Response**:
```json
{
  "proxies": {
    "vmess-proxy": {
      "name": "vmess-proxy",
      "type": "VMess",
      "udp": true,
      "history": [
        {"time": "2025-10-12T00:00:00Z", "delay": 150}
      ],
      "alive": true
    }
  }
}
```
...
```

### Example Configuration

**File**: `docs/examples/clash_dashboard_config.json`

```json
{
  "external_controller": "127.0.0.1:9090",
  "external_ui": "./ui",
  "secret": "your_secret_token",

  "log": {
    "level": "info"
  },

  "clash_api": {
    "enabled": true,
    "port": 9090,
    "secret": "your_secret_token"
  }
}
```

---

## Timeline

### Week 1 (Days 1-5)
- Day 1-2: Connection tracking system
- Day 3-4: Core endpoints (version, configs, proxies)
- Day 5: Unit tests and documentation

### Week 2 (Days 6-10)
- Day 6-7: WebSocket support (logs, traffic)
- Day 8-9: Provider API
- Day 10: Integration tests

### Week 3 (Days 11-15)
- Day 11-12: Control endpoints (PUT, DELETE)
- Day 13-14: E2E testing with dashboard
- Day 15: Documentation and Sprint completion

---

## Success Metrics

### Coverage
- ✅ 10+ core Clash API endpoints implemented
- ✅ WebSocket support for real-time monitoring
- ✅ Provider API basic functionality
- ✅ API test coverage >80%

### Compatibility
- ✅ Works with Yacd dashboard
- ✅ Works with Clash Dashboard
- ✅ WebSocket clients connect successfully

### Performance
- ✅ <10ms response time for GET endpoints
- ✅ <100ms WebSocket message latency
- ✅ Supports 100+ concurrent connections

---

## Risks and Mitigations

### Risk 1: Connection Tracking Overhead
**Impact**: High traffic may slow down tracking
**Mitigation**: Use lock-free data structures, async processing

### Risk 2: WebSocket Memory Leaks
**Impact**: Long-running connections consume memory
**Mitigation**: Connection timeout, proper cleanup on disconnect

### Risk 3: Dashboard Compatibility Issues
**Impact**: API may not match exact Clash behavior
**Mitigation**: Reference official Clash API docs, test with multiple dashboards

---

## Next Steps After Sprint 14

1. **Remaining Clash Endpoints** (P2)
   - Rule endpoints (/rules)
   - Cache endpoints (/cache/dns/flush, /cache/fakeip/flush)
   - Advanced provider features

2. **Inbound V2Ray Transport** (P1)
   - WebSocket/gRPC/HTTPUpgrade for inbound adapters
   - Complete E2E protocol testing

3. **Platform Testing** (P1)
   - Process matchers on Linux/Windows
   - Cross-platform validation

---

**Sprint 14 Status**: 🚀 READY TO START
**Estimated Completion**: 2025-10-25
**Next Review**: 2025-10-19 (Mid-sprint checkpoint)
