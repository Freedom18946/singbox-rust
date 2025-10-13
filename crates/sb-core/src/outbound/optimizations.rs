//! Performance optimizations for P0 protocols
//!
//! This module provides shared optimization utilities for REALITY, ECH,
//! Hysteria, SSH, and TUIC protocols.

use bytes::BytesMut;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Buffer pool for zero-copy operations
///
/// Reuses buffers to reduce allocations and improve cache locality.
pub struct BufferPool {
    buffers: Mutex<Vec<BytesMut>>,
    max_size: usize,
    max_buffer_capacity: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(max_size: usize, max_buffer_capacity: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(max_size)),
            max_size,
            max_buffer_capacity,
        }
    }

    /// Get a buffer from the pool or allocate a new one
    pub fn get(&self, capacity: usize) -> BytesMut {
        let mut buffers = self.buffers.lock().unwrap();

        // Try to find a buffer with sufficient capacity
        if let Some(pos) = buffers.iter().position(|b| b.capacity() >= capacity) {
            let mut buf = buffers.swap_remove(pos);
            buf.clear();
            return buf;
        }

        // Allocate new buffer
        BytesMut::with_capacity(capacity)
    }

    /// Return a buffer to the pool
    pub fn put(&self, mut buf: BytesMut) {
        // Don't pool buffers that are too large
        if buf.capacity() > self.max_buffer_capacity {
            return;
        }

        buf.clear();

        let mut buffers = self.buffers.lock().unwrap();
        if buffers.len() < self.max_size {
            buffers.push(buf);
        }
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.buffers.lock().unwrap().len()
    }
}

/// Global buffer pool for protocol operations
pub static PROTOCOL_BUFFER_POOL: once_cell::sync::Lazy<BufferPool> =
    once_cell::sync::Lazy::new(|| {
        let max_size = std::env::var("SB_BUFFER_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let max_capacity = std::env::var("SB_BUFFER_POOL_MAX_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024 * 1024); // 1MB

        BufferPool::new(max_size, max_capacity)
    });

/// Fast bandwidth limiter using atomic operations
///
/// Avoids lock contention by using atomic operations for token management.
pub struct FastBandwidthLimiter {
    up_tokens: AtomicU32,
    down_tokens: AtomicU32,
    up_limit: u32,
    down_limit: u32,
    last_refill_ms: AtomicU64,
}

impl FastBandwidthLimiter {
    /// Create a new bandwidth limiter
    pub fn new(up_mbps: u32, down_mbps: u32) -> Self {
        let up_tokens = up_mbps * 1024 * 1024;
        let down_tokens = down_mbps * 1024 * 1024;

        Self {
            up_tokens: AtomicU32::new(up_tokens),
            down_tokens: AtomicU32::new(down_tokens),
            up_limit: up_tokens,
            down_limit: down_tokens,
            last_refill_ms: AtomicU64::new(current_time_ms()),
        }
    }

    /// Try to consume upload tokens
    pub fn consume_up(&self, bytes: u32) -> bool {
        self.refill_if_needed();

        let mut current = self.up_tokens.load(Ordering::Acquire);
        loop {
            if current < bytes {
                return false;
            }

            match self.up_tokens.compare_exchange_weak(
                current,
                current - bytes,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Try to consume download tokens
    pub fn consume_down(&self, bytes: u32) -> bool {
        self.refill_if_needed();

        let mut current = self.down_tokens.load(Ordering::Acquire);
        loop {
            if current < bytes {
                return false;
            }

            match self.down_tokens.compare_exchange_weak(
                current,
                current - bytes,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Refill tokens if a second has passed
    fn refill_if_needed(&self) {
        let now = current_time_ms();
        let last = self.last_refill_ms.load(Ordering::Acquire);

        if now - last >= 1000 {
            // Try to update the refill time
            if self
                .last_refill_ms
                .compare_exchange(last, now, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                // We won the race, refill tokens
                self.up_tokens.store(self.up_limit, Ordering::Release);
                self.down_tokens.store(self.down_limit, Ordering::Release);
            }
        }
    }

    /// Get current upload tokens
    pub fn up_tokens(&self) -> u32 {
        self.up_tokens.load(Ordering::Acquire)
    }

    /// Get current download tokens
    pub fn down_tokens(&self) -> u32 {
        self.down_tokens.load(Ordering::Acquire)
    }
}

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Connection pool for protocol connections
///
/// Generic connection pool with health checking and round-robin selection.
pub struct ConnectionPool<T> {
    connections: Mutex<Vec<PooledConnection<T>>>,
    max_size: usize,
    round_robin: AtomicU32,
}

struct PooledConnection<T> {
    connection: Arc<T>,
    #[allow(dead_code)]
    created_at: Instant,
    #[allow(dead_code)]
    last_used: Instant,
}

impl<T> ConnectionPool<T> {
    /// Create a new connection pool
    pub fn new(max_size: usize) -> Self {
        Self {
            connections: Mutex::new(Vec::with_capacity(max_size)),
            max_size,
            round_robin: AtomicU32::new(0),
        }
    }

    /// Get a connection from the pool using round-robin
    pub fn get<F>(&self, is_healthy: F) -> Option<Arc<T>>
    where
        F: Fn(&T) -> bool,
    {
        let connections = self.connections.lock().unwrap();

        if connections.is_empty() {
            return None;
        }

        let idx = self.round_robin.fetch_add(1, Ordering::Relaxed) as usize;
        let start_idx = idx % connections.len();

        // Try round-robin selection first
        for i in 0..connections.len() {
            let idx = (start_idx + i) % connections.len();
            let conn = &connections[idx];

            if is_healthy(&conn.connection) {
                return Some(conn.connection.clone());
            }
        }

        None
    }

    /// Add a connection to the pool
    pub fn put(&self, connection: Arc<T>) {
        let mut connections = self.connections.lock().unwrap();

        if connections.len() < self.max_size {
            connections.push(PooledConnection {
                connection,
                created_at: Instant::now(),
                last_used: Instant::now(),
            });
        }
    }

    /// Remove stale connections
    pub fn cleanup<F>(&self, is_healthy: F)
    where
        F: Fn(&T) -> bool,
    {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|conn| is_healthy(&conn.connection));
    }

    /// Get pool size
    pub fn size(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    /// Clear all connections
    pub fn clear(&self) {
        self.connections.lock().unwrap().clear();
    }
}

/// Cache for expensive computations with TTL
pub struct TtlCache<K, V> {
    cache: Mutex<std::collections::HashMap<K, CachedValue<V>>>,
    ttl: Duration,
}

struct CachedValue<V> {
    value: Arc<V>,
    created_at: Instant,
}

impl<K, V> TtlCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    /// Create a new TTL cache
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(std::collections::HashMap::new()),
            ttl,
        }
    }

    /// Get a value from the cache
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        let cache = self.cache.lock().unwrap();

        if let Some(cached) = cache.get(key) {
            if cached.created_at.elapsed() < self.ttl {
                return Some(cached.value.clone());
            }
        }

        None
    }

    /// Put a value in the cache
    pub fn put(&self, key: K, value: V) {
        let mut cache = self.cache.lock().unwrap();

        cache.insert(
            key,
            CachedValue {
                value: Arc::new(value),
                created_at: Instant::now(),
            },
        );
    }

    /// Get or insert a value
    pub fn get_or_insert<F>(&self, key: K, create: F) -> Arc<V>
    where
        F: FnOnce() -> V,
    {
        // Fast path: check if value exists
        if let Some(value) = self.get(&key) {
            return value;
        }

        // Slow path: create and insert
        let value = Arc::new(create());
        let mut cache = self.cache.lock().unwrap();

        cache.insert(
            key,
            CachedValue {
                value: value.clone(),
                created_at: Instant::now(),
            },
        );

        value
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|_, v| v.created_at.elapsed() < self.ttl);
    }

    /// Get cache size
    pub fn size(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

/// Metrics for optimization monitoring
#[cfg(feature = "metrics")]
pub mod metrics {
    use super::*;

    /// Record buffer pool metrics
    pub fn record_buffer_pool_metrics() {
        use ::metrics::gauge;

        let size = PROTOCOL_BUFFER_POOL.size();
        gauge!("buffer_pool_size").set(size as f64);
    }

    /// Record connection pool metrics
    pub fn record_connection_pool_metrics<T>(pool: &ConnectionPool<T>, protocol: String) {
        use ::metrics::gauge;

        let size = pool.size();
        gauge!("connection_pool_size", "protocol" => protocol).set(size as f64);
    }

    /// Record bandwidth limiter metrics
    pub fn record_bandwidth_metrics(limiter: &FastBandwidthLimiter, protocol: String) {
        use ::metrics::gauge;

        gauge!("bandwidth_up_tokens", "protocol" => protocol.clone())
            .set(limiter.up_tokens() as f64);
        gauge!("bandwidth_down_tokens", "protocol" => protocol).set(limiter.down_tokens() as f64);
    }

    /// Record cache metrics
    pub fn record_cache_metrics<K, V>(cache: &TtlCache<K, V>, name: String)
    where
        K: std::hash::Hash + Eq + Clone,
    {
        use ::metrics::gauge;

        let size = cache.size();
        gauge!("cache_size", "cache" => name).set(size as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(10, 1024);

        // Get a buffer
        let buf1 = pool.get(512);
        assert_eq!(buf1.capacity(), 512);
        assert_eq!(pool.size(), 0);

        // Return it
        pool.put(buf1);
        assert_eq!(pool.size(), 1);

        // Get it again
        let buf2 = pool.get(256);
        assert!(buf2.capacity() >= 256);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_buffer_pool_max_size() {
        let pool = BufferPool::new(2, 1024);

        // Fill the pool
        pool.put(BytesMut::with_capacity(512));
        pool.put(BytesMut::with_capacity(512));
        assert_eq!(pool.size(), 2);

        // Try to add more (should be ignored)
        pool.put(BytesMut::with_capacity(512));
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_buffer_pool_max_capacity() {
        let pool = BufferPool::new(10, 1024);

        // Try to return a buffer that's too large
        pool.put(BytesMut::with_capacity(2048));
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_fast_bandwidth_limiter() {
        let limiter = FastBandwidthLimiter::new(1, 1); // 1 Mbps

        // Should be able to consume some bytes
        assert!(limiter.consume_up(1024));
        assert!(limiter.consume_down(1024));

        // Should eventually run out
        let mut consumed = 0;
        while limiter.consume_up(1024) {
            consumed += 1024;
            if consumed > 2 * 1024 * 1024 {
                break; // Safety limit
            }
        }

        assert!(consumed > 0);
    }

    #[test]
    fn test_bandwidth_limiter_refill() {
        let limiter = FastBandwidthLimiter::new(1, 1);

        // Consume all tokens
        while limiter.consume_up(1024) {}

        // Wait for refill (simulate by updating time)
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Should be able to consume again
        assert!(limiter.consume_up(1024));
    }

    #[test]
    fn test_connection_pool() {
        let pool = ConnectionPool::new(5);

        // Add connections
        pool.put(Arc::new(42));
        pool.put(Arc::new(43));
        assert_eq!(pool.size(), 2);

        // Get a connection
        let conn = pool.get(|_| true);
        assert!(conn.is_some());
        assert_eq!(*conn.unwrap(), 42);

        // Get another
        let conn = pool.get(|_| true);
        assert!(conn.is_some());
        assert_eq!(*conn.unwrap(), 43);
    }

    #[test]
    fn test_connection_pool_health_check() {
        let pool = ConnectionPool::new(5);

        pool.put(Arc::new(42));
        pool.put(Arc::new(43));

        // Only accept even numbers
        let conn = pool.get(|n| *n % 2 == 0);
        assert!(conn.is_some());
        assert_eq!(*conn.unwrap(), 42);
    }

    #[test]
    fn test_connection_pool_cleanup() {
        let pool = ConnectionPool::new(5);

        pool.put(Arc::new(42));
        pool.put(Arc::new(43));
        pool.put(Arc::new(44));
        assert_eq!(pool.size(), 3);

        // Remove odd numbers
        pool.cleanup(|n| *n % 2 == 0);
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_ttl_cache() {
        let cache = TtlCache::new(Duration::from_secs(1));

        // Put a value
        cache.put("key1", 42);
        assert_eq!(cache.size(), 1);

        // Get it back
        let value = cache.get(&"key1");
        assert!(value.is_some());
        assert_eq!(*value.unwrap(), 42);
    }

    #[test]
    fn test_ttl_cache_expiration() {
        let cache = TtlCache::new(Duration::from_millis(100));

        cache.put("key1", 42);

        // Should be available immediately
        assert!(cache.get(&"key1").is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Should be expired
        assert!(cache.get(&"key1").is_none());
    }

    #[test]
    fn test_ttl_cache_get_or_insert() {
        let cache = TtlCache::new(Duration::from_secs(1));

        // First call should create
        let value = cache.get_or_insert("key1", || 42);
        assert_eq!(*value, 42);
        assert_eq!(cache.size(), 1);

        // Second call should return cached
        let value = cache.get_or_insert("key1", || 99);
        assert_eq!(*value, 42); // Should still be 42, not 99
    }

    #[test]
    fn test_ttl_cache_cleanup() {
        let cache = TtlCache::new(Duration::from_millis(100));

        cache.put("key1", 42);
        cache.put("key2", 43);
        assert_eq!(cache.size(), 2);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Cleanup
        cache.cleanup();
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_current_time_ms() {
        let t1 = current_time_ms();
        std::thread::sleep(Duration::from_millis(10));
        let t2 = current_time_ms();

        assert!(t2 > t1);
        assert!(t2 - t1 >= 10);
    }
}
