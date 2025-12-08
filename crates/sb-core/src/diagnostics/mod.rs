//! Debug and diagnostics HTTP server module.
//!
//! Provides runtime diagnostics and profiling endpoints:
//! - `/debug/gc` - Trigger garbage collection  
//! - `/debug/memory` - Memory statistics
//! - `/debug/pprof/*` - Profiling endpoints (via pprof-rs if available)
//!
//! Mirrors Go's `debug_http.go`.

pub mod http_server;
pub mod memory;
pub mod options;

pub use http_server::DebugServer;
pub use memory::MemoryStats;
pub use options::DebugOptions;
