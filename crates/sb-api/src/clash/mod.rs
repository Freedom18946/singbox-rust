//! Clash API implementation
//!
//! This module provides a Clash-compatible REST API for managing and monitoring
//! the proxy server. It includes endpoints for proxy management, connection tracking,
//! rule management, and real-time statistics via WebSocket.

pub mod handlers;
pub mod server;
pub mod websocket;

pub use server::ClashApiServer;
