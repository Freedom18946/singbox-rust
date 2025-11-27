//! Clash API implementation
//! Clash API 实现
//!
//! This module provides a Clash-compatible REST API for managing and monitoring
//! the proxy server. It includes endpoints for proxy management, connection tracking,
//! rule management, and real-time statistics via WebSocket.
//!
//! 本模块提供了一个兼容 Clash 的 REST API，用于管理和监控代理服务器。它包括用于代理管理、
//! 连接跟踪、规则管理以及通过 WebSocket 进行实时统计的端点。

pub mod handlers;
pub mod server;
pub mod websocket;

pub use server::ClashApiServer;
