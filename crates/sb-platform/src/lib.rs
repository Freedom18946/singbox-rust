//! Platform-specific abstractions for `SingBox`
//!
//! # 🇨🇳 模块说明 (Module Description)
//!
//! `sb-platform` 是 `SingBox` 架构中的**底层基石 (Foundation)**，负责屏蔽操作系统之间的差异，
//! 为上层业务逻辑（如 `sb-adapters` 和 `sb-core`）提供统一的、跨平台的系统级能力接口。
//!
//! This crate serves as the **Foundation** in the `SingBox` architecture, abstracting away
//! operating system differences to provide unified, cross-platform system-level interfaces
//! for upper-layer business logic (such as `sb-adapters` and `sb-core`).
//!
//! ## 🎯 核心战略价值 (Core Strategic Value)
//!
//! 1.  **隔离系统复杂性 (Isolating System Complexity)**:
//!     -   将 Linux (ioctl), macOS (System Configuration/libproc), Windows (Win32 API/COM), Android (procfs/VpnService)
//!         等异构的系统调用封装在内部，防止平台相关代码污染核心业务逻辑。
//!     -   Encapsulates heterogeneous system calls (Linux ioctl, macOS libproc, Windows Win32 API, Android procfs/VpnService)
//!         internally, preventing platform-specific code from polluting core business logic.
//!
//! 2.  **赋能核心功能 (Enabling Core Features)**:
//!     -   **透明代理 (Transparent Proxy)**: 通过 [`tun`] 模块提供虚拟网卡设备的统一抽象。
//!     -   **路由决策 (Routing Decisions)**: 通过 [`process`] 模块提供基于进程信息的流量识别能力。
//!     -   **Transparent Proxy**: Provides a unified abstraction for virtual network interfaces via the [`tun`] module.
//!     -   **Routing Decisions**: Enables traffic identification based on process information via the [`process`] module.
//!
//! ## 🧩 模块概览 (Module Overview)
//!
//! ### Process Matching ([`process`])
//! -   **功能**: 根据网络连接信息（五元组）反查发起该连接的本地进程信息（PID, 路径, 名称）。
//! -   **Function**: Reverse-lookups local process information (PID, path, name) based on network connection info (5-tuple).
//! -   **实现策略**: 优先使用原生 API (libproc, `GetExtendedTcpTable`) 以获得最佳性能，
//!     降级时使用命令行工具 (lsof, netstat) 以保证兼容性。
//!
//! ### TUN Device Management ([`tun`])
//! -   **功能**: 创建和管理 TUN/TAP 虚拟网络设备，用于接管系统流量。
//! -   **Function**: Creates and manages TUN/TAP virtual network devices to capture system traffic.
//! -   **实现策略**: 利用 `tokio` 实现全异步 I/O，确保在高并发流量下的吞吐量。
//!
//! ## OS Detection ([`os::NAME`])
//! -   提供编译时的操作系统识别常量，用于条件编译和运行时环境判断。
//!
//! # Example
//!
//! ```no_run
//! use sb_platform::process::ProcessMatcher;
//! use sb_platform::os::NAME;
//!
//! // Platform detection
//! assert!(!NAME.is_empty());
//!
//! // Process matching (async)
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let matcher = ProcessMatcher::new()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `native-process-match` (default): Enable native OS APIs for process matching
//! - `linux`: Linux-specific features
//! - `macos`: macOS-specific features
//! - `windows`: Windows feature alias (`windows-sys` is kept as a compatibility no-op)
//! - `tun`: TUN device support
//! - `full`: Enable all platform features

#![warn(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::undocumented_unsafe_blocks
)]

/// Network monitoring utilities for detecting network changes.
pub mod monitor;
/// Network utilities for MAC address retrieval and interface queries.
pub mod network;
pub mod process;
pub mod system_proxy;
pub mod tun;
/// WiFi information retrieval (SSID, BSSID).
pub mod wifi;

// Re-export commonly used types at crate root for ergonomic usage
pub use monitor::{NetworkEvent, NetworkMonitor};

/// Android VPN protect hooks for socket protection.
pub mod android_protect;

/// Windows Internet (WinInet) proxy detection and configuration.
pub mod wininet;

/// OS detection constants and utilities
pub mod os {
    /// OS name detected at compile time
    #[cfg(target_os = "linux")]
    pub const NAME: &str = "linux";

    /// OS name detected at compile time
    #[cfg(target_os = "macos")]
    pub const NAME: &str = "macos";

    /// OS name detected at compile time
    #[cfg(target_os = "windows")]
    pub const NAME: &str = "windows";

    /// OS name detected at compile time
    #[cfg(target_os = "android")]
    pub const NAME: &str = "android";

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    )))]
    compile_error!(
        "Unsupported platform: sb-platform only supports Linux, macOS, Windows, and Android"
    );
}
