//! System Hardening and Security Sandbox
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module implements **OS-Level Security Hardening** for Linux environments.
//! It reduces the attack surface by restricting process privileges and resource access.
//!
//! 本模块实现了 Linux 环境的 **操作系统级安全加固**。
//! 它通过限制进程权限和资源访问来减少攻击面。
//!
//! ## Strategic Features / 战略特性
//! - **Resource Limits / 资源限制**: Increases file descriptor limits to handle high concurrency (C10K+).
//!   提高文件描述符限制以处理高并发 (C10K+)。
//! - **Privilege Drop / 权限降级**: Prevents the process from gaining new privileges (no_new_privs).
//!   防止进程获取新权限 (no_new_privs)。
//! - **Anti-Debugging / 反调试**: Disables core dumps to prevent sensitive memory leakage.
//!   禁用核心转储以防止敏感内存泄漏。

#[cfg(target_os = "linux")]
pub fn apply() {
    use nix::sys::prctl::{set_dumpable, set_no_new_privs};
    use nix::sys::resource::{setrlimit, Resource, Rlim};

    if std::env::var("SB_HARDEN").ok().as_deref() != Some("1") {
        return;
    }

    let limit = Rlim::from_raw(1_048_576);
    let _ = setrlimit(Resource::RLIMIT_NOFILE, limit, limit);
    let _ = set_dumpable(false);
    let _ = set_no_new_privs();
}

#[cfg(not(target_os = "linux"))]
pub const fn apply() {}
