#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "socks")]
pub mod socks;

#[cfg(all(feature = "http", feature = "socks"))]
pub mod mixed;

#[cfg(feature = "tun")]
pub mod tun;

#[cfg(all(feature = "tun_macos", target_os = "macos"))]
pub mod tun_macos;

#[cfg(all(feature = "tun_macos", target_os = "macos"))]
pub mod tun_process_aware;

#[cfg(all(target_os = "linux", feature = "redirect"))]
pub mod redirect;

#[cfg(all(target_os = "linux", feature = "tproxy"))]
pub mod tproxy;

#[cfg(feature = "trojan")]
pub mod trojan;

#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;

#[cfg(feature = "vmess")]
pub mod vmess;

#[cfg(feature = "vless")]
pub mod vless;

#[cfg(feature = "shadowtls")]
pub mod shadowtls;

#[cfg(feature = "naive")]
pub mod naive;

#[cfg(feature = "tuic")]
pub mod tuic;

#[cfg(feature = "adapter-hysteria")]
pub mod hysteria;

#[cfg(feature = "adapter-hysteria2")]
pub mod hysteria2;
