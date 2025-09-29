//! Optional HTTP DNS client (enabled by feature `dns_http`).
#[cfg(feature = "dns_http")]
pub fn query(_name: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    // 占位：仅表明在 feature 打开时由 reqwest 提供实现细节。
    Err(std::io::Error::other("not implemented"))
}
