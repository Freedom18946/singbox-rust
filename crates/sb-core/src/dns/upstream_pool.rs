use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[cfg(any(feature = "dns_dhcp", feature = "dns_resolved"))]
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::dns::DnsUpstream;

pub(crate) type UpstreamLoader = fn(&Path) -> Result<Vec<Arc<dyn DnsUpstream>>>;

#[cfg(unix)]
pub(crate) fn discover_nameservers_from_file(path: &Path) -> Result<Vec<SocketAddr>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read resolv.conf from {}", path.display()))?;
    let mut addrs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let addr = rest.split_whitespace().next();
            if let Some(token) = addr {
                if let Some(sa) = parse_nameserver_addr(token) {
                    addrs.push(sa);
                }
            }
        }
    }
    Ok(addrs)
}

#[cfg(not(unix))]
pub(crate) fn discover_nameservers_from_file(_path: &Path) -> Result<Vec<SocketAddr>> {
    Err(anyhow::anyhow!(
        "File-based DNS upstreams are only supported on Unix-like platforms"
    ))
}

fn parse_nameserver_addr(token: &str) -> Option<SocketAddr> {
    if let Ok(sa) = token.parse::<SocketAddr>() {
        return Some(sa);
    }
    if let Ok(ipv4) = token.parse::<Ipv4Addr>() {
        return Some(SocketAddr::new(IpAddr::V4(ipv4), 53));
    }
    if let Ok(ipv6) = token.parse::<Ipv6Addr>() {
        return Some(SocketAddr::new(IpAddr::V6(ipv6), 53));
    }
    if let Some((addr_part, port_part)) = token.rsplit_once(':') {
        if let Ok(port) = port_part.parse::<u16>() {
            let normalized = if addr_part.contains(':') && !addr_part.starts_with('[') {
                format!("[{addr_part}]")
            } else {
                addr_part.to_string()
            };
            if let Ok(sa) = format!("{normalized}:{port}").parse::<SocketAddr>() {
                return Some(sa);
            }
        }
    }
    None
}

pub(crate) fn load_udp_upstreams_from_file(path: &Path) -> Result<Vec<Arc<dyn DnsUpstream>>> {
    let servers = discover_nameservers_from_file(path)?;
    Ok(servers
        .into_iter()
        .map(|addr| Arc::new(super::upstream::UdpUpstream::new(addr)) as Arc<dyn DnsUpstream>)
        .collect())
}

pub(crate) fn record_upstream_reload(
    kind: &'static str,
    upstream: &str,
    result: &'static str,
    members: usize,
) {
    #[cfg(feature = "metrics")]
    {
        ::metrics::counter!(
            "dns_upstream_reload_total",
            "kind" => kind,
            "upstream" => upstream.to_string(),
            "result" => result
        )
        .increment(1);
        ::metrics::gauge!(
            "dns_upstream_members",
            "kind" => kind,
            "upstream" => upstream.to_string()
        )
        .set(members as f64);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (kind, upstream, result, members);
}

pub(crate) fn record_upstream_fallback(kind: &'static str, upstream: &str, reason: &'static str) {
    #[cfg(feature = "metrics")]
    {
        ::metrics::counter!(
            "dns_upstream_fallback_total",
            "kind" => kind,
            "upstream" => upstream.to_string(),
            "reason" => reason
        )
        .increment(1);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (kind, upstream, reason);
}

pub(crate) fn record_upstream_watch_error(kind: &'static str, upstream: &str, _error: &str) {
    #[cfg(feature = "metrics")]
    {
        ::metrics::counter!(
            "dns_upstream_watch_error_total",
            "kind" => kind,
            "upstream" => upstream.to_string(),
            "error" => "watch_error"
        )
        .increment(1);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (kind, upstream, _error);
}

pub(crate) struct FileBackedUpstreamPool {
    kind: &'static str,
    name: String,
    path: PathBuf,
    upstreams: Arc<RwLock<Vec<Arc<dyn DnsUpstream>>>>,
    round_robin: AtomicUsize,
    fallback: Arc<dyn DnsUpstream>,
    #[cfg(any(feature = "dns_dhcp", feature = "dns_resolved"))]
    _watcher: Option<RecommendedWatcher>,
    #[cfg(not(any(feature = "dns_dhcp", feature = "dns_resolved")))]
    _watcher: Option<()>,
    loader: UpstreamLoader,
}

impl FileBackedUpstreamPool {
    pub(crate) fn new(
        kind: &'static str,
        name: String,
        path: PathBuf,
        fallback: Arc<dyn DnsUpstream>,
        loader: UpstreamLoader,
    ) -> Self {
        let upstreams = Arc::new(RwLock::new(Vec::new()));
        reload_file_backed_servers(kind, &name, &path, &upstreams, loader);
        let watcher =
            create_file_backed_watcher(kind, name.clone(), path.clone(), upstreams.clone(), loader);

        Self {
            kind,
            name,
            path,
            upstreams,
            round_robin: AtomicUsize::new(0),
            fallback,
            _watcher: watcher,
            loader,
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn snapshot(&self) -> Vec<Arc<dyn DnsUpstream>> {
        self.upstreams.read().clone()
    }

    pub(crate) fn next_start(&self) -> usize {
        self.round_robin.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn fallback(&self) -> Arc<dyn DnsUpstream> {
        Arc::clone(&self.fallback)
    }

    pub(crate) fn reload_servers(&self) -> Result<()> {
        reload_file_backed_servers(
            self.kind,
            &self.name,
            &self.path,
            &self.upstreams,
            self.loader,
        );
        Ok(())
    }

    pub(crate) fn maybe_reload(&self) {
        let _ = self.reload_servers();
    }
}

#[cfg(any(feature = "dns_dhcp", feature = "dns_resolved"))]
fn create_file_backed_watcher(
    kind: &'static str,
    name: String,
    path: PathBuf,
    upstreams: Arc<RwLock<Vec<Arc<dyn DnsUpstream>>>>,
    loader: UpstreamLoader,
) -> Option<RecommendedWatcher> {
    let watch_path = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| path.clone());
    let target_filename = path.file_name().map(|f| f.to_owned());
    let name_clone = name.clone();
    let path_clone = path.clone();
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                let should_reload = if let Some(target) = &target_filename {
                    event.paths.iter().any(|p| p.file_name() == Some(target))
                } else {
                    event.paths.iter().any(|p| p == &path_clone)
                };

                if should_reload {
                    tracing::debug!(
                        target: "sb_core::dns",
                        upstream = %name_clone,
                        event = ?event.kind,
                        "file-backed DNS upstream changed, reloading"
                    );
                    reload_file_backed_servers(kind, &name_clone, &path_clone, &upstreams, loader);
                }
            }
            Err(error) => {
                tracing::warn!(
                    target: "sb_core::dns",
                    upstream = %name_clone,
                    error = %error,
                    "watch error"
                );
                record_upstream_watch_error(kind, &name_clone, &error.to_string());
            }
        })
        .ok();

    if let Some(watcher_ref) = &mut watcher {
        if let Err(error) = watcher_ref.watch(&watch_path, RecursiveMode::NonRecursive) {
            tracing::warn!(
                target: "sb_core::dns",
                upstream = %name,
                path = %watch_path.display(),
                error = %error,
                "failed to watch DNS upstream parent directory"
            );
        }
    }

    watcher
}

#[cfg(not(any(feature = "dns_dhcp", feature = "dns_resolved")))]
fn create_file_backed_watcher(
    _kind: &'static str,
    _name: String,
    _path: PathBuf,
    _upstreams: Arc<RwLock<Vec<Arc<dyn DnsUpstream>>>>,
    _loader: UpstreamLoader,
) -> Option<()> {
    None
}

fn reload_file_backed_servers(
    kind: &'static str,
    name: &str,
    path: &Path,
    upstreams: &RwLock<Vec<Arc<dyn DnsUpstream>>>,
    loader: UpstreamLoader,
) {
    let members = match loader(path) {
        Ok(members) => members,
        Err(error) => {
            record_upstream_reload(kind, name, "error", 0);
            tracing::debug!(
                target: "sb_core::dns",
                upstream = %name,
                error = %error,
                "failed to load file-backed upstream members"
            );
            return;
        }
    };

    if members.is_empty() {
        tracing::warn!(
            target: "sb_core::dns",
            upstream = %name,
            path = %path.display(),
            "file-backed DNS upstream found no nameservers"
        );
        upstreams.write().clear();
        record_upstream_reload(kind, name, "empty", 0);
        return;
    }

    tracing::info!(
        target: "sb_core::dns",
        upstream = %name,
        path = %path.display(),
        count = members.len(),
        "file-backed DNS upstream loaded nameservers"
    );
    *upstreams.write() = members;
    record_upstream_reload(kind, name, "success", upstreams.read().len());
}
