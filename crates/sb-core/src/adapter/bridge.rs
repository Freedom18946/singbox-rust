//! Adapter Bridge：优先使用 sb-adapter 注册表；缺失时回退到 scaffold。
use crate::adapter::{Bridge, InboundParam, InboundService, OutboundConnector, OutboundParam};
use crate::outbound::selector::Selector;
use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType};
use std::sync::Arc;

fn want_adapter() -> Option<bool> {
    match std::env::var("ADAPTER_FORCE").ok().as_deref() {
        Some("adapter") => Some(true),
        Some("scaffold") => Some(false),
        _ => None,
    }
}

/// 从 IR 生成参数
fn to_inbound_param(ib: &InboundIR) -> InboundParam {
    InboundParam {
        kind: match ib.ty {
            InboundType::Socks => "socks",
            InboundType::Http => "http",
            InboundType::Tun => "tun",
        }
        .to_string(),
        listen: ib.listen.clone(),
        port: ib.port,
        basic_auth: ib.basic_auth.clone(),
        sniff: ib.sniff,
    }
}
fn to_outbound_param(ob: &OutboundIR) -> (String, OutboundParam) {
    let name = ob.name.clone().unwrap_or_else(|| ob.ty_str().to_string());
    let kind = match ob.ty {
        OutboundType::Direct => "direct",
        OutboundType::Http => "http",
        OutboundType::Socks => "socks",
        OutboundType::Block => "block",
        OutboundType::Selector => "selector",
        OutboundType::Vless => "vless",
        OutboundType::Vmess => "vmess",
        OutboundType::Trojan => "trojan",
        OutboundType::Ssh => "ssh",
    }
    .to_string();
    (
        name.clone(),
        OutboundParam {
            kind,
            name: ob.name.clone(),
            server: ob.server.clone(),
            port: ob.port,
            credentials: ob.credentials.clone(),
            ssh_private_key: ob.ssh_private_key.clone().or(ob.ssh_private_key_path.clone()),
            ssh_private_key_passphrase: ob.ssh_private_key_passphrase.clone(),
            ssh_host_key_verification: ob.ssh_host_key_verification,
            ssh_known_hosts_path: ob.ssh_known_hosts_path.clone(),
        },
    )
}

#[cfg(feature = "adapter")]
fn try_adapter_inbound(_p: &InboundParam) -> Option<Arc<dyn InboundService>> {
    None
}
#[cfg(not(feature = "adapter"))]
fn try_adapter_inbound(_p: &InboundParam) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(feature = "adapter")]
fn try_adapter_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    // let server = p.server.clone().unwrap_or_default();
    // let port = p.port.unwrap_or(0);
    // sb_adapter::registry::outbound_create(p.kind.as_str(), p.name.as_deref(), if server.is_empty(){None}else{Some(server.as_str())}, port)
    None // placeholder until sb-adapter is available
}
#[cfg(not(feature = "adapter"))]
fn try_adapter_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    None
}

#[cfg(all(feature = "scaffold", feature = "router"))]
fn try_scaffold_inbound(
    p: &InboundParam,
    engine: crate::routing::engine::Engine<'_>,
    br: &Bridge,
) -> Option<Arc<dyn InboundService>> {
    if p.kind == "socks" {
        use crate::inbound::socks5::Socks5;
        let srv = Socks5::new(p.listen.clone(), p.port)
            .with_engine(engine.clone_as_static())
            .with_bridge(Arc::new(br.clone()));
        return Some(Arc::new(srv));
    } else if p.kind == "http" {
        use crate::inbound::http_connect::HttpConnect;
        let mut srv = HttpConnect::new(p.listen.clone(), p.port)
            .with_engine(engine.clone_as_static())
            .with_bridge(Arc::new(br.clone()))
            .with_sniff(p.sniff);
        if let Some(c) = &p.basic_auth {
            srv = srv.with_basic_auth(c.username.clone(), c.password.clone());
        }
        return Some(Arc::new(srv));
    } else if p.kind == "tun" {
        // Basic TUN inbound (scaffold); enhanced implementation lives in sb-adapters
        use crate::inbound::tun::TunInboundService;
        let srv = TunInboundService::new().with_sniff(p.sniff);
        return Some(Arc::new(srv));
    }
    None
}
// Router present but scaffold disabled: keep signature compatible with router path
#[cfg(all(feature = "router", not(feature = "scaffold")))]
fn try_scaffold_inbound(
    _p: &InboundParam,
    _engine: crate::routing::engine::Engine<'_>,
    _br: &Bridge,
) -> Option<Arc<dyn InboundService>> {
    None
}

// No router: provide a minimal stub without engine (used by the no-router build_bridge)
#[cfg(not(feature = "router"))]
fn try_scaffold_inbound(_p: &InboundParam, _br: &Bridge) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(feature = "scaffold")]
fn try_scaffold_outbound(p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    if p.kind == "direct" {
        use crate::outbound::direct_simple::Direct;
        return Some(Arc::new(Direct::default()));
    } else if p.kind == "socks" {
        use crate::outbound::socks_upstream::SocksUp;
        let (u, pw) = p
            .credentials
            .as_ref()
            .map(|c| (c.username.clone(), c.password.clone()))
            .unwrap_or((None, None));
        return Some(Arc::new(SocksUp::new(
            p.server.clone().unwrap_or_default(),
            p.port.unwrap_or(1080),
            u,
            pw,
        )));
    } else if p.kind == "http" {
        use crate::outbound::http_upstream::HttpUp;
        let (u, pw) = p
            .credentials
            .as_ref()
            .map(|c| (c.username.clone(), c.password.clone()))
            .unwrap_or((None, None));
        return Some(Arc::new(HttpUp::new(
            p.server.clone().unwrap_or_default(),
            p.port.unwrap_or(8080),
            u,
            pw,
        )));
    } else if p.kind == "ssh" {
        #[cfg(feature = "out_ssh")]
        {
            use crate::adapter::OutboundConnector as Oc;
            use crate::outbound::crypto_types::{HostPort, OutboundTcp};
            use crate::outbound::ssh_stub::{SshConfig, SshOutbound};
            use async_trait::async_trait;

            #[derive(Clone)]
            struct SshOc {
                inner: std::sync::Arc<SshOutbound>,
            }

            impl std::fmt::Debug for SshOc {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct("SshOc").field("inner", &"<ssh-outbound>").finish()
                }
            }
            #[async_trait]
            impl Oc for SshOc {
                async fn connect(
                    &self,
                    host: &str,
                    port: u16,
                ) -> std::io::Result<tokio::net::TcpStream> {
                    let hp = HostPort::new(host.to_string(), port);
                    self.inner.connect(&hp).await
                }
            }

            let (u, pw) = p
                .credentials
                .as_ref()
                .map(|c| (c.username.clone(), c.password.clone()))
                .unwrap_or((None, None));
            let server = p.server.clone().unwrap_or_default();
            let port = p.port.unwrap_or(22);
            let using_key = p.ssh_private_key.is_some();
            let has_auth = u.is_some() && (pw.is_some() || using_key);
            if server.is_empty() || !has_auth {
                return None;
            }
            let cfg = SshConfig {
                server,
                port,
                username: u.unwrap_or_default(),
                password: if using_key { None } else { pw },
                private_key: p.ssh_private_key.clone(),
                private_key_passphrase: p.ssh_private_key_passphrase.clone(),
                host_key_verification: p.ssh_host_key_verification.unwrap_or(true),
                compression: false,
                keepalive_interval: Some(30),
                connect_timeout: Some(10),
                connection_pool_size: Some(2),
                known_hosts_path: p.ssh_known_hosts_path.clone(),
            };
            match SshOutbound::new(cfg) {
                Ok(inner) => return Some(Arc::new(SshOc { inner: std::sync::Arc::new(inner) })),
                Err(e) => {
                    tracing::warn!(target: "sb_core::adapter", error = %e, "ssh outbound init failed; fallback");
                    return None;
                }
            }
        }
        #[cfg(not(feature = "out_ssh"))]
        {
            return None;
        }
    }
    None
}
#[cfg(not(feature = "scaffold"))]
fn try_scaffold_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    None
}

/// 将 IR 装配为 Bridge；优先 adapter，允许回退；可被 ADAPTER_FORCE 覆盖
#[cfg(feature = "router")]
pub fn build_bridge<'a>(cfg: &'a ConfigIR, engine: crate::routing::engine::Engine<'a>) -> Bridge {
    let mut br = Bridge::new();
    // 先装配出站（供入站转发时可查询命名出站）
    for ob in &cfg.outbounds {
        let (name, p) = to_outbound_param(ob);
        let kind = p.kind.clone();
        let forced = want_adapter();
        let inst: Option<Arc<dyn OutboundConnector>> = match forced {
            Some(true) => try_adapter_outbound(&p),
            Some(false) => try_scaffold_outbound(&p),
            None => try_adapter_outbound(&p).or_else(|| try_scaffold_outbound(&p)),
        };
        if let Some(o) = inst {
            br.add_outbound(name, kind, o);
        }
    }
    // 第二轮：对 selector 类型做"绑定成员"的虚拟出站
    for ob in &cfg.outbounds {
        if ob.ty == OutboundType::Selector {
            let name = ob.name.clone().unwrap_or_else(|| "selector".into());
            let members = ob.members.clone().unwrap_or_default(); // 假设 IR 中存在 members 字段
            let mut resolved = Vec::new();
            for m in members {
                if let Some(conn) = br.find_outbound(&m) {
                    resolved.push(crate::outbound::selector::Member {
                        name: m.clone(),
                        conn,
                    });
                } else {
                    // 成员缺失：跳过。preflight 会提示；运行时以 direct 回退或报错
                    tracing::warn!(
                        target: "sb_core::adapter",
                        selector = %name,
                        missing_member = %m,
                        "selector member not found, skipping"
                    );
                }
            }
            if !resolved.is_empty() {
                let sel = Selector::new(name.clone(), resolved);
                br.add_outbound(name, "selector".into(), Arc::new(sel));
            }
        }
    }
    // 再装配入站
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let forced = want_adapter();
        let inst: Option<Arc<dyn InboundService>> = match forced {
            Some(true) => try_adapter_inbound(&p),
            Some(false) => try_scaffold_inbound(&p, engine.clone(), &br),
            None => {
                try_adapter_inbound(&p).or_else(|| try_scaffold_inbound(&p, engine.clone(), &br))
            }
        };
        if let Some(i) = inst {
            br.add_inbound(i);
        }
    }
    br
}

/// 将 IR 装配为 Bridge（无 router 特性时的占位版本）
#[cfg(not(feature = "router"))]
pub fn build_bridge(cfg: &ConfigIR, _engine: ()) -> Bridge {
    let mut br = Bridge::new();
    // 先装配出站（供入站转发时可查询命名出站）
    for ob in &cfg.outbounds {
        let (name, p) = to_outbound_param(ob);
        let kind = p.kind.clone();
        let forced = want_adapter();
        let inst: Option<Arc<dyn OutboundConnector>> = match forced {
            Some(true) => try_adapter_outbound(&p),
            Some(false) => try_scaffold_outbound(&p),
            None => try_adapter_outbound(&p).or_else(|| try_scaffold_outbound(&p)),
        };
        if let Some(o) = inst {
            br.add_outbound(name, kind, o);
        }
    }
    // 第二轮：对 selector 类型做"绑定成员"的虚拟出站
    for ob in &cfg.outbounds {
        if ob.ty == OutboundType::Selector {
            let name = ob.name.clone().unwrap_or_else(|| "selector".into());
            let members = ob.members.clone().unwrap_or_default(); // 假设 IR 中存在 members 字段
            let mut resolved = Vec::new();
            for m in members {
                if let Some(conn) = br.find_outbound(&m) {
                    resolved.push(crate::outbound::selector::Member {
                        name: m.clone(),
                        conn,
                    });
                } else {
                    tracing::warn!(
                        target: "sb_core::adapter",
                        selector = %name,
                        missing_member = %m,
                        "selector member not found, skipping"
                    );
                }
            }
            if !resolved.is_empty() {
                let sel = Selector::new(name.clone(), resolved);
                br.add_outbound(name, "selector".into(), Arc::new(sel));
            }
        }
    }
    // 再装配入站（无 router 特性时，scaffold 版本不依赖 engine）
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let forced = want_adapter();
        let inst: Option<Arc<dyn InboundService>> = match forced {
            Some(true) => try_adapter_inbound(&p),
            Some(false) => try_scaffold_inbound(&p, &br),
            None => try_adapter_inbound(&p).or_else(|| try_scaffold_inbound(&p, &br)),
        };
        if let Some(i) = inst {
            br.add_inbound(i);
        }
    }
    br
}
