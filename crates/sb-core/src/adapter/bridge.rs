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
        },
    )
}

#[cfg(feature = "adapter")]
fn try_adapter_inbound(p: &InboundParam) -> Option<Arc<dyn InboundService>> {
    // 假定 sb-adapter 提供如下接口（若命名不同，可在此桥接）
    // sb_adapter::registry::inbound_create(p.kind.as_str(), &p.listen, p.port)
    None // placeholder until sb-adapter is available
}
#[cfg(not(feature = "adapter"))]
fn try_adapter_inbound(_p: &InboundParam) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(feature = "adapter")]
fn try_adapter_outbound(p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
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
    _engine: crate::routing::engine::Engine<'_>,
    br: &Bridge,
) -> Option<Arc<dyn InboundService>> {
    if p.kind == "socks" {
        use crate::inbound::socks5::Socks5;
        let srv = Socks5::new(p.listen.clone(), p.port).with_bridge(Arc::new(br.clone()));
        return Some(Arc::new(srv));
    } else if p.kind == "http" {
        use crate::inbound::http_connect::HttpConnect;
        let mut srv = HttpConnect::new(p.listen.clone(), p.port).with_bridge(Arc::new(br.clone()));
        if let Some(c) = &p.basic_auth {
            srv = srv.with_basic_auth(c.username.clone(), c.password.clone());
        }
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
