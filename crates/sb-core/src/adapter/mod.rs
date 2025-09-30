//! Adapter traits and factory interfaces.
//! sb-adapter 提供真实实现；sb-core 仅定义接口与桥接。
use sb_config::ir::Credentials;
use std::net::TcpStream;
use std::sync::Arc;

pub use crate::outbound::selector::Member as SelectorMember;
pub mod bridge;

/// 入站服务（如 socks/http/tun）统一接口
pub trait InboundService: Send + Sync + std::fmt::Debug + 'static {
    /// 阻塞运行（内部自行 spawn 工作线程）
    fn serve(&self) -> std::io::Result<()>;
}

/// 出站连接器（如 direct/socks-upstream/http）
pub trait OutboundConnector: Send + Sync + std::fmt::Debug + 'static {
    /// 建立到目标的 TCP 连接
    fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream>;
}

/// 入站构造参数（来自 IR）
#[derive(Clone, Debug)]
pub struct InboundParam {
    pub kind: String, // "socks" | "http" | "tun" | ...
    pub listen: String,
    pub port: u16,
    pub basic_auth: Option<Credentials>,
}

/// 出站构造参数（来自 IR）
#[derive(Clone, Debug)]
pub struct OutboundParam {
    pub kind: String, // "direct" | "socks" | "http" | "block" | named
    pub name: Option<String>,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub credentials: Option<Credentials>,
}

/// 工厂接口（由 sb-adapter 实现；桥接层会优先尝试调用）
pub trait InboundFactory: Send + Sync {
    fn create(&self, p: &InboundParam) -> Option<Arc<dyn InboundService>>;
}
pub trait OutboundFactory: Send + Sync {
    fn create(&self, p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>>;
}

/// 运行时桥接入口：先尝试 adapter，再回退脚手架
#[derive(Clone, Debug)] // 允许在多线程/装配处克隆
pub struct Bridge {
    pub inbounds: Vec<Arc<dyn InboundService>>,
    /// (name, kind, connector)
    pub outbounds: Vec<(String, String, Arc<dyn OutboundConnector>)>,
}

impl Bridge {
    pub fn new() -> Self {
        Self {
            inbounds: vec![],
            outbounds: vec![],
        }
    }

    /// Create bridge from IR configuration
    pub fn new_from_config(ir: &sb_config::ir::ConfigIR) -> anyhow::Result<Self> {
        let mut bridge = Self::new();

        // Build inbound services from IR
        #[cfg(feature = "scaffold")]
        {
            for inbound in &ir.inbounds {
                let inbound_service = match inbound.ty {
                    sb_config::ir::InboundType::Socks => {
                        // Create SOCKS5 inbound service
                        use crate::inbound::socks5::Socks5;
                        use std::net::SocketAddr;

                        let addr: SocketAddr = format!("{}:{}", inbound.listen, inbound.port)
                            .parse()
                            .map_err(|e| anyhow::anyhow!("Invalid inbound address: {}", e))?;

                        Arc::new(Socks5::new(addr.ip().to_string(), addr.port())) as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Http => {
                        // Create HTTP inbound service
                        use crate::inbound::http::HttpInboundService;
                        use std::net::SocketAddr;

                        let addr: SocketAddr = format!("{}:{}", inbound.listen, inbound.port)
                            .parse()
                            .map_err(|e| anyhow::anyhow!("Invalid inbound address: {}", e))?;

                        Arc::new(HttpInboundService::new(addr)) as Arc<dyn InboundService>
                    }
                    sb_config::ir::InboundType::Tun => {
                        // TUN inbound service
                        use crate::inbound::tun::TunInboundService;

                        Arc::new(TunInboundService::new()) as Arc<dyn InboundService>
                    }
                };

                bridge.add_inbound(inbound_service);
            }
        }

        #[cfg(not(feature = "scaffold"))]
        {
            if !ir.inbounds.is_empty() {
                return Err(anyhow::anyhow!("Inbound services not available without scaffold feature"));
            }
        }

        // Build outbound connectors from IR
        for outbound in &ir.outbounds {
            let name = outbound.name.clone().unwrap_or_else(|| format!("outbound_{}", outbound.ty_str()));
            let kind = outbound.ty_str().to_string();

            let connector = match outbound.ty {
                sb_config::ir::OutboundType::Direct => {
                    use crate::outbound::direct_connector::DirectConnector;
                    Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                }
                sb_config::ir::OutboundType::Block => {
                    #[cfg(feature = "scaffold")]
                    {
                        use crate::outbound::block_connector::BlockConnector;
                        Arc::new(BlockConnector::new()) as Arc<dyn OutboundConnector>
                    }
                    #[cfg(not(feature = "scaffold"))]
                    {
                        // Fall back to direct connector when scaffold is not available
                        use crate::outbound::direct_connector::DirectConnector;
                        Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                    }
                }
                sb_config::ir::OutboundType::Http => {
                    // HTTP proxy connector would be implemented here
                    // For now, fall back to direct
                    use crate::outbound::direct_connector::DirectConnector;
                    Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                }
                sb_config::ir::OutboundType::Socks => {
                    // SOCKS5 proxy connector would be implemented here
                    // For now, fall back to direct
                    use crate::outbound::direct_connector::DirectConnector;
                    Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                }
                sb_config::ir::OutboundType::Vless => {
                    #[cfg(feature = "out_vless")]
                    {
                        use crate::outbound::vless::VlessOutbound;
                        use crate::outbound::vless::VlessConfig;

                        if let (Some(server), Some(port)) = (&outbound.server, outbound.port) {
                            let config = VlessConfig {
                                server: server.clone(),
                                port,
                                uuid: uuid::Uuid::new_v4(), // Would need to parse from IR
                                flow: None,
                                encryption: Some("none".to_string()),
                            };

                            match VlessOutbound::new(config) {
                                Ok(vless_outbound) => {
                                    Arc::new(vless_outbound) as Arc<dyn OutboundConnector>
                                }
                                Err(_) => {
                                    use crate::outbound::direct_connector::DirectConnector;
                                    Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                                }
                            }
                        } else {
                            use crate::outbound::direct_connector::DirectConnector;
                            Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                        }
                    }
                    #[cfg(not(feature = "out_vless"))]
                    {
                        use crate::outbound::direct_connector::DirectConnector;
                        Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                    }
                }
                sb_config::ir::OutboundType::Selector => {
                    // Selector outbound would be implemented here
                    // For now, fall back to direct
                    use crate::outbound::direct_connector::DirectConnector;
                    Arc::new(DirectConnector::new()) as Arc<dyn OutboundConnector>
                }
            };

            bridge.add_outbound(name, kind, connector);
        }

        Ok(bridge)
    }
    pub fn add_inbound(&mut self, ib: Arc<dyn InboundService>) {
        self.inbounds.push(ib);
    }
    pub fn add_outbound(&mut self, name: String, kind: String, ob: Arc<dyn OutboundConnector>) {
        self.outbounds.push((name, kind, ob));
    }
    pub fn find_outbound(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {
        for (n, _k, ob) in &self.outbounds {
            if n == name {
                return Some(ob.clone());
            }
        }
        None
    }
    /// 用于兜底：找第一个 kind == "direct" 的出站
    pub fn find_direct_fallback(&self) -> Option<Arc<dyn OutboundConnector>> {
        for (_n, k, ob) in &self.outbounds {
            if k == "direct" {
                return Some(ob.clone());
            }
        }
        None
    }
    /// 供健康探测/可视化：拿到当前出站（name,kind）
    pub fn outbounds_snapshot(&self) -> Vec<(String, String)> {
        self.outbounds
            .iter()
            .map(|(n, k, _)| (n.clone(), k.clone()))
            .collect()
    }
    pub fn get_member(&self, name: &str) -> Option<Arc<dyn OutboundConnector>> {
        self.find_outbound(name)
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}
