//! Process runtime: hold Engine/Bridge, spawn inbounds, optional health task.
//! 进程运行时：持有引擎/桥接器，生成入站，可选的健康任务。
use crate::adapter::Bridge;
use crate::health;
use crate::router::Engine;
use crate::runtime::supervisor::{start_endpoints, start_services};
use sb_config::ir::ConfigIR;
use std::sync::Arc;
use std::thread::{self, JoinHandle as ThreadJoinHandle};

pub mod runtime_health;
pub mod supervisor;
pub mod switchboard;
pub mod transport;

pub use supervisor::{Supervisor, SupervisorHandle};

pub struct Runtime {
    pub engine: Engine,
    pub bridge: Arc<Bridge>,
    pub switchboard: Arc<switchboard::OutboundSwitchboard>,
    workers: Vec<ThreadJoinHandle<()>>,
    health: Option<tokio::task::JoinHandle<()>>,
    supervisor: Option<Arc<supervisor::Supervisor>>,
}

impl Runtime {
    pub fn new(
        engine: Engine,
        bridge: Bridge,
        switchboard: switchboard::OutboundSwitchboard,
    ) -> Self {
        Self {
            engine,
            bridge: Arc::new(bridge),
            switchboard: Arc::new(switchboard),
            workers: vec![],
            health: None,
            supervisor: None,
        }
    }

    /// Create runtime from configuration IR.
    /// 从配置 IR 创建运行时。
    pub fn from_config_ir(ir: &ConfigIR) -> crate::error::SbResult<Self> {
        let engine = Engine::new(Arc::new(ir.clone()));
        let bridge = Bridge::new_from_config(ir, crate::context::Context::new()).map_err(|e| {
            crate::error::SbError::config(
                sb_types::IssueCode::SchemaInvalid,
                "bridge_init",
                format!("Failed to initialize bridge from IR: {}", e),
            )
        })?;
        let switchboard = switchboard::SwitchboardBuilder::from_bridge(&bridge)?;
        Ok(Self::new(engine, bridge, switchboard))
    }
}

impl Runtime {
    /// Start all inbounds (constructed in bridge).
    /// 启动所有入站（bridge 中已构造）。
    pub fn start(mut self) -> Self {
        for ib in &self.bridge.inbounds {
            let i = ib.clone();
            let h = thread::spawn(move || {
                let _ = i.start(sb_types::StartStage::Start);
            });
            self.workers.push(h);
        }
        let endpoints = self.bridge.endpoints.clone();
        let services = self.bridge.services.clone();
        start_endpoints(&endpoints);
        start_services(&services);
        self
    }
    /// Optionally enable health check task.
    /// 可选启用健康探测。
    pub fn with_health(mut self) -> Self {
        let br = self.bridge.clone();
        let h = health::spawn_health_task(br);
        self.health = Some(h);
        self
    }
    /// Simple "soft shutdown": currently only aborts background threads (called in test environment).
    /// 简单的"软关闭"：当前仅中止后台线程（测试环境下调用）。
    pub fn shutdown(self) {
        // Currently does not forcibly kill threads; relies on process exit or future control channels.
        // 现阶段不强杀线程；交由进程退出，或未来增加控制通道。
        let _ = self;
    }
    /// Helper: clone engine as 'static view (for admin thread usage).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    pub const fn bridge(&self) -> &Arc<Bridge> {
        &self.bridge
    }

    /// Get switchboard reference for outbound connector access
    pub const fn switchboard(&self) -> &Arc<switchboard::OutboundSwitchboard> {
        &self.switchboard
    }

    /// Get supervisor reference for hot reload operations
    pub const fn supervisor(&self) -> Option<&Arc<supervisor::Supervisor>> {
        self.supervisor.as_ref()
    }

    /// Set supervisor for hot reload operations
    pub fn with_supervisor(mut self, supervisor: Arc<supervisor::Supervisor>) -> Self {
        self.supervisor = Some(supervisor);
        self
    }

    /// Create dummy engine for admin compatibility
    pub fn dummy_engine() -> Engine {
        use sb_config::ir::ConfigIR;
        let empty_ir = Arc::new(ConfigIR::default());
        Engine::new(empty_ir)
    }

    /// Create dummy bridge for admin compatibility
    pub fn dummy_bridge() -> Arc<Bridge> {
        Arc::new(Bridge::new(crate::context::Context::new()))
    }

    /// Create dummy switchboard for admin compatibility
    pub fn dummy_switchboard() -> Arc<switchboard::OutboundSwitchboard> {
        Arc::new(switchboard::OutboundSwitchboard::new())
    }
}
