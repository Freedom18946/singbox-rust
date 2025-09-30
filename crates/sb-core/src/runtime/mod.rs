//! Process runtime: hold Engine/Bridge, spawn inbounds, optional health task.
use crate::adapter::Bridge;
use crate::health;
#[cfg(feature = "router")]
use crate::routing::engine::Engine;
#[cfg(feature = "router")]
use sb_config::ir::ConfigIR;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub mod supervisor;
pub mod switchboard;

#[cfg(feature = "router")]
pub struct Runtime<'a> {
    pub engine: Engine<'a>,
    pub bridge: Arc<Bridge>,
    pub switchboard: Arc<switchboard::OutboundSwitchboard>,
    workers: Vec<JoinHandle<()>>,
    health: Option<JoinHandle<()>>,
    supervisor: Option<Arc<supervisor::Supervisor>>,
}

#[cfg(not(feature = "router"))]
pub struct Runtime<'a> {
    _phantom: std::marker::PhantomData<&'a ()>,
    pub bridge: Arc<Bridge>,
    pub switchboard: Arc<switchboard::OutboundSwitchboard>,
    workers: Vec<JoinHandle<()>>,
    health: Option<JoinHandle<()>>,
    supervisor: Option<Arc<supervisor::Supervisor>>,
}

#[cfg(feature = "router")]
impl<'a> Runtime<'a> {
    pub fn new(
        engine: Engine<'a>,
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

    /// Create runtime from configuration IR
    pub fn from_config_ir(ir: &'a ConfigIR) -> crate::error::SbResult<Self> {
        let engine = Engine::new(ir);
        let bridge = Bridge::new_from_config(ir)
            .map_err(|e| crate::error::SbError::config(
                sb_types::IssueCode::SchemaInvalid,
                "bridge_init",
                format!("Failed to initialize bridge from IR: {}", e)
            ))?;
        let switchboard = switchboard::SwitchboardBuilder::from_config_ir(ir)?;
        Ok(Self::new(engine, bridge, switchboard))
    }
}

#[cfg(not(feature = "router"))]
impl<'a> Runtime<'a> {
    pub fn new(_engine: (), bridge: Bridge, switchboard: switchboard::OutboundSwitchboard) -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            bridge: Arc::new(bridge),
            switchboard: Arc::new(switchboard),
            workers: vec![],
            health: None,
            supervisor: None,
        }
    }
}

impl<'a> Runtime<'a> {
    /// 启动所有入站（bridge 中已构造）
    pub fn start(mut self) -> Self {
        for ib in &self.bridge.inbounds {
            let i = ib.clone();
            let h = thread::spawn(move || {
                let _ = i.serve();
            });
            self.workers.push(h);
        }
        self
    }
    /// 可选启用健康探测
    pub fn with_health(mut self) -> Self {
        let br = self.bridge.clone();
        let h = health::spawn_health_task(br);
        self.health = Some(h);
        self
    }
    /// 简单的"软关闭"：当前仅中止后台线程（测试环境下调用）
    pub fn shutdown(self) {
        // 现阶段不强杀线程；交由进程退出，或未来增加控制通道
        let _ = self;
    }
    /// Helper: clone engine as 'static view (for admin thread usage).
    #[cfg(feature = "router")]
    pub fn engine(&self) -> &Engine<'a> {
        &self.engine
    }

    #[cfg(not(feature = "router"))]
    pub fn engine(&self) -> Result<(), anyhow::Error> {
        anyhow::bail!("app built without `router` feature")
    }
    pub fn bridge(&self) -> &Arc<Bridge> {
        &self.bridge
    }

    /// Get switchboard reference for outbound connector access
    pub fn switchboard(&self) -> &Arc<switchboard::OutboundSwitchboard> {
        &self.switchboard
    }

    /// Get supervisor reference for hot reload operations
    pub fn supervisor(&self) -> Option<&Arc<supervisor::Supervisor>> {
        self.supervisor.as_ref()
    }

    /// Set supervisor for hot reload operations
    pub fn with_supervisor(mut self, supervisor: Arc<supervisor::Supervisor>) -> Self {
        self.supervisor = Some(supervisor);
        self
    }

    /// Create dummy engine for admin compatibility
    #[cfg(feature = "router")]
    pub fn dummy_engine() -> Engine<'static> {
        use sb_config::ir::ConfigIR;
        let empty_ir = ConfigIR::default();
        Engine::new(Box::leak(Box::new(empty_ir)))
    }

    #[cfg(not(feature = "router"))]
    pub fn dummy_engine() -> Result<(), anyhow::Error> {
        anyhow::bail!("app built without `router` feature")
    }

    /// Create dummy bridge for admin compatibility
    pub fn dummy_bridge() -> Arc<Bridge> {
        Arc::new(Bridge::new())
    }

    /// Create dummy switchboard for admin compatibility
    pub fn dummy_switchboard() -> Arc<switchboard::OutboundSwitchboard> {
        Arc::new(switchboard::OutboundSwitchboard::new())
    }
}

#[cfg(feature = "router")]
impl<'a> Engine<'a> {
    /// Produce an Engine<'static> that references the same config (safe because config lives for process lifetime).
    ///
    /// # Safety
    /// This is safe because the configuration is guaranteed to live for the entire process lifetime.
    /// The caller must ensure that the referenced ConfigIR outlives the returned Engine<'static>.
    pub fn clone_as_static(&self) -> Engine<'static> {
        // SAFETY:
        // - 不变量：self.cfg 指向有效的 ConfigIR，设计上具有进程生命周期
        // - 并发/别名：调用者必须确保 ConfigIR 的生命周期长于返回的 Engine<'static>
        // - FFI/平台契约：生命周期转换基于设计保证，不涉及内存布局变更
        let static_cfg: &'static ConfigIR = unsafe { std::mem::transmute(self.cfg) };
        Engine::new(static_cfg)
    }
}
