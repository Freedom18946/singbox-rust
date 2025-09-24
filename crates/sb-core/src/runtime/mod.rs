//! Process runtime: hold Engine/Bridge, spawn inbounds, optional health task.
use crate::adapter::Bridge;
use crate::health;
use crate::routing::engine::Engine;
use sb_config::ir::ConfigIR;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub mod supervisor;

pub struct Runtime<'a> {
    pub engine: Engine<'a>,
    pub bridge: Arc<Bridge>,
    workers: Vec<JoinHandle<()>>,
    health: Option<JoinHandle<()>>,
    supervisor: Option<Arc<supervisor::Supervisor>>,
}

impl<'a> Runtime<'a> {
    pub fn new(engine: Engine<'a>, bridge: Bridge) -> Self {
        Self {
            engine,
            bridge: Arc::new(bridge),
            workers: vec![],
            health: None,
            supervisor: None,
        }
    }
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
    pub fn engine(&self) -> &Engine<'a> {
        &self.engine
    }
    pub fn bridge(&self) -> &Arc<Bridge> {
        &self.bridge
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
    pub fn dummy_engine() -> Engine<'static> {
        use sb_config::ir::ConfigIR;
        let empty_ir = ConfigIR::default();
        Engine::new(Box::leak(Box::new(empty_ir)))
    }

    /// Create dummy bridge for admin compatibility
    pub fn dummy_bridge() -> Arc<Bridge> {
        Arc::new(Bridge::new())
    }
}

impl<'a> Engine<'a> {
    /// Produce an Engine<'static> that references the same config (safe because config lives for process lifetime).
    ///
    /// # Safety
    /// This is safe because the configuration is guaranteed to live for the entire process lifetime.
    /// The caller must ensure that the referenced ConfigIR outlives the returned Engine<'static>.
    pub fn clone_as_static(&self) -> Engine<'static> {
        // SAFETY: According to the design, config lives for process lifetime,
        // so extending the lifetime to 'static is safe in this context.
        let static_cfg: &'static ConfigIR = unsafe { std::mem::transmute(self.cfg) };
        Engine::new(static_cfg)
    }
}
