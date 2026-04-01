use sb_config::ir::ConfigIR;

/// Apply debug/pprof options from config's experimental.debug section.
/// Sets environment variables for `SB_DEBUG_ADDR`, `SB_PPROF`, `SB_PPROF_FREQ`, `SB_PPROF_MAX_SEC`.
pub fn apply_debug_options(ir: &ConfigIR) {
    if let Some(exp) = ir.experimental.as_ref() {
        if let Some(debug) = exp.debug.as_ref() {
            if let Some(listen) = debug.listen.as_ref() {
                std::env::set_var("SB_DEBUG_ADDR", listen);
                std::env::set_var("SB_PPROF", "1");
                if std::env::var("SB_PPROF_FREQ").is_err() {
                    std::env::set_var("SB_PPROF_FREQ", "100");
                }
                if std::env::var("SB_PPROF_MAX_SEC").is_err() {
                    std::env::set_var("SB_PPROF_MAX_SEC", "60");
                }
            }
            if let Some(freq) = debug.gc_percent {
                tracing::info!(
                    gc_percent = freq,
                    "debug option gc_percent recorded (Go parity, no-op)"
                );
            }
            if let Some(limit) = debug.memory_limit {
                tracing::info!(
                    memory_limit = limit,
                    "debug option memory_limit recorded (Go parity, no-op)"
                );
            }
            if debug.panic_on_fault.is_some()
                || debug.max_stack.is_some()
                || debug.max_threads.is_some()
                || debug.trace_back.is_some()
                || debug.oom_killer.is_some()
            {
                tracing::info!(
                    "debug options recorded for parity; behavior is platform-dependent/no-op in Rust build"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::apply_debug_options;
    use sb_config::ir::{ConfigIR, DebugIR, ExperimentalIR};
    use serial_test::serial;

    const TRACKED_DEBUG_ENV: &[&str] = &[
        "SB_DEBUG_ADDR",
        "SB_PPROF",
        "SB_PPROF_FREQ",
        "SB_PPROF_MAX_SEC",
    ];

    struct ScopedDebugEnv {
        saved: Vec<(String, String)>,
    }

    impl ScopedDebugEnv {
        fn capture() -> Self {
            let saved = std::env::vars()
                .filter(|(key, _)| TRACKED_DEBUG_ENV.contains(&key.as_str()))
                .collect();
            clear_tracked_debug_env();
            Self { saved }
        }
    }

    impl Drop for ScopedDebugEnv {
        fn drop(&mut self) {
            clear_tracked_debug_env();
            for (key, value) in &self.saved {
                std::env::set_var(key, value);
            }
        }
    }

    fn clear_tracked_debug_env() {
        let keys: Vec<String> = std::env::vars()
            .map(|(key, _)| key)
            .filter(|key| TRACKED_DEBUG_ENV.contains(&key.as_str()))
            .collect();
        for key in keys {
            std::env::remove_var(key);
        }
    }

    fn env_var(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn debug_ir(listen: &str) -> ConfigIR {
        ConfigIR {
            experimental: Some(ExperimentalIR {
                debug: Some(DebugIR {
                    listen: Some(listen.to_string()),
                    ..DebugIR::default()
                }),
                ..ExperimentalIR::default()
            }),
            ..ConfigIR::default()
        }
    }

    #[test]
    #[serial]
    fn applies_debug_listen_and_default_pprof_env() {
        let _guard = ScopedDebugEnv::capture();

        apply_debug_options(&debug_ir("127.0.0.1:6060"));

        assert_eq!(env_var("SB_DEBUG_ADDR").as_deref(), Some("127.0.0.1:6060"));
        assert_eq!(env_var("SB_PPROF").as_deref(), Some("1"));
        assert_eq!(env_var("SB_PPROF_FREQ").as_deref(), Some("100"));
        assert_eq!(env_var("SB_PPROF_MAX_SEC").as_deref(), Some("60"));
    }

    #[test]
    #[serial]
    fn preserves_preexisting_pprof_overrides() {
        let _guard = ScopedDebugEnv::capture();
        std::env::set_var("SB_PPROF_FREQ", "250");
        std::env::set_var("SB_PPROF_MAX_SEC", "15");

        apply_debug_options(&debug_ir("127.0.0.1:7070"));

        assert_eq!(env_var("SB_DEBUG_ADDR").as_deref(), Some("127.0.0.1:7070"));
        assert_eq!(env_var("SB_PPROF").as_deref(), Some("1"));
        assert_eq!(env_var("SB_PPROF_FREQ").as_deref(), Some("250"));
        assert_eq!(env_var("SB_PPROF_MAX_SEC").as_deref(), Some("15"));
    }

    #[test]
    fn wp30ao_pin_debug_env_owner_moved_out_of_run_engine_rs() {
        let source = include_str!("debug_env.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("fn apply_debug_options"));
        assert!(run_engine.contains("run_engine_runtime::debug_env::apply_debug_options(ir)"));
        assert!(!run_engine.contains("std::env::set_var(\"SB_DEBUG_ADDR\""));
    }
}
