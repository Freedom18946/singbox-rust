//! Service lifecycle port.
//!
//! # Strategic Purpose
//! These traits define the lifecycle contract for services (DERP, SSM, Resolved, etc.)
//! and generic components that support staged initialization.
//!
//! sb-core and sb-adapters both use these traits.
//! Concrete implementations live in sb-core (managers) and sb-adapters (services).

use std::fmt;

/// Lifecycle stages for service/component initialization.
///
/// Components are started in order: Initialize → Start → PostStart → Started.
/// Each stage allows progressively more dependencies to be available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StartStage {
    /// Initialize resources (allocate, configure, but don't connect).
    Initialize,
    /// Start the component (open connections, begin listening).
    Start,
    /// Post-start configuration (register with other components).
    PostStart,
    /// Startup complete (all components are ready).
    Started,
}

impl fmt::Display for StartStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialize => f.write_str("Initialize"),
            Self::Start => f.write_str("Start"),
            Self::PostStart => f.write_str("PostStart"),
            Self::Started => f.write_str("Started"),
        }
    }
}

/// Service trait for background services.
///
/// Services (like Resolved/DERP/SSM) implement this trait to provide
/// background functionality with lifecycle management.
///
/// This is the contract between sb-core (which manages services) and
/// sb-adapters (which implements them).
pub trait Service: Send + Sync {
    /// Return the service type (e.g., "resolved", "derp", "ssm-api").
    fn service_type(&self) -> &str;

    /// Return the service tag/identifier.
    fn tag(&self) -> &str;

    /// Start the service at a specific lifecycle stage.
    ///
    /// # Errors
    /// Returns an error if the service fails to start.
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop and clean up the service.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Lifecycle trait for components with staged initialization.
///
/// This trait is similar to `Service` but without service-specific methods like
/// `service_type()` and `tag()`. It's used by inbound/outbound handlers that
/// need lifecycle management but aren't full services.
pub trait Lifecycle: Send + Sync {
    /// Start at a specific lifecycle stage.
    ///
    /// # Errors
    /// Returns an error if starting at this stage fails.
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Stop and clean up resources.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Trait for components that support lifecycle stages.
///
/// Similar to `Lifecycle` but with a default `close()` implementation.
/// Used by managers and infrastructure components in sb-core's Context.
pub trait Startable: Send + Sync {
    /// Start the component at a specific lifecycle stage.
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Close the component and release resources.
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

/// Numeric rank of a `StartStage` for ordering comparisons.
///
/// Useful for idempotent lifecycle managers that skip already-completed stages.
#[inline]
pub fn stage_rank(stage: StartStage) -> u8 {
    match stage {
        StartStage::Initialize => 0,
        StartStage::Start => 1,
        StartStage::PostStart => 2,
        StartStage::Started => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_stage_ordering() {
        assert!(stage_rank(StartStage::Initialize) < stage_rank(StartStage::Start));
        assert!(stage_rank(StartStage::Start) < stage_rank(StartStage::PostStart));
        assert!(stage_rank(StartStage::PostStart) < stage_rank(StartStage::Started));
    }

    #[test]
    fn start_stage_display() {
        assert_eq!(StartStage::Initialize.to_string(), "Initialize");
        assert_eq!(StartStage::Start.to_string(), "Start");
        assert_eq!(StartStage::PostStart.to_string(), "PostStart");
        assert_eq!(StartStage::Started.to_string(), "Started");
    }

    #[test]
    fn service_trait_object_safety() {
        // Verify Service can be used as trait object
        struct DummyService;
        impl Service for DummyService {
            fn service_type(&self) -> &str { "dummy" }
            fn tag(&self) -> &str { "svc" }
            fn start(&self, _stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }
        }

        let svc: Box<dyn Service> = Box::new(DummyService);
        assert_eq!(svc.service_type(), "dummy");
        assert_eq!(svc.tag(), "svc");
        assert!(svc.start(StartStage::Initialize).is_ok());
        assert!(svc.close().is_ok());
    }

    #[test]
    fn lifecycle_trait_object_safety() {
        struct DummyLifecycle;
        impl Lifecycle for DummyLifecycle {
            fn start(&self, _stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { Ok(()) }
        }

        let lc: Box<dyn Lifecycle> = Box::new(DummyLifecycle);
        assert!(lc.start(StartStage::Start).is_ok());
        assert!(lc.close().is_ok());
    }
}
