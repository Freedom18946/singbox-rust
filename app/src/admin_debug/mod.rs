#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_doc_comments,
    unused_comparisons,
    clippy::future_not_send,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::items_after_statements,
    clippy::await_holding_lock,
    clippy::cast_possible_truncation,
    clippy::assigning_clones,
    clippy::no_effect_underscore_binding,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::implicit_hasher,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::result_large_err,
    clippy::match_same_arms,
    clippy::must_use_candidate,
    clippy::borrow_deref_ref,
    clippy::useless_vec,
    // Additional relaxations for monitoring/metrics code
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::type_complexity,
    clippy::verbose_bit_mask,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value,
    // Additional style relaxations
    clippy::ref_option,
    clippy::use_debug,
    clippy::format_push_string,
    clippy::significant_drop_tightening,
    clippy::fn_params_excessive_bools,
    clippy::if_same_then_else,
    clippy::single_match_else,
    clippy::trivial_regex,
    clippy::collection_is_never_read,
    clippy::should_implement_trait,
    clippy::struct_excessive_bools,
    clippy::unused_self
)] // Admin debug functionality allows relaxed linting standards

pub mod audit;
pub mod breaker;
pub mod cache;
pub mod endpoints;
pub mod http;
pub mod http_server;
pub mod http_util;
pub mod prefetch;
pub mod reloadable;
pub mod security;
pub mod security_async;
pub mod security_metrics;

#[cfg(feature = "auth")]
pub mod auth;

pub mod middleware;

// Note: http_server contains the plain HTTP admin server functionality
// while http/ contains redirect policies and other HTTP utilities

/// Initialize admin debug server if enabled
pub async fn init(addr: Option<&str>) {
    let bind_addr = match addr {
        Some(a) => a.to_string(),
        None => std::env::var("SB_DEBUG_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string()),
    };

    // Initialize SIGHUP signal handler for configuration reloading
    reloadable::init_signal_handler();

    if let Err(e) = http_server::serve_plain(&bind_addr).await {
        tracing::error!(error = %e, "failed to start admin debug server");
    }
}
