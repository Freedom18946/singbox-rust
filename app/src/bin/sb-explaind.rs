#![cfg(feature = "explain")]
#![cfg_attr(feature = "strict_warnings", deny(warnings))]
use hyper::{Body, Request, Response, StatusCode};
use sb_core::router::explain as ex;
use sb_core::router::explain::{ExplainQuery, ExplainResult};
use serde_json::{Map, Value};
use app::http_util;
use std::{net::SocketAddr, str::FromStr};
use url::form_urlencoded;

mod telemetry {
    pub use app::telemetry::*;
}

#[cfg(feature = "pprof")]
async fn collect_pprof(sec: u64, _freq: i32) -> Result<Vec<u8>, String> {
    // 本构建未链接 pprof 后端，统一返回占位 SVG，避免依赖引入。
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="640" height="60">
      <text x="10" y="35" font-size="16">pprof feature enabled but backend not linked; waited {}s</text></svg>"#,
        sec
    );
    Ok(svg.into_bytes())
}

fn to_dot(res: &ExplainResult) -> String {
    use std::fmt::Write;
    let mut s = String::from("digraph explain { rankdir=LR; ");
    for (i, st) in res.steps.iter().enumerate() {
        let shape = if st.matched { "box" } else { "ellipse" };
        let color = if st.matched { "green" } else { "gray" };
        let _ = write!(
            s,
            r#"n{} [label="{}\n{}\n{}", shape={}, color={}]; "#,
            i, st.phase, st.rule_id, st.reason, shape, color
        );
        if i > 0 {
            let _ = write!(s, "n{} -> n{}; ", i - 1, i);
        }
    }
    s.push('}');
    s
}

async fn handle(
    req: Request<Body>,
    router: std::sync::Arc<sb_core::router::engine::RouterHandle>,
) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path();
    if path == "/health" {
        return Ok(Response::new(Body::from("ok")));
    }
    if path == "/debug/pprof/status" {
        // 返回运行期状态（软/硬开关 + 平台）
        let body = serde_json::json!({
            "feature": "pprof",
            "env": std::env::var("SB_PPROF").ok(),
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH
        });
        return Ok(http_util::ok_json(body));
    }
    if path == "/debug/pprof" {
        if std::env::var("SB_PPROF").ok().as_deref() != Some("1") {
            return Ok(http_util::bad_request("pprof disabled"));
        }
        let mut req_sec = 10u64;
        if let Some(query) = req.uri().query() {
            for (k, v) in form_urlencoded::parse(query.as_bytes()) {
                if k == "sec" {
                    req_sec = v.parse().unwrap_or(10);
                }
            }
        }
        let max_sec = std::env::var("SB_PPROF_MAX_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        if req_sec > max_sec {
            return Ok(http_util::text(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "requested duration {}s exceeds SB_PPROF_MAX_SEC={}",
                    req_sec, max_sec
                ),
            ));
        }
        let sec = req_sec.min(max_sec).max(1);
        let freq = std::env::var("SB_PPROF_FREQ")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(100);
        #[cfg(feature = "pprof")]
        {
            return match collect_pprof(sec, freq).await {
                Ok(buf) => Ok(http_util::ok_octet("image/svg+xml", buf)),
                Err(e) => Ok(http_util::text(StatusCode::GATEWAY_TIMEOUT, e)),
            };
        }
        #[cfg(not(feature = "pprof"))]
        {
            return Ok(http_util::text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "pprof feature disabled".to_string(),
            ));
        }
    }
    if path == "/debug/explain/snapshot" {
        let idx = sb_core::router::get_index();
        let digest = sb_core::router::explain_index::snapshot_digest(&idx);
        let overrides =
            idx.ov_exact.len() + idx.ov_suffix.len() + usize::from(idx.ov_default.is_some());
        let body = serde_json::json!({
            "digest": digest,
            "counts": {
                "overrides": overrides,
                "cidrs": idx.cidr.len(),
                "geos": idx.geo.len(),
                "suffixes": idx.suffix.len(),
                "exacts": idx.exact.len(),
            }
        });
        return Ok(http_util::ok_json(body));
    }
    if path != "/debug/explain" {
        return Ok(http_util::not_found());
    }
    let q = req.uri().query().unwrap_or("");
    let mut sni: Option<String> = None;
    let mut ip: Option<std::net::IpAddr> = None;
    let mut port: u16 = 0;
    let mut proto: &str = "tcp";
    let mut format: &str = "json";
    for (k, v) in form_urlencoded::parse(q.as_bytes()) {
        match k.as_ref() {
            "sni" => {
                if !v.is_empty() {
                    sni = Some(v.into_owned());
                }
            }
            "ip" => {
                ip = std::net::IpAddr::from_str(&v).ok();
                if ip.is_none() {
                    return Ok(http_util::bad_request("invalid ip"));
                }
            }
            "port" => {
                port = v.parse().unwrap_or(0);
            }
            "proto" => {
                if v == "tcp" || v == "udp" {
                    proto = Box::leak(v.into_owned().into_boxed_str());
                } else {
                    return Ok(http_util::bad_request("proto must be tcp|udp"));
                }
            }
            "format" => {
                if v == "json" || v == "dot" {
                    format = Box::leak(v.into_owned().into_boxed_str());
                } else {
                    return Ok(http_util::bad_request("format must be json|dot"));
                }
            }
            _ => {}
        }
    }
    let trace_id = if std::env::var("SB_TRACE_ID").ok().as_deref() == Some("1") {
        Some(crate::telemetry::next_trace_id())
    } else {
        None
    };

    if let Err(err) = router.export_and_rebuild() {
        let mut decision = Map::new();
        decision.insert("phase".into(), Value::String("default".into()));
        decision.insert("rule_id".into(), Value::String("default".into()));
        decision.insert("reason".into(), Value::String("export_failed".into()));
        decision.insert("steps".into(), Value::Array(Vec::new()));
        let mut trace = Map::new();
        trace.insert("error".into(), Value::String(err));
        if let Some(id) = trace_id.clone() {
            trace.insert("trace_id".into(), Value::String(id));
        }
        let body = ex::envelope_from_parts(decision, trace);
        return Ok(http_util::service_unavailable_json(body));
    }

    let res = ex::explain_decision(
        &router,
        ExplainQuery {
            sni,
            ip,
            port,
            proto,
            transport: None,
        },
    );
    match format {
        "json" => {
            let mut trace = Map::new();
            if let Some(id) = trace_id {
                trace.insert("trace_id".into(), Value::String(id));
            }
            let body = ex::envelope_from_result(&res, trace);
            Ok(http_util::ok_json(body))
        }
        "dot" => {
            let body = to_dot(&res);
            Ok(Response::builder()
                .header("content-type", "text/vnd.graphviz")
                .body(Body::from(body))
                .unwrap())
        }
        _ => unreachable!(),
    }
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "panic_log")]
    app::panic::install();
    #[cfg(feature = "hardening")]
    app::hardening::apply();
    let addr: SocketAddr = std::env::var("SB_DEBUG_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18089".into())
        .parse()
        .expect("SB_DEBUG_ADDR");
    eprintln!("[explaind] listen http://{}", addr);
    let router = std::sync::Arc::new(sb_core::router::engine::RouterHandle::from_env());
    #[cfg(feature = "explain")]
    sb_core::router::explain_index::rebuild_periodic(
        sb_core::router::engine::RouterHandle::from_env(),
    );
    let svc = hyper::service::make_service_fn(move |_| {
        let router = router.clone();
        async move {
            Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                handle(req, router.clone())
            }))
        }
    });
    hyper::Server::bind(&addr).serve(svc).await.unwrap();
}
