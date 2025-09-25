#![cfg(feature = "rule_coverage")]
#![cfg_attr(feature = "strict_warnings", deny(warnings))]
use hyper::{Body, Request, Response, StatusCode};

#[tokio::main]
async fn main() {
    let addr: std::net::SocketAddr = std::env::var("SB_COV_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18090".into())
        .parse()
        .unwrap();
    tracing::info!(target: "app::coverage-http", %addr, "listen");
    let svc = hyper::service::make_service_fn(move |_| async move {
        Ok::<_, hyper::Error>(hyper::service::service_fn(
            |req: Request<Body>| async move {
                let path = req.uri().path();
                if path == "/health" {
                    return Ok::<Response<Body>, hyper::Error>(Response::new(Body::from("ok")));
                }
                if path == "/debug/coverage" {
                    let q = req.uri().query().unwrap_or("");
                    if q.contains("reset=1") {
                        sb_core::router::coverage::reset();
                    }
                    let body = serde_json::to_vec(&sb_core::router::coverage::snapshot()).unwrap();
                    return Ok::<Response<Body>, hyper::Error>(
                        Response::builder()
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    );
                }
                Ok::<Response<Body>, hyper::Error>(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .unwrap(),
                )
            },
        ))
    });
    hyper::Server::bind(&addr).serve(svc).await.unwrap();
}
