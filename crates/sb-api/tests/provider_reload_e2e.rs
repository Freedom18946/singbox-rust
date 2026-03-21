#![cfg(feature = "provider-reload")]

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, routing::get, Router};
use reqwest::{Client, StatusCode};
use sb_api::clash::ClashApiServer;
use sb_api::managers::{Provider, ProviderManager};
use sb_api::types::ApiConfig;
use sb_config::ir::{ConfigIR, OutboundIR, OutboundType};
use sb_core::runtime::supervisor::Supervisor;
use tokio::sync::RwLock;

#[derive(Clone)]
struct MockProviderState {
    body: Arc<RwLock<String>>,
}

struct MockProviderServer {
    addr: SocketAddr,
    body: Arc<RwLock<String>>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockProviderServer {
    async fn start(initial_body: &str) -> anyhow::Result<Option<Self>> {
        let listener =
            match tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
                Ok(listener) => listener,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    eprintln!("skipping provider reload e2e: PermissionDenied binding mock server");
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };
        let addr = listener.local_addr()?;
        let body = Arc::new(RwLock::new(initial_body.to_string()));
        let state = MockProviderState {
            body: Arc::clone(&body),
        };
        let app = Router::new()
            .route(
                "/provider",
                get(|State(state): State<MockProviderState>| async move {
                    state.body.read().await.clone()
                }),
            )
            .with_state(state);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok(Some(Self {
            addr,
            body,
            _task: task,
        }))
    }

    async fn set_body(&self, body: &str) {
        *self.body.write().await = body.to_string();
    }

    fn url(&self) -> String {
        format!("http://{}/provider", self.addr)
    }
}

struct ApiTestServer {
    base_url: String,
    client: Client,
    _task: tokio::task::JoinHandle<()>,
}

impl ApiTestServer {
    async fn start(provider_manager: Arc<ProviderManager>) -> anyhow::Result<Option<Self>> {
        let config = ApiConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            enable_cors: true,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: true,
            enable_logs_ws: true,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let listener =
            match tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
                Ok(listener) => listener,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    eprintln!("skipping provider reload e2e: PermissionDenied binding api server");
                    return Ok(None);
                }
                Err(err) => return Err(err.into()),
            };
        let addr = listener.local_addr()?;
        let server = ClashApiServer::new(config)?.with_provider_manager(provider_manager);
        let app = server.create_app();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(Some(Self {
            base_url: format!("http://{}", addr),
            client: Client::new(),
            _task: task,
        }))
    }

    async fn put(&self, path: &str) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .client
            .put(format!("{}{}", self.base_url, path))
            .json(&serde_json::json!({}))
            .send()
            .await?)
    }
}

fn initial_ir() -> ConfigIR {
    ConfigIR {
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("base-direct".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn wait_for_condition<F, Fut>(mut check: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..40 {
        if check().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("timed out waiting for condition")
}

#[tokio::test]
async fn proxy_provider_http_update_replaces_runtime_outbounds() -> anyhow::Result<()> {
    std::env::set_var("SB_INBOUND_RELOAD_GRACE_MS", "0");

    let Some(mock) = MockProviderServer::start(
        r#"[
          {"ty":"direct","name":"provider-a"}
        ]"#,
    )
    .await?
    else {
        return Ok(());
    };

    let supervisor = Supervisor::start(initial_ir()).await?;
    let provider_manager = Arc::new(
        ProviderManager::default().with_reload_channel(supervisor.handle().reload_sender()),
    );

    let mut provider = Provider::new("sub1".to_string(), "proxy".to_string());
    provider.url = Some(mock.url());
    provider_manager.add_proxy_provider(provider).await?;

    let Some(api) = ApiTestServer::start(Arc::clone(&provider_manager)).await? else {
        supervisor.shutdown_graceful(Duration::from_secs(1)).await?;
        return Ok(());
    };

    let response = api.put("/providers/proxies/sub1").await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    wait_for_condition(|| {
        let supervisor = supervisor.handle();
        async move {
            let state = supervisor.state().await;
            let guard = state.read().await;
            guard
                .current_ir
                .outbounds
                .iter()
                .any(|ob| ob.name.as_deref() == Some("provider-a"))
        }
    })
    .await?;

    mock.set_body(
        r#"[
          {"ty":"direct","name":"provider-b"}
        ]"#,
    )
    .await;

    let response = api.put("/providers/proxies/sub1").await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    wait_for_condition(|| {
        let supervisor = supervisor.handle();
        async move {
            let state = supervisor.state().await;
            let guard = state.read().await;
            let names: Vec<_> = guard
                .current_ir
                .outbounds
                .iter()
                .filter_map(|ob| ob.name.as_deref())
                .collect();
            names.contains(&"provider-b") && !names.contains(&"provider-a")
        }
    })
    .await?;

    supervisor.shutdown_graceful(Duration::from_secs(1)).await?;
    Ok(())
}

#[tokio::test]
async fn rule_provider_http_update_replaces_runtime_rules() -> anyhow::Result<()> {
    std::env::set_var("SB_INBOUND_RELOAD_GRACE_MS", "0");

    let Some(mock) = MockProviderServer::start("DOMAIN,alpha.example").await? else {
        return Ok(());
    };

    let supervisor = Supervisor::start(initial_ir()).await?;
    let provider_manager = Arc::new(
        ProviderManager::default().with_reload_channel(supervisor.handle().reload_sender()),
    );

    let mut provider = Provider::new("rules1".to_string(), "rule".to_string());
    provider.url = Some(mock.url());
    provider_manager.add_rule_provider(provider).await?;

    let Some(api) = ApiTestServer::start(Arc::clone(&provider_manager)).await? else {
        supervisor.shutdown_graceful(Duration::from_secs(1)).await?;
        return Ok(());
    };

    let response = api.put("/providers/rules/rules1").await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    wait_for_condition(|| {
        let supervisor = supervisor.handle();
        async move {
            let state = supervisor.state().await;
            let guard = state.read().await;
            guard
                .current_ir
                .route
                .rules
                .iter()
                .any(|rule| rule.domain.iter().any(|domain| domain == "alpha.example"))
        }
    })
    .await?;

    mock.set_body("DOMAIN,beta.example").await;

    let response = api.put("/providers/rules/rules1").await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    wait_for_condition(|| {
        let supervisor = supervisor.handle();
        async move {
            let state = supervisor.state().await;
            let guard = state.read().await;
            let domains: Vec<_> = guard
                .current_ir
                .route
                .rules
                .iter()
                .flat_map(|rule| rule.domain.iter())
                .cloned()
                .collect();
            domains.contains(&"beta.example".to_string())
                && !domains.contains(&"alpha.example".to_string())
        }
    })
    .await?;

    supervisor.shutdown_graceful(Duration::from_secs(1)).await?;
    Ok(())
}
