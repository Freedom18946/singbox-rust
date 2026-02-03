# depcheck baseline

生成时间：2026-02-03 13:12
命令：`python tools/depcheck/depcheck.py`

输出：

```
depcheck: violations found
- sb-adapters: sb-core (direct/dependencies)
- sb-core: axum (direct/dependencies)
- sb-core: axum-server (direct/dependencies)
- sb-core: h3 (direct/dependencies)
- sb-core: hyper (direct/dependencies)
- sb-core: quinn (direct/dependencies)
- sb-core: reqwest (direct/dependencies)
- sb-core: rustls (direct/dependencies)
- sb-core: sb-config (direct/dependencies)
- sb-core: sb-metrics (direct/dependencies)
- sb-core: sb-platform (direct/dependencies)
- sb-core: sb-tls (direct/dependencies)
- sb-core: sb-transport (direct/dependencies)
- sb-core: tokio-tungstenite (direct/dependencies)
- sb-core: tonic (direct/dependencies)
- sb-core: tower (direct/dependencies)
- sb-core: axum (transitive/transitive)
- sb-core: h2 (transitive/transitive)
- sb-core: hyper (transitive/transitive)
- sb-core: reqwest (transitive/transitive)
- sb-core: tonic (transitive/transitive)
- sb-core: tower (transitive/transitive)
- sb-core: tower-http (transitive/transitive)
```
