<!-- tier: B -->
# MIG-03 WP08 — Router stack responsibility map

Date: 2026-07-11
Scope: pre-change census for `router/`, `routing/`, and DNS matcher consumers.

## 1. Implementation homes before merge

| Source | Responsibility | Disposition |
|---|---|---|
| `router/mod.rs` | compiled `RouterIndex`, public route context, env compatibility | canonical |
| `router/engine.rs` | `RouterHandle`, lock-free index reads, DNS/GeoIP integration | canonical |
| `router/rules.rs` | typed rules and bucketed legacy rule evaluator | retain; rename evaluator to `RuleEngine` |
| `router/matcher.rs` | reusable domain and CIDR primitives | canonical matcher primitives |
| `router/ruleset/*` | Go-shaped rule-set model and `RuleMatcher` | canonical; also consumed by DNS |
| `router/{hot_reload,explain,trace support}` | production hot reload and indexed explain | canonical |
| `routing/engine.rs` | ConfigIR decision/explain facade used by supervisor and bridge | move under `router/` |
| `routing/explain.rs`, `routing/trace.rs` | ConfigIR explain DTO and trace | move under `router/` |
| `routing/matcher.rs`, `routing/router.rs` | isolated toy matcher/reload router | delete; hot-reload bin switches to `RouterHandle` |
| `routing/ir.rs` | unused duplicate local IR | delete; `sb_config::ir` remains canonical |

Duplicate pairs: `routing/engine.rs` wraps a separately constructed `RouterHandle`;
`routing/matcher.rs` duplicates `router` domain matching; `routing/router.rs` duplicates
`RouterHandle` reload ownership. `routing/explain.rs` is a separate ConfigIR explain schema,
not the indexed `router/explain.rs` schema, so it moves with an explicit name and a JSON
regression lock rather than being silently conflated.

## 2. Consumer census

- Runtime/core: `runtime/{mod,supervisor}.rs`, `adapter/{mod,bridge,registry}.rs`,
  `admin/http.rs` consume ConfigIR `Engine`/`Input`.
- App: preflight, probe-outbound, route-explain, route CLI/tools and runtime tests consume
  `routing::engine` or `routing::ExplainEngine`.
- Data-plane adapters already consume canonical `sb_core::router::{RouterHandle,RouteCtx}`.
- `rule-hot-reload` alone consumes `routing::router::{Router,RouterConfig}`.
- DNS `rule_engine.rs` already consumes `router::ruleset::matcher::RuleMatcher`; no local
  exact/suffix/keyword/regex matcher implementation remains there.

## 3. Target shape

- `router/` is sole implementation home.
- Public ConfigIR facade is `router::{Engine, Input, ExplainEngine}`.
- `routing/` remains one compatibility module (WP14 removal), re-exporting canonical types;
  no implementation lives below it.
- `Engine::handle()` no longer constructs `RouterHandle::from_env()`; bridge/supervisor keep
  explicit ConfigIR construction paths, ready for WP11 configuration injection.
- Domain suffix boundary semantics live in `router::matcher` and are reused by ConfigIR and
  rule-set matching. DNS inherits them through `RuleMatcher`.

## 4. Baseline metrics

- `routing/`: 7 files / 1,487 LOC.
- `router/`: 49 top-level files / 20,149 LOC (ruleset children excluded from this file count).
- Router-domain public structs named `Engine`: ConfigIR `routing::engine::Engine` plus
  `router::rules::Engine`.
- DNS matcher implementation count: zero local implementations; one shared
  `router::ruleset::RuleMatcher` consumer path.

## 5. Accepted result

- `routing/`: 1 file / 25 LOC compatibility facade; implementation files 7 → 0.
- `router/`: 52 top-level files / 21,293 LOC after receiving ConfigIR engine/explain/trace.
- Combined top-level router-domain LOC: 21,636 → 21,318 (-318); duplicate toy matcher,
  router/reload, and IR implementations removed.
- Router-domain `pub struct Engine`: 2 → 1. Legacy bucket evaluator is now `RuleEngine`.
- Domain suffix boundary logic has one primitive in `router::matcher`; ConfigIR engine and
  rule-set matcher share it. DNS keeps using shared `RuleMatcher`, with no local domain matcher.
- All production/test consumers use `router::{Engine, Input, ExplainEngine}`; `routing/` exists
  only for one compatibility cycle and is marked for WP14 deletion.
