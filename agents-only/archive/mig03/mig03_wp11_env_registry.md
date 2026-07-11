<!-- tier: B -->
# MIG-03 WP11 环境变量登记表

状态：DONE（2026-07-11）

## 口径

本表登记 WP11 从 `sb-core` 上收的全部 141 个兼容变量。旧读取点来自 WP11 基线 census；迁移后唯一解析点为 `app/src/core_env.rs`，唯一缺省值权威为 `crates/sb-core/src/runtime_options.rs` 各域 `Default`。两处由 `parser_empty_environment_matches_core_defaults` 逐结构相等断言锁定，避免复制易漂移的数字。所有变量保留；无废弃、无白名单 core 读取、无运行中重读。

解析语义：布尔接受 `1/true/yes/on` 与 `0/false/no/off/空串`；数值解析失败记录 warning 并回落旧缺省；可选字符串 trim 后空值视为 None；地址/路径解析失败保持旧回落语义。消费时机统一为 app 启动组合期一次，随后通过 `CoreRuntimeOptions` 注入 supervisor、Context、Bridge、DNS/router/net/service/debug 消费方。

## Core 迁移登记

| 变量 | 域 | 读取点迁移 | 类型/解析 | 注入去向与缺省值 | 时机 |
|---|---|---|---|---|---|
| `SB_ACCESS_LOG` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_FIRSTBYTE_TIMEOUT_MS` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_FIRSTLINE_TIMEOUT_MS` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_MAX_BODY_BYTES` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_MAX_CONN_PER_IP` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_MAX_HEADER_BYTES` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_MAX_RPS_PER_IP` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_READ_TIMEOUT_MS` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ADMIN_WRITE_TIMEOUT_MS` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_BUFFER_POOL_MAX_CAPACITY` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_BUFFER_POOL_SIZE` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_CB_ENABLE` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DIAL_TIMEOUT_MS` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DIAL_USE_ALL` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_CAP` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_CLEANUP_INTERVAL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_ENABLE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_MAX` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_NEG_TTL_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_SIZE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_STALE_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CACHE_TTL_SEC` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_CLIENT_SUBNET` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DEFAULT_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DHCP_RESOLV_CONF` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOH3_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOH_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOH_URL` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOQ_ADDR` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOQ_SERVER_NAME` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOQ_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOT_ADDR` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_DOT_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_ENABLE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_FAKEIP_ENABLE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_FAKEIP_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_FAKEIP_V6` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_FALLBACK` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_HE_ORDER` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_HE_RACE_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_HOSTS_ENABLE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_HOSTS_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_IPV6` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_LOCAL_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_MAX_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_MIN_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_MODE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_NEGATIVE_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_NEG_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_PARALLEL` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_PER_HOST_INFLIGHT` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_POOL` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_POOL_MAX_INFLIGHT` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_POOL_STRATEGY` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_PREFETCH` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_PREFETCH_BEFORE_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_PREFETCH_CONCURRENCY` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_QTYPE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_QUERY_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_RACE_WINDOW_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_RESOLVED_STUB` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_RETRIES` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_SERVERS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_STATIC` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_STATIC_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_STRATEGY` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_SYSTEM_TTL_S` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_TCP_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_TTL` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_UDP_RETRIES` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_UDP_SERVER` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_UDP_TIMEOUT_MS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_DNS_UPSTREAM` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_EXPLAIN_REBUILD_MS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_FAILPOINTS` | Debug/Admin | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DebugRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_FAKEIP_CAP` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_FAKEIP_V4_BASE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_FAKEIP_V4_MASK` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_FAKEIP_V6_BASE` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_FAKEIP_V6_MASK` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_GEOIP_CACHE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_GEOIP_ENABLE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_GEOIP_MMDB` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_GEOIP_TTL` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_HEALTH_ENABLE` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_INBOUND_RATE_LIMIT_PER_IP` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_INBOUND_RATE_LIMIT_QPS` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_INBOUND_RATE_LIMIT_WINDOW_SEC` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_NETWORK_STRATEGY` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_NTP_INTERVAL_S` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_NTP_SERVER` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_NTP_TIMEOUT_MS` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_PROXY_HEALTH_ENABLE` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_PROXY_HEALTH_INTERVAL_MS` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_PROXY_HEALTH_TIMEOUT_MS` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_PUBLIC_SUFFIX_LIST` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DECIDE_BUDGET_MS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DECISION_CACHE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DECISION_CACHE_CAP` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DEFAULT_PROXY` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DEFAULT_PROXY_ADDR` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DEFAULT_PROXY_KIND` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DNS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DNS_TIMEOUT_MS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_DOMAIN_OVERRIDES` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_HOT_RELOAD` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_JSON_FILE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_JSON_TEXT` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_KEYWORD_AC_MIN` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_OVERRIDE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_BACKOFF_MAX_MS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_BASEDIR` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_ENABLE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_FILE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_FROM_JSON` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_HOT_RELOAD_MS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_INCLUDE_DEPTH` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_JITTER_MS` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_MAX` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_MAX_DEPTH` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_REQUIRE_DEFAULT` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_RULES_TEXT` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_SUFFIX_STRICT` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_SUFFIX_TRIE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_UDP` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_ROUTER_UDP_RULES` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_RULE_COVERAGE` | Router | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `RouterRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_RUNTIME_DIFF` | Service | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `ServiceRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_SOCKS_UDP_RESOLVE_BND` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_TAILSCALE_DNS_ADDRS` | DNS | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `DnsRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_TCP_PROXY_HTTP` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_TCP_PROXY_MODE` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_TCP_PROXY_TIMEOUT_MS` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_TRANSPORT_SNI_FALLBACK` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_UDP_GC_MS` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_UDP_NAT_MAX` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_UDP_OUTBOUND_BPS_MAX` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_UDP_OUTBOUND_PPS_MAX` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |
| `SB_UDP_TTL_MS` | Network | 原 core 分散读取点（基线 census）→ `app/src/core_env.rs` | bool/number/string/address/path；兼容解析器按字段选用 | `NetworkRuntimeOptions` 对应字段；精确缺省值锁定于 `Default` + app 空环境单测 | 启动组合期读取一次，构造后冻结 |

## 白名单

空。最终 `crates/sb-core/src/**/*.rs` 中不同 `SB_*` 字面量 0，直接 `SB_*` env 读取 0。

## 全仓非 core 附表

WP11 non-goal 保留 app、adapters、xtests、scripts、Makefile、文档中的变量消费。其权威枚举由下列命令实时生成，避免在本表复制 283 个易漂移名字：

```bash
rg -o 'SB_[A-Z0-9_]+' --glob '!target/**' --glob '!crates/sb-core/src/**' . | sort -u
```

这些变量不属于 core 白名单；其中上述 141 项由 app 解析并继续对外兼容，adapter 自有变量仍由 adapter 解析。后续迁移不得删除现有 CLI/xtest/script 入口。
