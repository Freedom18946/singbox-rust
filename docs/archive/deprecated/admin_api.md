# Admin API（Debug 实现）

## `/__health`（GET）
返回服务健康与构建信息，并包含：
* `auth_mode`、`mtls_status`
* `audit_latest_ts`
* `config_version`（每次真实 `apply` 自增）

## `/__config`（GET / PUT）

### RBAC 与鉴权
* Header `X-Role: viewer|admin`；仅 `admin` 允许 `PUT`
* 支持 mTLS/Bearer/HMAC，HMAC 校验规则：`hex(hmac_sha256(secret, ts + path))`

### Dry-Run
* `X-Config-Dryrun: 1` 时仅返回 **diff**，不落地，并记录审计（`ok=false,msg='dryrun'`）

### 幂等与版本
* 当 Patch 不产生变更时：`{"ok":true,"msg":"no changes","changed":false,"version":X,"diff":{}}`
* 仅当 `changed && !dry_run` 时版本号自增

### 示例
**Dry-Run：**
```bash
curl -sS -X PUT "$SB_ADMIN_URL/__config" \
  -H "Authorization: SB-HMAC admin:$ts:$sig" \
  -H "X-Role: admin" -H "X-Config-Dryrun: 1" \
  -d @patch.json | jq .
```
响应：
```json
{ "ok": false, "msg": "dryrun", "changed": true, "version": 5, "diff": { "replace": { "timeout_ms": [800, 1200] } } }
```

## 预取（Prefetch）
**触发条件**：主路径 `/subs/...` 成功（`200/304`）且 `Cache-Control: max-age>=60` 时，将 URL 入队异步预取；
**指标**：
* `sb_prefetch_queue_depth`：队列深度（Gauge）
* `sb_prefetch_jobs_total{event= enq|done|retry|fail }`：任务事件计数
* `sb_prefetch_run_seconds_bucket`：worker 执行用时直方图
* `cache_hit_total`：缓存命中

**开关/容量**：
* `SB_PREFETCH_ENABLE=1`
* `SB_PREFETCH_CAP`（默认 256）
* `SB_PREFETCH_WORKERS`（默认 2）
* `SB_PREFETCH_RETRIES`（默认 3）

**回滚**：仅需置 `SB_PREFETCH_ENABLE=0`。