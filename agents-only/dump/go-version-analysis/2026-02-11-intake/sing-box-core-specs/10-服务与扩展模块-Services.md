# 10 服务与扩展模块（Services）

有些能力不属于“代理的主干”，却能在现实世界里解决关键痛点：比如系统服务集成、特定生态的 API 桥接、或为上层客户端提供统一控制面。

sing-box 把这类能力收拢在 `services[]` 中。

## 1) 总体要求

- MUST：支持 `services[]` 数组配置，每个 service 至少包含 `type`（以及必要字段）。
- SHOULD：服务的生命周期应与主进程绑定：启动时初始化、退出时清理资源，并在日志中可追踪。

## 2) Service 类型清单（官方文档导航列举）

内核 SHOULD 支持下列 service 类型（按官方文档导航列举）：

1. `derp`
2. `resolved`
3. `ssm_api`
4. `ccm`
5. `ocm`

> 注：这些服务并非所有部署都需要；但从“应具备的核心能力”角度，内核至少需要有相应模块或可选编译开关来覆盖它们。

## 3) 重点服务功能需求（按文档现有信息抽象）

### 3.1 DERP

- SHOULD：提供 DERP 中继/服务能力（常与 Tailscale/分布式网络场景关联）。
- MUST：与 Endpoint/Tailscale 体系兼容（若启用）。

### 3.2 Resolved

- SHOULD：提供与 systemd-resolved 的服务级集成能力（区别于 `dns.server.type=resolved` 的“作为上游”模式）。
- SHOULD：保证在 Linux 系统中行为可预测，失败时给出明确原因（权限/套接字/依赖等）。

### 3.3 SSM API（API Bridge）

- MUST（若启用）：暴露一组 HTTP API 端点，为上层客户端提供统一调用入口。  
  文档中出现的能力包括：  
  - `/v1/claude`  
  - `/v1/chat/completions`  
  - `/v1/usage`、`/v1/usage_status`（用量/统计）  
- SHOULD：提供鉴权/访问控制机制（避免无意暴露本地服务）。
- SHOULD：与 `log` 联动，记录请求维度的诊断信息（注意隐私与敏感信息脱敏）。

### 3.4 CCM（Claude Code 相关）

- MUST（若启用）：提供面向 Claude Code 生态的一组端点。文档中出现的路径包括：  
  - `/token`  
  - `/api_key`  
  - `/claude_api_key`  
  - `/claude_ai_token`  
- SHOULD：同样提供鉴权与最小暴露面（localhost 默认，或受控监听）。

### 3.5 OCM（OpenAI 相关）

- MUST（若启用）：提供面向 OpenAI 生态的桥接/管理能力（具体字段与端点以官方 OCM 文档为准）。
- SHOULD：与 SSM API 的通用路径（如 `/v1/chat/completions`）保持一致或可配置映射，减少上层适配成本。

## 4) 安全与默认策略（强烈建议）

- MUST：服务默认不应暴露到公网（除非用户显式配置监听地址/鉴权）。
- SHOULD：对所有 API 服务提供：
  - 访问日志（可关闭）
  - 基本限流/防滥用（可选）
  - 错误码与结构化响应

## 5) 验收清单

- services[] 可按 type 启动/停止，失败可定位。
- 启用 ssm_api/ccm/ocm 时，端点行为与文档一致，并具备最小安全默认值。

## 来源链接（官方文档）

- Service 总览（类型列表）  
  https://sing-box.sagernet.org/configuration/service/
- DERP / Resolved / SSM API / CCM / OCM  
  https://sing-box.sagernet.org/configuration/service/derp/  
  https://sing-box.sagernet.org/configuration/service/resolved/  
  https://sing-box.sagernet.org/configuration/service/ssm-api/  
  https://sing-box.sagernet.org/configuration/service/ccm/  
  https://sing-box.sagernet.org/configuration/service/ocm/
