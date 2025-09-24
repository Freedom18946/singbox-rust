# singbox-rust Check Errors (v1)

> 错误码为**稳定契约**；新增码允许，**禁止**修改既有码的语义。

| Code               | Meaning                                   | Typical Pointer         | Fix hint                                  |
|--------------------|-------------------------------------------|-------------------------|-------------------------------------------|
| SCHEMA_VIOLATION   | 违反 JSON-Schema                          | /dns/mode               | 依文档修正字段/枚举                        |
| MISSING_FIELD      | 缺少必填字段                              | /inbounds/0/listen      | 增加字段                                  |
| INVALID_TYPE       | 类型不匹配                                | /route/rules/0/when/... | 改为数组/字符串等                          |
| INVALID_PORT       | 端口越界                                  | /inbounds/0/port        | 1..65535                                  |
| INVALID_ENUM       | 枚举非法                                  | /dns/mode               | system|udp|dot|doh                         |
| MUTUAL_EXCLUSIVE   | 互斥字段并存                              | /                       | 删除其一                                  |
| REF_MISSING        | 引用文件不存在                            | /rules_text             | 修正路径或提供文件                        |
| REF_UNREADABLE     | 引用文件不可读/非 UTF-8                   | /.../file               | 修正权限/编码                              |
| REF_TOO_LARGE      | 引用文件超限                              | /.../file               | 减小文件或调大 --max-ref-size             |
| CROSS_REF_MISSING  | 交叉引用缺失（proxy pool 不存在）         | /route/rules/i/to       | 在 outbounds[].name 中定义                |
| UNKNOWN_FIELD      | 未知字段（deny-unknown 触发）             | /inbounds/0/<key>       | 移除/升级                                 |
| DUPLICATE_NAME     | 名称重复                                  | /outbounds/i            | 调整为唯一                                |
| PORT_CONFLICT      | 监听端口冲突                              | /inbounds/i             | 修改端口或 listen                         |
| BAD_CIDR           | CIDR 格式错                               | /route/rules/i/when     | a.b.c.d/len                               |
| BAD_DOMAIN         | 域名格式错                                | /route/rules/i/when     | 允许 *.example.com                         |
| API_VERSION_MISSING| 建议设置 apiVersion                       | /apiVersion             | 设置为 singbox/v1                         |
| KIND_MISSING       | 建议设置 kind                             | /kind                   | 设置为 Config                             |
| API_VERSION_UNKNOWN| apiVersion 未知                           | /apiVersion             | 支持 singbox/v1                           |
| UNREACHABLE_RULE   | 规则不可达（被前序规则完全覆盖）           | /route/rules/i          | 调整顺序或收紧前序规则                     |
| SHADOWED_BY        | 规则被遮蔽（前序规则过于宽泛）             | /route/rules/i          | 前置该规则或添加 domain/cidr 限定          |
| EMPTY_RULE_MATCH   | 规则为空集                               | /route/rules/i          | 修正约束或删除                            |
| REDUNDANT_RULE     | 被前序完全覆盖                           | /route/rules/i          | 参考 --autofix-plan 重排                  |
| CONFLICTING_RULE   | 内部约束互斥（预留将来否定条件）           | /route/rules/i          | 检查规则内部逻辑一致性                     |