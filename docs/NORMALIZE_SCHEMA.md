## 订阅条目规范化导出说明

### 目标
把经过筛选/去重的节点数组，导出为**单一、稳定**的 JSON 数组，便于后续脚本或其他工具继续处理。

### 模式
- `none`：保留原始字段，仅在缺失 `server_port` 时用 `port` 回填（历史兼容）。
- `sing_box`：面向 sing-box：
  * `server_port` 为主；如缺失则由 `port` 回填；
  * `tls` 固化为对象：`{enabled,server_name,insecure?}`；若输入为布尔则转为对象；
  * 删除明显 clash-only 的冗余键（如 `name`、`udp`、`skip-cert-verify`）。
- `clash`：面向 Clash：
  * 产出最小键集合：`name`(由 `tag` 回填)、`type`、`server`、`port`、`tls`(bool)、`servername`(由 `tls.server_name` 回填)；
  * 删除 sing-box only 的键（如 `server_port`）。
- `schema`：外部自定义映射：
  * 加载 `--schema-map <path>`，按映射执行 rename/coalesce/set/delete；
  * **仅影响导出文件**，不改变 stdout/`--out` 的统计 JSON。

### 自定义 Schema 映射文件格式（examples/schema.map.json）
```json
{
  "rename": [
    {"from":"tag","to":"name"}
  ],
  "coalesce": [
    {"to":"server_port","from":["server_port","port"]}
  ],
  "set": [
    {"path":"tls.enabled","value":true}
  ],
  "delete": ["udp","skip-cert-verify"]
}
```
> 语义：如果存在 `tag` 则改名为 `name`；把 `server_port` 或 `port` 的第一个可用值灌到 `server_port`；强制 `tls.enabled=true`；最后删掉无关键。

### 稳定性
导出数组形，顺序为输入稳定顺序（去重保留首见）。字段顺序不保证，但键集合稳定。