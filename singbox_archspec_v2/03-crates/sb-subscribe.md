# sb-subscribe（订阅/远程资源）

## 1) 职责

- 远程订阅拉取（HTTP/文件）
- Geo 数据、规则集更新
- 缓存与校验（etag/hash）

## 2) 产出

- 输出 RawConfig 或规则原料
- 不直接编译为 IR（由 sb-config 统一编译）
