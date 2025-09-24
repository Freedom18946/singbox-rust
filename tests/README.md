# SingBox-Rust 测试指南

本目录包含 singbox-rust 项目的所有测试文件，按功能和类型进行了重新组织。

## 目录结构

```
tests/
├── integration/     # 集成测试 - 跨模块功能测试
├── unit/           # 单元测试 - 单个模块测试
├── configs/        # 测试配置文件
├── data/           # 测试数据文件
├── scripts/        # 测试脚本
└── docs/           # 测试相关文档
```

## 测试分类

### 🔗 集成测试 (integration/)
- `test_schema_v2_integration.rs` - Schema V2 错误格式集成测试
- `test_udp_nat_*` - UDP NAT 系统完整功能测试
- `verify_*` - 各种功能验证脚本

### 🧪 单元测试 (unit/)
- 待添加：各模块的单元测试

### ⚙️ 配置测试 (configs/)
- `test_*_config.yaml` - 各种配置场景测试
- `test_schema_v2_*.yaml` - Schema V2 验证测试
- `test_cert.pem` - 测试证书文件

### 📊 测试数据 (data/)
- `demo*.json` - 演示数据
- `task_receipt*.json` - 任务执行回执
- `*.long-type-*.txt` - 编译器类型推断临时文件

### 🛠️ 测试脚本 (scripts/)
- `verify_schema_v2_implementation.sh` - Schema V2 实现验证

### 📚 测试文档 (docs/)
- `UDP_NAT_*.md` - UDP NAT 系统实现文档
- `SCHEMA_V2_*.md` - Schema V2 错误格式文档

## 运行测试

### 运行所有测试
```bash
cargo test
```

### 运行集成测试
```bash
cargo test --test integration
```

### 运行特定测试
```bash
# UDP NAT 测试
./tests/integration/test_udp_nat_complete_system

# Schema V2 测试
cargo test --test test_schema_v2_integration
```

### 运行验证脚本
```bash
# Schema V2 验证
./tests/scripts/verify_schema_v2_implementation.sh
```

## 测试开发指南

### 添加新的集成测试
1. 在 `integration/` 目录创建测试文件
2. 使用描述性的文件名，如 `test_feature_name.rs`
3. 包含完整的功能验证

### 添加配置测试
1. 在 `configs/` 目录添加测试配置
2. 使用 `test_` 前缀命名
3. 包含正面和负面测试用例

### 测试数据管理
1. 将测试数据放在 `data/` 目录
2. 使用有意义的文件名
3. 定期清理临时文件

## 最近更新

- ✅ 重新组织测试目录结构
- ✅ 完成 UDP NAT 系统集成测试
- ✅ 添加 Schema V2 错误格式测试
- ✅ 整理测试配置和数据文件