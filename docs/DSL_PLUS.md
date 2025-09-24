# DSL+ 规格说明（include/macro）

> 目标：保持"标准 DSL"不变，在其之上提供**可组合**与**分片复用**能力；编译期纯展开，不改变运行时语义。

## 1. 基本语法
- 注释：以 `#` 开头的整行忽略；支持 UTF-8；
- 空行：忽略；
- include：
  ```
  include "relative/or/absolute/path.dsl"
  include path/without/quotes.dsl
  ```
  - 相对路径以当前文件所在目录为基准；
  - 检测 include 循环，发现即报错；
- 宏定义与调用：
  ```
  @macro NAME {
    # 这里写若干"标准 DSL 行"，也允许嵌套 use
    suffix:shop.com=proxyA
    use SUB_COMMON
  }
  use NAME
  ```
  - 宏名仅允许 `[A-Za-z0-9_]+`；
  - 宏体内允许再次 `use` 其它宏；定义可以嵌套，但必须成对 `{}`；
  - 调用未定义宏时报错；

## 2. 标准 DSL 行（由现有构建器解析）
常见形态（举例，非穷尽）：
```
exact:example.com=direct
suffix:shop.com=proxyA
default:reject
portset:80,443,8443=proxyA
transport:udp=direct
```
> DSL+ 只负责"把宏与 include 展开成上面这些基础行"，后续交给既有解析器。

## 3. 设计约束与动机
- 不改变现有解释器的语义与错误模型（Never break userspace）；
- 扩展能力足够覆盖"规则拆分/复用/拼装"的 80% 需求；
- 失败模式**早失败**：语法/循环/未定义宏等立刻报错；

## 4. 错误示例与诊断
- 未闭合宏：
  ```
  @macro BAD {
    suffix:a.com=proxyA
  # 缺少 }
  ```
  报错：`宏定义未正确闭合（缺少 `}`）`
- include 循环：
  ```
  # a.dsl
  include "b.dsl"
  # b.dsl
  include "a.dsl"
  ```
  报错：`检测到 include 循环：.../a.dsl`
- 未定义宏：
  ```
  use NOT_DEFINED
  ```
  报错：`use 未定义的宏：NOT_DEFINED`

## 5. 与工具链对接
- `sb-dsl expand` → 产出标准 DSL → `sb-preview` / `router::preview::*`
- `sb-dsl lint --show` → 快速校验与可视化展开结果
- `sb-preview` 在设置 `SB_DSL_PLUS=1` 时自动对 `--dsl` 做展开（不破坏默认）

## 6. 安全与可观测性
- 展开阶段不执行任何网络/系统调用，仅做本地文件读取；
- include 路径 canonicalize 后纳入"去重集"防环；
- 后续可在 `dsl_plus` 模块添加 debug 日志（本版先不引入 tracing 依赖）。