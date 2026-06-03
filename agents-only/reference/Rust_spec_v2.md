# Rust Agent Ruleset (3-Tier Architecture)

> **说明**：本文档是 Rust 规则原文。  
> 对当前仓库的项目化落地，请同时阅读：
> - `agents-only/reference/AGENT-DEVELOPMENT-GUIDELINES.md`
> - `agents-only/mt_audit_01_reconciliation.md`
> - `agents-only/mt_audit_01_full_report.md`
>
> 解释原则：
> - 规则原文长期有效
> - 但“当前仓库哪些项已修、哪些已降级为 future boundary、哪些仍是 non-blocking structural debt”，以复扫结论和当前源码事实为准
> - 不得把规则原文直接翻译成“当前所有命中都必须继续拆卡”

---

## Layer 1: Baseline Strict Constraints (Non-Negotiable)

- **禁止一切 panic 路径**：永远不在生产代码中使用 `unwrap()`、`expect()`、`panic!()`，或任何可能导致栈展开的构造。错误必须通过 `?` 运算符或显式的 `match` / `if let` 向上传播，绝不在中间层吞掉或强行断言。原型阶段临时写下的 `expect("TODO")` 在提交前必须替换为具名的 `Err(…)` 变体。如果某个值在逻辑上"不可能为 None / Err"，应将该不变量编码进类型系统（如 `NonZeroUsize`、`NonEmpty<T>`、专用 Newtype）而不是用 `unwrap()` 掩盖。唯一允许例外的场所是 `#[cfg(test)]` 块，以及 `fn main()` 或顶层 CLI 入口处、在所有恢复路径均已穷尽后作为最后手段出现的带有人类可读信息的 `.expect("fatal: …")`。

- **绝对路径优先**：始终使用以 `crate::` 开头的绝对路径引用模块内的符号，避免 `super::` 相对路径。`super::` 路径会在重构时随目录层级的变动而悄然失效，制造难以追踪的编译错误；`crate::` 路径则始终描述同一逻辑位置，具有重构稳定性。当在现有代码中发现 `super::` 时，应作为小型重构任务立即修正，不得积累。唯一可接受的残留 `super::` 是在 `#[cfg(test)]` 中引用被测模块的私有符号（`use super::*`），这是 Rust 测试惯例，属于有意为之。

- **谨慎使用 `pub use` 再导出**：不得随意将内部依赖通过 `pub use` 暴露到公开 API 中，因为这会将实现细节泄漏为公开契约，一旦对外发布便产生版本兼容性负担。`pub use` 只在两种场景下合法：一是明确设计为 facade 层的 prelude 模块（如 `pub mod prelude`），二是刻意将底层依赖类型作为本 crate 公开 API 的组成部分对外重新导出（此时须在文档注释中明确声明意图）。其余所有场合均应在内部消费后仅暴露自身定义的类型。

- **禁止全局可变状态**：禁止使用 `lazy_static!`、`OnceLock<T>`、`static mut`，或任何形式的全局单例可变状态。全局可变状态使调用者无法推断函数的副作用边界，也让单元测试的隔离性难以保证。正确做法是将共享状态显式封装进 Context 结构体，并通过函数参数或依赖注入将其传递给需要的组件。只读的全局常量（`const` 或 `static` 不可变值）不受此限制。如果某个第三方库内部使用了全局状态，应在模块文档注释中明确标注，提醒调用者注意线程安全和测试隔离风险。

---

## Layer 2: Intermediate Code Habits (Easy to Implement)

- **安全访问与错误处理**：任何集合（`Vec`、`HashMap`、`slice`）的元素访问均须使用 `.get(index)` 或 `.get(key)` 返回 `Option`，然后对结果进行显式处理；绝对禁止 `collection[n]` 形式的直接下标访问，因为越界会触发 panic 而不是返回错误。同样，禁止用 `let _ = some_result` 的形式静默丢弃 `Result` 或 `Option`；如果某个错误在当前上下文中确实可以安全忽略，须写明注释解释原因（如 `// ignoring send error: receiver already dropped`），并用具名变量承接以触发 `unused_must_use` lint。对于无法向上传播但又必须处理的错误，须通过 `tracing::warn!` 或 `tracing::error!` 记录，保留完整的错误链上下文。

- **禁止通配符导入与调试输出**：除 `#[cfg(test)]` 模块内的 `use super::*`（测试惯例）外，任何生产代码中均不得出现 `use foo::*` 形式的通配符导入，因为它会隐藏引入的符号来源，增加命名冲突风险，并使 IDE 分析和 `grep` 追踪失效。与此同时，任何 `println!`、`eprintln!`、`print!`、`dbg!` 宏均不得出现在提交代码中；所有运行时信息输出（调试信息、警告、指标事件）一律使用 `tracing` crate 的对应宏（`tracing::trace!`、`tracing::debug!`、`tracing::info!`、`tracing::warn!`、`tracing::error!`），并在宏调用中以结构化字段（`key = value`）的形式附加上下文，而不是将信息拼接进格式化字符串。

- **代码组织与文件边界**：`main.rs` 应保持极度精简，仅包含命令行参数解析、运行时初始化（`tokio::main`、日志/tracing 订阅者注册）和顶层错误处理；业务逻辑的任何一行都不应出现在此文件中。核心业务逻辑统一放入 `lib.rs`（或以 `lib.rs` 为根的模块树），使其可独立被测试 harness 和集成测试引用，无需启动完整的二进制入口。单元测试放在与被测代码同文件的 `#[cfg(test)] mod tests { … }` 块中，确保可访问私有接口；集成测试放在 `tests/` 目录下，仅通过公开 API 验证对外契约。`benches/`、`examples/` 同理，各司其职，不与测试目录混用。

- **惯用函数签名**：对只读访问的参数，应尽量使用借用类型而非拥有类型：字符串用 `&str` 而非 `&String`，字节序列用 `&[u8]` 而非 `&Vec<u8>`，路径用 `&Path` 而非 `&PathBuf`。这样做既避免了不必要的内存分配，又使函数接受更广泛的输入类型（任何可 `Deref` 到目标类型的值均可传入）。对于需要自定义构造或转换的类型，应通过实现标准 trait（`From<T>`、`TryFrom<T>`、`Display`、`Debug`、`Default`、`Clone`）来提供能力，而不是定义孤立的 `to_foo()` / `from_bar()` 方法——标准 trait 可与 `?`、`into()`、格式化宏无缝协作，自定义方法则不能。

- **禁止占位宏**：`todo!()`、`unimplemented!()`、`unreachable!()` 是运行时 panic 的语法糖，不得在任何会被提交的代码中使用（测试代码亦不例外，因为测试失败应通过断言而非 panic 体现）。对于尚未实现的功能，应在错误枚举中定义 `NotImplemented` 变体并返回 `Err(MyError::NotImplemented)`，使调用方能够在类型层面捕获并处理；对于逻辑上"不应到达"的分支，若编译器无法自动推断，应通过类型重构消除该分支（参考 Layer 3 "Type-Driven Design"），而不是用 `unreachable!()` 掩盖设计缺陷。

---

## Layer 3: Architectural & Semantic Design (Requires Deep Reasoning)

- **异步边界约束**：凡是传入 `tokio::spawn` 的 future，其捕获的所有引用和资源均必须满足 `Send + 'static` 约束；如果编译器报告不满足，应重新审视数据所有权（转移而非借用），而不是绕过约束。在持有 `Mutex` 或 `RwLock` 的守卫（guard）期间，绝不跨越 `.await` 点——因为异步运行时可能在 await 处切换线程，而 `MutexGuard` 不是 `Send`；正确做法是在 `.await` 之前释放 guard，或将锁的范围完全压缩在同步代码块内。`tokio::task::spawn_blocking` 仅用于有明确执行边界的 CPU 密集型或阻塞 I/O 工作（如压缩、正则匹配大文本），不得用于包含无限循环或长期持有资源的任务，此类场景应设计为独立的后台 task 并纳入 task 生命周期管理（见下文"Task Lifecycle"）。

- **所有权与借用设计**：永远不要以"让编译器满意"为目的调用 `.clone()`；每一次克隆都必须有明确的语义理由（如数据确实需要被两个所有者独立持有）。当借用冲突出现时，应首先考虑缩短可变借用的作用域（用块 `{}` 划定范围）、拆分结构体字段的借用（分别借用不同字段），或将计算结果提取为局部变量以终止借用。对于函数式管道中既可能拥有数据也可能借用数据的场景，使用 `std::borrow::Cow<'_, T>` 表达"按需克隆"语义。如果被调函数需要对数据的完整控制权（如存入数据结构、跨线程传送），则应直接接受拥有类型（by value），而不是接受引用后内部再克隆——后者既不诚实也不高效。

- **并发原语的选型**：不得将 `Arc<Mutex<T>>` 作为共享状态的默认方案——这是并发设计思考的终点，而非起点。决策树应为：若数据在初始化后不再变更，使用不可变的 `Arc<T>` 共享；若读多写少，使用 `Arc<RwLock<T>>` 并留意写操作的饥饿风险；若状态更新有明确的时序语义（如单一 owner 负责写入），应将状态集中在一个专属 task 中，外部通过 `mpsc` 或 `oneshot` 通道发送命令/查询，彻底避免跨线程锁竞争；仅当上述方案均不适用时，才考虑 `Mutex`，并须在注释中说明为何其他方式不可行。lock poisoning 须被显式处理（`.lock().unwrap_or_else(|e| e.into_inner())` 或在文档中声明 panicking 策略）。

- **类型驱动设计**：对所有具有业务语义的标识符（用户 ID、会话 ID、工具名称等）使用 Newtype 模式封装（如 `struct UserId(Uuid)`），即使底层类型相同，也要在类型层面阻止混淆传参。Enum 应尽量携带数据（ADT 风格），而不是裸 variant + 外部字段，以使非法状态在编译期不可表达（"make illegal states unrepresentable"）——例如用 `enum Connection { Connected(Socket), Disconnected { reason: String } }` 代替 `struct Connection { socket: Option<Socket>, is_connected: bool, disconnect_reason: Option<String> }`。所有来自外部的数据（网络响应、配置文件、用户输入）须在系统边界处通过 `TryFrom` 或专用验证函数转换为内部类型，经过验证的类型应与原始输入类型在名称上有所区分（如 `RawConfig` vs `ValidatedConfig`），使数据是否已验证在类型上显而易见。

- **错误类型的语义层级**：在库 crate（`lib.rs` 及其子模块）中，使用 `thiserror` 派生的精确枚举错误类型，每个 variant 须对应一种具体的失败原因，且须实现 `#[source]` 链以保留底层错误上下文，不得使用 `.map_err(|_| MyError::Generic)` 丢弃原始错误。在二进制入口（`main.rs`）或需要聚合多种异构错误源的顶层调用链末端，可使用 `anyhow::Result` 和 `.context("…")` / `.with_context(|| …)` 附加人类可读的调用上下文；但 `anyhow` 不得出现在库的公开 API 类型签名中，因为它向库的使用者隐藏了错误的结构信息，破坏了错误处理的可组合性。同一函数中的 `thiserror` 和 `anyhow` 不得混用。

- **分发策略的选择**：默认使用静态分发：用泛型参数 `fn foo<T: MyTrait>(x: T)` 或 `impl Trait` 语法（`fn foo(x: impl MyTrait)`）让编译器单态化，获得零运行时开销。仅在确实需要运行时多态（如将不同具体类型存入同一 `Vec`、跨越不可知的 plugin 边界）时，才引入 `Box<dyn Trait>`。引入 trait object 之前，应检查目标 trait 的 object safety：含有 `Self: Sized` 约束、泛型方法、或返回 `Self` 的方法均会破坏 object safety，须在设计阶段消除或拆分这些方法。对于高频调用路径上的 trait object，若 profiling 显示虚表调用是热点，应考虑用 enum dispatch（`enum Dispatcher { A(ImplA), B(ImplB) }`）替代，以恢复静态分发的性能。

- **Task 生命周期管理**：`tokio::spawn` 返回的 `JoinHandle<T>` 绝不允许被隐式丢弃（drop）——丢弃 handle 会使 task 在后台无声运行，既无法等待完成，也无法观测 panic。所有 handle 须被存储并在适当时机 `.await` 或通过取消信号 (`CancellationToken`) 显式终止。在使用 `tokio::select!` 时，须仔细审查每个分支的取消安全性：持有内部状态的 future（如 `AsyncReadExt::read_buf`）在被取消时可能丢失已读取的部分数据，应改用其 cancel-safe 的等价物或将 future 包装在不可取消的 scope 中。应用程序须实现显式的优雅关闭流程：监听 `SIGTERM`/`SIGINT` 信号后，先广播取消令牌，再依次 join 全部 task handle，并为整个关闭流程设置超时上限，超时后强制退出，避免因某个 task 卡死而导致进程永久悬挂。

- **精度与 unsafe 纪律**：任何涉及货币、计量单位或需要精确小数表示的数值，一律使用 `rust_decimal::Decimal` 或等效的定点类型，绝不使用 `f32` / `f64`——浮点数的精度损失在累积计算中会产生不可预测的误差。`unsafe` 代码块须最小化到不可避免的最小范围，每一个 `unsafe` 块（即使位于 `unsafe fn` 内部）均须在其紧上方附上 `// SAFETY: <解释此处 unsafe 代码为何在当前上下文中不违反内存安全的具体原因>` 注释，说明维护了哪些不变量。新增 `unsafe` 代码须在代码审查中额外关注，并在对应的 `#[cfg(test)]` 模块中提供覆盖边界条件的测试。

---

## Layer 4: Tooling & API Discipline (Enforced by Toolchain)

- **`#[must_use]` 标注**：所有公开函数（`pub fn`）若返回 `Result<T, E>`、`Option<T>`，或任何对调用方逻辑有影响的值（如事务句柄、建造者对象、计数器），均须标注 `#[must_use]` 或 `#[must_use = "描述忽略后果"]`。这确保调用方不会无意中静默丢弃错误或资源。在 CI 配置中应开启 `#[deny(unused_must_use)]`（Rust 默认为 warn 级别），将所有未处理的 `must_use` 返回值升级为编译错误。对于内部函数（`pub(crate)` 或私有函数），在存在真实的误用风险时同样应加注此属性，而不仅限于公开 API。

- **文档强制覆盖**：所有公开导出的 item（`pub struct`、`pub enum`、`pub fn`、`pub trait`、`pub type`）均须有 `///` 文档注释，说明其用途、关键参数语义及可能返回的错误类型。在 `lib.rs` 根部添加 `#![deny(missing_docs)]`，在 CI 中将文档缺失升级为编译错误，而不是依赖人工审查。文档注释中的代码示例（` ```rust ` 块）应能通过 `cargo test --doc` 执行验证，防止文档与实现随版本迭代而脱节。内部实现函数（非公开）不强制要求文档注释，但对于逻辑复杂或有非显而易见的副作用的私有函数，鼓励添加 `//`（普通注释）说明设计意图。

- **Clippy 配置规范**：在项目根目录的 `Cargo.toml` 中（或 `.clippy.toml`）显式配置 Clippy lint 级别，不得依赖默认行为。至少应在 CI 中以 `cargo clippy -- -D warnings` 运行，将所有 warn 级别 lint 升级为错误。建议额外启用的 lint 组：`clippy::pedantic`（开启后对不符合惯用写法的代码强制报错）、`clippy::nursery`（开启编译器尚在实验阶段但已较稳定的检查）。对于不适合项目的特定 lint（如 `clippy::module_name_repetitions`），应在 `Cargo.toml` 中统一豁免并附注原因，严禁在业务代码中分散出现 `#[allow(clippy::…)]`——后者会使豁免策略不可追踪、不可审计。每次升级 Rust 工具链后，须重新审视新引入的 lint，及时纳入或豁免。

- **外部数据反序列化卫生**：对所有来自外部的结构化输入（网络响应 JSON、配置文件、消息队列载荷），反序列化时须在对应的 `#[derive(Deserialize)]` 结构体上标注 `#[serde(deny_unknown_fields)]`，防止上游静默添加字段时代码无声接受而掩盖版本不兼容问题。反序列化完成后，须立即通过 `TryFrom` 或专用 validate 函数将原始的"输入类型"转换为经验证的"领域类型"（参考 Layer 3 "Type-Driven Design"），而不是在业务逻辑中直接操作 serde 派生的结构体。对于可选字段，显式声明 `#[serde(default)]` 或 `Option<T>`，不得依赖 serde 的隐式行为。反序列化失败产生的 `serde_json::Error`（或等价错误）须被转换为具名的领域错误类型后向上传播，不得裸露 serde 错误类型穿透应用层边界。
