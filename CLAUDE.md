# Project Memory (for Claude)
- Project: singbox-rust
- Goals: Go 版 sing-box 的等价或超集特性，聚焦 TUN 入站、路由、并发与跨平台兼容。
- MSRV: 1.90（按需调整），Rust 2021/2024（以实际为准）。
- 样式：clippy 严格、单测+集测齐备、错误处理不“吃掉”上下文、日志语义化。
- 关键第三方：tokio、tokio-tun/平台 TUN 适配、governor/自研限流器（如有）、…（按实际填写）
- 质量门槛：见 /QUALITY_GATE.md
