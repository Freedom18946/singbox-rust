#![cfg_attr(feature = "strict_warnings", deny(warnings))]
//! sb-handshake - offline handshake tester (alpha, feature-gated)

// Provide a friendly stub when feature is disabled so `cargo check` succeeds by default.
#[cfg(not(feature = "handshake_alpha"))]
fn main() {
    eprintln!("sb-handshake: built without `--features handshake_alpha` — stub running.");
    eprintln!(
        "Hint: enable `handshake_alpha` (and the required runtime features) to use this tool."
    );
}

#[cfg(feature = "handshake_alpha")]
mod real {
    #![cfg_attr(feature = "strict_warnings", deny(warnings))]
    //! sb-handshake - offline handshake tester (alpha, feature-gated)
    #![allow(clippy::collapsible_if)]
    use anyhow::{anyhow, Result};
    use clap::{Parser, Subcommand, ValueEnum};
    use sb_runtime::prelude::*;
    use std::collections::HashMap;
    use std::{fs, path::PathBuf};

    #[derive(ValueEnum, Clone, Debug)]
    enum Proto {
        Trojan,
        Vmess,
    }
    impl Proto {
        fn make(&self, host: String, port: u16) -> Box<dyn Handshake> {
            match self {
                Proto::Trojan => Box::new(sb_runtime::protocols::trojan::Trojan::new(host, port)),
                Proto::Vmess => Box::new(sb_runtime::protocols::vmess::Vmess::new(host, port)),
            }
        }
    }

    #[derive(Parser, Debug)]
    #[command(
        name = "sb-handshake",
        version,
        about = "offline handshake alpha (no network)"
    )]
    struct Opt {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand, Debug)]
    enum Cmd {
        /// 生成首发报文并写文件
        Encode {
            #[arg(long)]
            proto: Proto,
            #[arg(long)]
            host: String,
            #[arg(long)]
            port: u16,
            #[arg(long, default_value_t = 42)]
            seed: u64,
            #[arg(long = "out")]
            out: PathBuf,
        },
        /// encode→decode 自洽回环（仅做静态校验）
        Roundtrip {
            #[arg(long)]
            proto: Proto,
            #[arg(long, default_value_t = 42)]
            seed: u64,
            #[arg(long = "out")]
            out: PathBuf,
        },
        /// JSON 摘要：len / head16(hex) / tail16(hex)
        Inspect {
            #[arg(long)]
            proto: Proto,
            #[arg(long)]
            host: String,
            #[arg(long)]
            port: u16,
            #[arg(long, default_value_t = 42)]
            seed: u64,
            #[arg(long = "out")]
            out: PathBuf,
        },
        /// 回环一次并记录帧（可选 XOR 混淆；仅写 JSONL）
        Loopback {
            #[arg(long)]
            proto: Proto,
            #[arg(long)]
            host: String,
            #[arg(long)]
            port: u16,
            #[arg(long, default_value_t = 42)]
            seed: u64,
            /// 输出 JSONL 路径
            #[arg(long = "out")]
            out: PathBuf,
            /// 可选混淆（形如 xor:AA，其中 AA 为十六进制字节）
            #[arg(long = "obf")]
            obf: Option<String>,
        },
        /// 从 JSONL 生成指标（流式解析，输出有序数组 head8_modes）
        Metrics {
            #[arg(long = "from")]
            from: PathBuf,
            #[arg(long = "out")]
            out: PathBuf,
            /// 限制 head8_modes 输出条目数（默认 5）
            #[arg(long = "head8-top", default_value_t = 5)]
            head8_top: usize,
        },
        /// 校验 JSONL（帧数、时间戳单调、长度直方图）
        VerifyJsonl {
            #[arg(long = "from")]
            from: PathBuf,
            /// 允许时间戳非单调（默认 false 即要求单调）
            #[arg(long = "allow-disorder", default_value_t = false)]
            allow_disorder: bool,
            #[arg(long = "out")]
            out: PathBuf,
        },
        /// 断言 metrics 阈值（CI 友好）
        AssertMetrics {
            #[arg(long = "from")]
            from: PathBuf,
            /// 最小帧数
            #[arg(long = "min-frames")]
            min_frames: Option<usize>,
            /// 最小 tx/rx 字节
            #[arg(long = "min-tx")]
            min_tx: Option<usize>,
            #[arg(long = "min-rx")]
            min_rx: Option<usize>,
            /// 允许最大 ts_disorder（默认 0）
            #[arg(long = "max-disorder")]
            max_disorder: Option<usize>,
            /// 期望 head8 片段出现次数 (可多次) 形如 HEX 或 HEX:MIN
            #[arg(long = "expect-head8")]
            expect_head8: Vec<String>,
            /// 可选：长度阈值
            #[arg(long = "len-min")]
            len_min: Option<usize>,
            #[arg(long = "len-max")]
            len_max: Option<usize>,
            /// 可选：时间跨度上限（毫秒）
            #[arg(long = "max-span-ms")]
            max_span_ms: Option<u64>,
        },
        /// 运行场景文件（JSON），把离线回归固化为声明式流程
        RunScenarios {
            #[arg(long = "from")]
            from: PathBuf,
            /// 失败即停（默认 true）
            #[arg(long = "stop-on-fail", default_value_t = true)]
            stop_on_fail: bool,
            /// 可选：将 summary 写入文件
            #[arg(long = "out")]
            out: Option<PathBuf>,
            /// 全局默认 seed（当 step.seed=0 时生效）
            #[arg(long = "default-seed")]
            default_seed: Option<u64>,
            /// 全局输出目录（相对路径将拼接到该目录）
            #[arg(long = "out-dir")]
            out_dir: Option<PathBuf>,
            /// 变量注入（可多次） KEY=VAL，仅用于字符串/路径模板 ${KEY}
            #[arg(long = "var")]
            vars: Vec<String>,
            /// 额外：生成简要报告（passed/failed/total），写入 path
            #[arg(long = "report")]
            report: Option<PathBuf>,
            /// 仅展开（dry-run），打印或写出展开后的场景JSON，不执行
            #[arg(long = "dry-run", default_value_t = false)]
            dry_run: bool,
            /// 从JSON加载变量字典（优先级：--var > vars_from > 文件内 vars）
            #[arg(long = "vars-from")]
            vars_from: Option<PathBuf>,
        },
        /// 重放解码器：从 JSONL 验证 decode_ack（仅 RX 帧）
        Replay {
            #[arg(long)]
            proto: Proto,
            #[arg(long)]
            host: String,
            #[arg(long)]
            port: u16,
            #[arg(long = "from")]
            from: PathBuf,
            /// 严格模式：遇到解码错误立即退出
            #[arg(long)]
            strict: bool,
        },
        /// JSONL 切片（过滤方向/数量/前缀），用于快速调试与 CI 回归样本
        Slice {
            /// JSONL 来源
            #[arg(long = "from")]
            from: PathBuf,
            /// 目标输出
            #[arg(long = "out")]
            out: PathBuf,
            /// 方向过滤：tx|rx|all
            #[arg(long = "dir", default_value = "all")]
            dir: String,
            /// 限制行数（0=不限）
            #[arg(long = "limit", default_value_t = 0)]
            limit: usize,
            /// 仅保留 head8 前缀（十六进制，大小写不敏感），为空则忽略
            #[arg(long = "head8-prefix")]
            head8_prefix: Option<String>,
        },
        #[cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
        /// 本机 TCP 环回（Echo 可选）—— 仅 127.0.0.1 / ::1，写 JSONL 帧，兼容 metrics/replay
        IoLocal {
            #[arg(long)]
            proto: Proto,
            /// 本机端口；可配合 --spawn-echo 使用 0 让系统分配
            #[arg(long, default_value_t = 0)]
            port: u16,
            #[arg(long, default_value_t = 42)]
            seed: u64,
            #[arg(long = "out")]
            out: PathBuf,
            /// 读取回包最大字节数（默认 64）
            #[arg(long = "read-max", default_value_t = 64)]
            read_max: usize,
            /// 超时时间（ms，默认 200）
            #[arg(long = "timeout-ms", default_value_t = 200)]
            timeout_ms: u64,
            /// 启动内置 Echo 服务器（仅一次连接）
            #[arg(long = "spawn-echo", default_value_t = false)]
            spawn_echo: bool,
            /// 可选 XOR 混淆键（对 Echo 回包应用，如 0xaa 写作 "aa"）
            #[arg(long = "obf-xor")]
            obf_xor: Option<String>,
            /// Chaos 预设名（内置：none/slowloss/evil），或自定义 JSON 文件通过 --chaos-from
            #[arg(long = "chaos-profile")]
            chaos_profile: Option<String>,
            /// Chaos 配置 JSON 路径（字段：delay_tx_ms,delay_rx_ms,rx_drop,rx_trim,rx_xor）
            #[arg(long = "chaos-from")]
            chaos_from: Option<PathBuf>,
            /// Chaos: 写入前延迟（毫秒）
            #[arg(long = "delay-tx-ms", default_value_t = 0)]
            delay_tx_ms: u64,
            /// Chaos: 读取前延迟（毫秒）
            #[arg(long = "delay-rx-ms", default_value_t = 0)]
            delay_rx_ms: u64,
            /// Chaos: 丢弃回包前 N 字节
            #[arg(long = "rx-drop", default_value_t = 0)]
            rx_drop: usize,
            /// Chaos: 截断回包到最多 M 字节（0=不截断）
            #[arg(long = "rx-trim", default_value_t = 0)]
            rx_trim: usize,
            /// Chaos: 对回包按字节 XOR 的掩码（十六进制，如 "aa"）
            #[arg(long = "rx-xor")]
            rx_xor: Option<String>,
        },
    }

    fn hex16(v: &[u8]) -> String {
        let n = v.len();
        let k = n.min(16);
        v[..k]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    #[cfg(feature = "handshake_alpha")]
    fn parse_obf(spec: &str) -> Result<Box<dyn Obfuscator>> {
        let lowered = spec.to_ascii_lowercase();
        if let Some(rest) = lowered.strip_prefix("xor:") {
            let byte = u8::from_str_radix(rest.trim(), 16)
                .map_err(|e| anyhow!("invalid xor key '{}': {e}", rest))?;
            return Ok(Box::new(sb_runtime::loopback::XorObfuscator::new(byte)));
        }
        Err(anyhow!("unsupported obfuscator spec: {}", spec))
    }

    #[cfg(feature = "handshake_alpha")]
    fn generate_metrics_stream(
        jsonl_path: &PathBuf,
        head8_top: usize,
    ) -> Result<serde_json::Value> {
        use sb_runtime::loopback::Frame;
        use std::io::{BufRead, BufReader};
        let f = std::fs::File::open(jsonl_path)
            .map_err(|e| anyhow!("Failed to open {}: {}", jsonl_path.display(), e))?;
        let mut rdr = BufReader::new(f);
        let mut buf = String::new();
        let mut frames = 0usize;
        let mut total_tx = 0usize;
        let mut total_rx = 0usize;
        let mut head8_modes: HashMap<String, usize> = HashMap::new();
        let mut ts_min: Option<u64> = None;
        let mut ts_max: Option<u64> = None;
        // 长度直方图：0-15, 16-63, 64-255, 256+
        let mut hist = [0u64; 4];
        loop {
            buf.clear();
            let n = rdr.read_line(&mut buf)?;
            if n == 0 {
                break;
            }
            let line = buf.trim();
            if line.is_empty() {
                continue;
            }
            let frame: Frame = serde_json::from_str(line)
                .map_err(|e| anyhow!("Failed to parse JSONL line: {}", e))?;
            frames += 1;
            ts_min = Some(ts_min.map_or(frame.ts_ms, |x| x.min(frame.ts_ms)));
            ts_max = Some(ts_max.map_or(frame.ts_ms, |x| x.max(frame.ts_ms)));
            match frame.dir {
                sb_runtime::loopback::FrameDir::Tx => total_tx += frame.len,
                sb_runtime::loopback::FrameDir::Rx => total_rx += frame.len,
            }
            *head8_modes.entry(frame.head8_hex).or_insert(0) += 1;
            let b = match frame.len {
                0..=15 => 0,
                16..=63 => 1,
                64..=255 => 2,
                _ => 3,
            };
            hist[b] += 1;
        }
        // Top-N
        let mut head8_vec: Vec<(String, usize)> = head8_modes.into_iter().collect();
        head8_vec.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        if head8_top > 0 && head8_vec.len() > head8_top {
            head8_vec.truncate(head8_top);
        }
        let elapsed_ms = match (ts_min, ts_max) {
            (Some(a), Some(b)) => b.saturating_sub(a),
            _ => 0,
        };
        Ok(serde_json::json!({
            "frames": frames, "tx": total_tx, "rx": total_rx, "elapsed_ms": elapsed_ms,
            "head8_modes": head8_vec.into_iter().map(|(k,v)| serde_json::json!([k, v])).collect::<Vec<_>>(),
            "len_hist": {"0_15": hist[0], "16_63": hist[1], "64_255": hist[2], "256_up": hist[3]}
        }))
    }

    #[cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
    fn load_chaos_from_flags(
        profile: &Option<String>,
        from: &Option<PathBuf>,
        delay_tx_ms: u64,
        delay_rx_ms: u64,
        rx_drop: usize,
        rx_trim: usize,
        rx_xor_s: &Option<String>,
    ) -> Result<Option<sb_runtime::tcp_local::ChaosSpec>> {
        use sb_runtime::tcp_local::ChaosSpec;
        // 1) 外部文件优先
        if let Some(p) = from {
            let txt =
                std::fs::read_to_string(p).map_err(|e| anyhow!("read chaos-from failed: {e}"))?;
            let v: serde_json::Value = serde_json::from_str(&txt)
                .map_err(|e| anyhow!("parse chaos-from json failed: {e}"))?;
            let rx_xor = v
                .get("rx_xor")
                .and_then(|x| x.as_str())
                .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            let spec = ChaosSpec {
                delay_tx_ms: v.get("delay_tx_ms").and_then(|x| x.as_u64()).unwrap_or(0),
                delay_rx_ms: v.get("delay_rx_ms").and_then(|x| x.as_u64()).unwrap_or(0),
                rx_drop: v.get("rx_drop").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
                rx_trim: v
                    .get("rx_trim")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as usize),
                rx_xor,
            };
            return Ok(Some(spec));
        }
        // 2) 预设
        if let Some(name) = profile.as_ref().map(|s| s.as_str()) {
            let spec = match name {
                "none" => ChaosSpec::default(),
                "slowloss" => ChaosSpec {
                    delay_tx_ms: 20,
                    delay_rx_ms: 30,
                    rx_drop: 1,
                    rx_trim: Some(24),
                    rx_xor: None,
                },
                "evil" => ChaosSpec {
                    delay_tx_ms: 50,
                    delay_rx_ms: 50,
                    rx_drop: 4,
                    rx_trim: Some(16),
                    rx_xor: Some(0xAA),
                },
                "mobile3g" => ChaosSpec {
                    delay_tx_ms: 120,
                    delay_rx_ms: 180,
                    rx_drop: 2,
                    rx_trim: Some(32),
                    rx_xor: None,
                },
                "edge" => ChaosSpec {
                    delay_tx_ms: 250,
                    delay_rx_ms: 350,
                    rx_drop: 3,
                    rx_trim: Some(24),
                    rx_xor: Some(0x55),
                },
                "wifi_bad" => ChaosSpec {
                    delay_tx_ms: 40,
                    delay_rx_ms: 60,
                    rx_drop: 1,
                    rx_trim: Some(8),
                    rx_xor: None,
                },
                other => return Err(anyhow!("unknown chaos-profile: {other}")),
            };
            // 显式 flags 覆盖预设
            let rx_xor = rx_xor_s
                .as_ref()
                .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .or(spec.rx_xor);
            let rx_trim_o = if rx_trim == 0 {
                spec.rx_trim
            } else {
                Some(rx_trim)
            };
            return Ok(Some(ChaosSpec {
                delay_tx_ms: if delay_tx_ms == 0 {
                    spec.delay_tx_ms
                } else {
                    delay_tx_ms
                },
                delay_rx_ms: if delay_rx_ms == 0 {
                    spec.delay_rx_ms
                } else {
                    delay_rx_ms
                },
                rx_drop: if rx_drop == 0 { spec.rx_drop } else { rx_drop },
                rx_trim: rx_trim_o,
                rx_xor,
            }));
        }
        // 3) 仅 flags
        if delay_tx_ms > 0 || delay_rx_ms > 0 || rx_drop > 0 || rx_trim > 0 || rx_xor_s.is_some() {
            let rx_xor = rx_xor_s
                .as_ref()
                .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            let rx_trim_o = if rx_trim == 0 { None } else { Some(rx_trim) };
            return Ok(Some(ChaosSpec {
                delay_tx_ms,
                delay_rx_ms,
                rx_drop,
                rx_trim: rx_trim_o,
                rx_xor,
            }));
        }
        Ok(None)
    }

    pub fn main() -> Result<()> {
        let opt = Opt::parse();
        match opt.cmd {
            Cmd::Encode {
                proto,
                host,
                port,
                seed,
                out,
            } => {
                let hs = proto.make(host, port);
                let bytes = hs.encode_init(seed);
                fs::write(&out, &bytes)
                    .map_err(|e| anyhow!("write {} failed: {e}", out.display()))?;
                println!(
                    "HANDSHAKE_OK: proto={:?} bytes={} out='{}'",
                    proto,
                    bytes.len(),
                    out.display()
                );
            }
            Cmd::Roundtrip { proto, seed, out } => {
                // 构造一个最小 ctx（host: example.com:443）
                let hs = proto.make("example.com".into(), 443);
                let bytes = hs.encode_init(seed);
                hs.decode_ack(&bytes[..bytes.len().min(32)])?;
                fs::write(&out, &bytes)
                    .map_err(|e| anyhow!("write {} failed: {e}", out.display()))?;
                println!(
                    "HANDSHAKE_OK: proto={:?} roundtrip bytes={} out='{}'",
                    proto,
                    bytes.len(),
                    out.display()
                );
            }
            Cmd::Inspect {
                proto,
                host,
                port,
                seed,
                out,
            } => {
                let hs = proto.make(host, port);
                let bytes = hs.encode_init(seed);
                let head = hex16(&bytes);
                let tail = hex16(&bytes[bytes.len().saturating_sub(16)..]);
                let j = serde_json::json!({
                    "proto": format!("{:?}", proto),
                    "len": bytes.len(),
                    "head16": head,
                    "tail16": tail
                });
                fs::write(&out, serde_json::to_string_pretty(&j)?)
                    .map_err(|e| anyhow!("write {} failed: {e}", out.display()))?;
                println!("HS_OK: {}", out.display());
            }
            #[cfg(feature = "handshake_alpha")]
            Cmd::Loopback {
                proto,
                host,
                port,
                seed,
                out,
                obf,
            } => {
                // 构造 HS
                let hs = proto.make(host, port);
                // 如果指定混淆，仅用于帧回环（encode_init → rx echo 前）
                if let Some(spec) = obf.as_ref() {
                    // 读取 init bytes，手工回环并写日志（带 obf）
                    let mut conn =
                        sb_runtime::loopback::LoopConn::with_obfuscator(parse_obf(spec)?);
                    let bytes = hs.encode_init(seed);
                    let tx_len = conn.send(&bytes);
                    let echo = conn.recv(bytes.len().min(32));
                    hs.decode_ack(&echo)?; // 形状校验
                    let log = sb_runtime::loopback::SessionLog::new(&out);
                    log.log_frame(&sb_runtime::loopback::Frame::new(
                        sb_runtime::loopback::FrameDir::Tx,
                        &bytes,
                    ))?;
                    log.log_frame(&sb_runtime::loopback::Frame::new(
                        sb_runtime::loopback::FrameDir::Rx,
                        &echo,
                    ))?;
                    println!(
                        "HS_OK: loopback bytes_tx={} bytes_rx={} out='{}'",
                        tx_len,
                        echo.len(),
                        out.display()
                    );
                } else {
                    // 使用默认 run_once（无混淆）
                    let m = sb_runtime::loopback::run_once(hs.as_ref(), seed, Some(&out))?;
                    println!(
                        "HS_OK: loopback bytes_tx={} bytes_rx={} out='{}'",
                        m.bytes_tx,
                        m.bytes_rx,
                        out.display()
                    );
                }
            }
            #[cfg(feature = "handshake_alpha")]
            Cmd::Metrics {
                from,
                out,
                head8_top,
            } => {
                let metrics = generate_metrics_stream(&from, head8_top)?;
                fs::write(&out, serde_json::to_string_pretty(&metrics)?)
                    .map_err(|e| anyhow!("write {} failed: {e}", out.display()))?;
                println!("HS_OK: metrics path='{}'", out.display());
            }
            Cmd::VerifyJsonl {
                from,
                allow_disorder,
                out,
            } => {
                let v = sb_runtime::jsonl::basic_verify(&from)?;
                let dis = v.get("ts_disorder").and_then(|x| x.as_u64()).unwrap_or(0);
                if !allow_disorder && dis > 0 {
                    return Err(anyhow!("VERIFY_JSONL: ts_disorder={dis} not allowed"));
                }
                fs::write(&out, serde_json::to_string_pretty(&v)?)
                    .map_err(|e| anyhow!("write {} failed: {e}", out.display()))?;
                println!(
                    "HS_OK: verify_jsonl path='{}' frames={}",
                    out.display(),
                    v.get("frames").and_then(|x| x.as_u64()).unwrap_or(0)
                );
            }
            Cmd::AssertMetrics {
                from,
                min_frames,
                min_tx,
                min_rx,
                max_disorder,
                expect_head8,
                len_min,
                len_max,
                max_span_ms,
            } => {
                let v = sb_runtime::jsonl::basic_verify(&from)?;
                let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                let frames = g("frames");
                let tx = g("tx");
                let rx = g("rx");
                let dis = g("ts_disorder");
                let lmin = v.get("len_min").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                let lmax = v.get("len_max").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                let span = v.get("ts_span_ms").and_then(|x| x.as_u64()).unwrap_or(0);
                if let Some(min) = min_frames {
                    if frames < min {
                        return Err(anyhow!("frames {} < {}", frames, min));
                    }
                }
                if let Some(min) = min_tx {
                    if tx < min {
                        return Err(anyhow!("tx {} < {}", tx, min));
                    }
                }
                if let Some(min) = min_rx {
                    if rx < min {
                        return Err(anyhow!("rx {} < {}", rx, min));
                    }
                }
                if let Some(max) = max_disorder {
                    if dis > max {
                        return Err(anyhow!("ts_disorder {} > {}", dis, max));
                    }
                }
                if let Some(mn) = len_min {
                    if lmin < mn {
                        return Err(anyhow!("len_min {} < {}", lmin, mn));
                    }
                }
                if let Some(mx) = len_max {
                    if lmax > mx {
                        return Err(anyhow!("len_max {} > {}", lmax, mx));
                    }
                }
                if let Some(ms) = max_span_ms {
                    if span > ms {
                        return Err(anyhow!("ts_span_ms {} > {}", span, ms));
                    }
                }
                // head8 expectations
                if !expect_head8.is_empty() {
                    // 将 head8_top 转为映射 {hex:count}
                    let mut map = std::collections::HashMap::<String, usize>::new();
                    if let Some(arr) = v.get("head8_top").and_then(|x| x.as_array()) {
                        for it in arr {
                            if let (Some(h), Some(c)) = (
                                it.get("hex").and_then(|x| x.as_str()),
                                it.get("count").and_then(|x| x.as_u64()),
                            ) {
                                map.insert(h.to_string(), c as usize);
                            }
                        }
                    }
                    for spec in expect_head8 {
                        let (hex, need) = if let Some((h, n)) = spec.split_once(':') {
                            (h.trim().to_string(), n.trim().parse::<usize>().unwrap_or(1))
                        } else {
                            (spec.trim().to_string(), 1usize)
                        };
                        let got = map.get(&hex).cloned().unwrap_or(0usize);
                        if got < need {
                            return Err(anyhow!("head8 '{}' count {} < {}", hex, got, need));
                        }
                    }
                }
                println!(
                    "HS_OK: assert frames={} tx={} rx={} disorder={} len_min={} len_max={} span_ms={}",
                    frames, tx, rx, dis, lmin, lmax, span
                );
            }
            Cmd::RunScenarios {
                from,
                stop_on_fail,
                out,
                default_seed,
                out_dir,
                vars,
                report,
                dry_run,
                vars_from,
            } => {
                use std::collections::HashMap;
                let mut sc: sb_runtime::scenario::ScenarioFile = serde_json::from_str(
                    &std::fs::read_to_string(&from)
                        .map_err(|e| anyhow!("read {} failed: {e}", from.display()))?,
                )
                .map_err(|e| anyhow!("parse scenario failed: {e}"))?;
                sc.stop_on_fail = stop_on_fail;
                if let Some(s) = default_seed {
                    sc.defaults.seed = Some(s);
                }
                if let Some(d) = out_dir {
                    sc.defaults.out_dir = Some(d);
                }
                if let Some(path) = vars_from {
                    if let Ok(txt) = std::fs::read_to_string(&path) {
                        if let Ok(mut m) = serde_json::from_str::<HashMap<String, String>>(&txt) {
                            // 合并到现有 vars
                            for (k, v) in m.drain() {
                                sc.vars.entry(k).or_insert(v);
                            }
                        }
                    }
                }
                if !vars.is_empty() {
                    let mut map: HashMap<String, String> = sc.vars.clone();
                    for kv in vars {
                        if let Some((k, v)) = kv.split_once('=') {
                            map.insert(k.trim().to_string(), v.trim().to_string());
                        } else {
                            eprintln!("WARN: --var expects KEY=VAL, got: {}", kv);
                        }
                    }
                    sc.vars = map;
                }
                if dry_run {
                    // 打印展开后的场景内容（不执行）
                    let json_str = serde_json::to_string_pretty(&sc)?;
                    if let Some(p) = out {
                        std::fs::write(&p, &json_str)
                            .map_err(|e| anyhow!("write {} failed: {e}", p.display()))?;
                        println!(
                            "HS_OK: scenarios-dry-run path='{}' bytes={}",
                            p.display(),
                            json_str.len()
                        );
                    } else {
                        println!("{json_str}");
                    }
                    return Ok(());
                }
                let sum = sb_runtime::scenario::run(sc)?;
                let summary = serde_json::to_string_pretty(&sum)?;
                if let Some(p) = out {
                    std::fs::write(&p, &summary)
                        .map_err(|e| anyhow!("write {} failed: {e}", p.display()))?;
                    println!(
                        "HS_OK: scenarios path='{}' passed={} failed={} total={}",
                        p.display(),
                        sum.passed,
                        sum.failed,
                        sum.total
                    );
                } else {
                    println!("{summary}");
                }
                if let Some(rp) = report {
                    let mini = serde_json::json!({"passed": sum.passed, "failed": sum.failed, "total": sum.total});
                    std::fs::write(&rp, serde_json::to_string_pretty(&mini)?)
                        .map_err(|e| anyhow!("write report {} failed: {e}", rp.display()))?;
                    println!("HS_OK: report '{}'", rp.display());
                }
            }
            #[cfg(feature = "handshake_alpha")]
            Cmd::Replay {
                proto,
                host,
                port,
                from,
                strict,
            } => {
                let hs = proto.make(host, port);
                let (frames, errors) =
                    sb_runtime::loopback::replay_decode(hs.as_ref(), &from, strict)?;
                println!(
                    "HS_OK: replay frames={} errors={} path='{}'",
                    frames,
                    errors,
                    from.display()
                );
            }
            Cmd::Slice {
                from,
                out,
                dir,
                limit,
                head8_prefix,
            } => {
                use sb_runtime::loopback::{Frame, FrameDir};
                use std::io::{BufRead, BufReader, Write};
                let f = std::fs::File::open(&from)
                    .map_err(|e| anyhow!("open {} failed: {e}", from.display()))?;
                let mut rdr = BufReader::new(f);
                let mut w = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&out)
                    .map_err(|e| anyhow!("open {} failed: {e}", out.display()))?;
                let want_dir = match dir.to_ascii_lowercase().as_str() {
                    "tx" => Some(FrameDir::Tx),
                    "rx" => Some(FrameDir::Rx),
                    "all" | "" => None,
                    other => return Err(anyhow!("invalid --dir {}", other)),
                };
                let prefix = head8_prefix.map(|s| s.to_ascii_lowercase());
                let mut buf = String::new();
                let mut kept = 0usize;
                loop {
                    buf.clear();
                    let n = rdr.read_line(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    let line = buf.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let f: Frame = match serde_json::from_str(line) {
                        Ok(x) => x,
                        Err(_) => continue, // 跳过坏行
                    };
                    if let Some(ref d) = want_dir {
                        if f.dir != *d {
                            continue;
                        }
                    }
                    if let Some(p) = &prefix {
                        if !f.head8_hex.to_ascii_lowercase().starts_with(p) {
                            continue;
                        }
                    }
                    writeln!(w, "{}", serde_json::to_string(&f).unwrap()).ok();
                    kept += 1;
                    if limit > 0 && kept >= limit {
                        break;
                    }
                }
                println!(
                    "HS_OK: slice from='{}' out='{}' kept={}",
                    from.display(),
                    out.display(),
                    kept
                );
            }
            #[cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
            Cmd::IoLocal {
                proto,
                port,
                seed,
                out,
                read_max,
                timeout_ms,
                spawn_echo,
                obf_xor,
                chaos_profile,
                chaos_from,
                delay_tx_ms,
                delay_rx_ms,
                rx_drop,
                rx_trim,
                rx_xor,
            } => {
                use sb_runtime::tcp_local::io_local_with_optional_echo;
                let xor =
                    obf_xor.and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok());
                // 单线程 runtime 足够
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .map_err(|e| anyhow!("runtime build failed: {e}"))?;
                let hs = proto.make("localhost".into(), port);
                // 汇总 Chaos 来源（profile / 文件 / flags）
                let chaos_from_flags = load_chaos_from_flags(
                    &chaos_profile,
                    &chaos_from,
                    delay_tx_ms,
                    delay_rx_ms,
                    rx_drop,
                    rx_trim,
                    &rx_xor,
                )?;
                if chaos_from_flags.is_some() {
                    use sb_runtime::tcp_local::{io_local_once, spawn_echo_once};
                    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                    let mut target = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        port,
                    );
                    if spawn_echo {
                        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
                        let bound = rt.block_on(spawn_echo_once(bind, xor))?;
                        target = bound;
                    }
                    let (tx, rx) = rt.block_on(io_local_once(
                        hs.as_ref(),
                        target,
                        seed,
                        &out,
                        read_max,
                        timeout_ms,
                        chaos_from_flags,
                    ))?;
                    println!("HS_OK: io_local addr='{}' bytes_tx={} bytes_rx={} out='{}' chaos={{tx_ms:{},rx_ms:{},drop:{},trim:{},xor:{}}}",
                        target, tx, rx, out.display(),
                        delay_tx_ms, delay_rx_ms, rx_drop, rx_trim,
                        rx_xor.unwrap_or_else(|| chaos_from.as_ref().map(|_| "file".into()).unwrap_or("-".into())));
                } else {
                    let config = sb_runtime::tcp_local::IoLocalConfig {
                        req_port: port,
                        seed,
                        log_path: &out,
                        read_max,
                        to_ms: timeout_ms,
                        spawn_echo,
                        xor_key: xor,
                    };
                    let (addr, tx, rx) =
                        rt.block_on(io_local_with_optional_echo(hs.as_ref(), config))?;
                    println!(
                        "HS_OK: io_local addr='{}' bytes_tx={} bytes_rx={} out='{}'",
                        addr,
                        tx,
                        rx,
                        out.display()
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "handshake_alpha")]
// Provide a real entrypoint when feature is enabled
fn main() {
    if let Err(e) = real::main() {
        eprintln!("handshake failed: {e}");
        std::process::exit(1);
    }
}
