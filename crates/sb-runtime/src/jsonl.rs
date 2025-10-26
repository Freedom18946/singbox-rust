//! JSONL 帧工具 - 流式读取与校验
//!
//! 提供 JSONL 格式的协议握手帧解析、统计和验证功能。
//! 依赖 `loopback::Frame` 结构，不引入 IO 以外的副作用。
//!
//! # 主要功能
//! - 流式读取 JSONL 文件（容错跳过空行和解析失败行）
//! - 基本统计验证（帧数、传输量、时间戳等）
//! - 回放校验（严格/宽松模式）
use crate::loopback::Frame;
use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    time::SystemTime,
};

/// 逐帧流式读取 JSONL 文件（容错：跳过空行与解析失败行）
///
/// # 参数
/// - `p`: JSONL 文件路径
///
/// # 返回
/// 返回帧的迭代器，自动过滤空行
///
/// # 错误
/// 当文件无法打开时返回错误，解析失败的行会作为 `Err` 返回
pub fn stream_frames<P: AsRef<Path>>(p: P) -> Result<impl Iterator<Item = Result<Frame>>> {
    let path = p.as_ref();
    let f = File::open(path).map_err(|e| anyhow!("open {} failed: {e}", path.display()))?;
    let mut rdr = BufReader::new(f);
    let mut buf = String::new();

    // 使用生成器风格的迭代器
    let iter = std::iter::from_fn(move || {
        buf.clear();
        match rdr.read_line(&mut buf) {
            Ok(0) => None, // EOF
            Ok(_) => {
                let line = buf.trim();
                // 跳过空行，继续读取下一行
                if line.is_empty() {
                    return Some(Ok(Frame {
                        ts_ms: 0,
                        dir: crate::loopback::FrameDir::Tx,
                        len: 0,
                        head8_hex: String::new(),
                        tail8_hex: String::new(),
                    }));
                }
                match serde_json::from_str::<Frame>(line) {
                    Ok(f) => Some(Ok(f)),
                    Err(e) => Some(Err(anyhow!("parse JSONL failed: {e}"))),
                }
            }
            Err(e) => Some(Err(anyhow!("read_line failed: {e}"))),
        }
    })
    .filter(|r| {
        // 过滤掉空行占位符
        match r {
            Ok(f) => f.len > 0,
            Err(_) => true,
        }
    });

    Ok(iter)
}

/// 基本统计验证（扩展版，向后兼容旧版本）
///
/// 统计信息包括：
/// - `frames`: 总帧数
/// - `tx/rx`: 发送/接收字节数
/// - `ts_disorder`: 时间戳乱序计数
/// - `head8_modes`: 前 8 字节模式的 Top 5（旧格式，向后兼容）
/// - `head8_top`: 前 8 字节模式的 Top 5（新格式，带计数）
/// - `ts_min/ts_max/ts_span_ms`: 时间戳范围
/// - `len_min/len_max`: 帧长度范围
/// - `generated_at_ms`: 生成时间
///
/// # 参数
/// - `p`: JSONL 文件路径
///
/// # 返回
/// 包含统计信息的 JSON 对象
///
/// # 错误
/// 当文件读取或解析失败时返回错误
pub fn basic_verify<P: AsRef<Path>>(p: P) -> Result<serde_json::Value> {
    use crate::loopback::FrameDir;

    let mut frames = 0_usize;
    let mut tx = 0_usize;
    let mut rx = 0_usize;
    let mut disorder = 0_usize;
    let mut last_ts = 0_u64;
    let mut ts_min: Option<u64> = None;
    let mut ts_max: Option<u64> = None;
    let mut len_min: Option<usize> = None;
    let mut len_max: Option<usize> = None;
    let mut head8: HashMap<String, usize> = HashMap::new();

    for fr in stream_frames(&p)? {
        let fr = fr?;
        frames += 1;

        match fr.dir {
            FrameDir::Tx => tx += fr.len,
            FrameDir::Rx => rx += fr.len,
        }

        // 更新时间戳范围
        ts_min = Some(ts_min.map_or(fr.ts_ms, |v| v.min(fr.ts_ms)));
        ts_max = Some(ts_max.map_or(fr.ts_ms, |v| v.max(fr.ts_ms)));

        // 更新长度范围
        len_min = Some(len_min.map_or(fr.len, |v| v.min(fr.len)));
        len_max = Some(len_max.map_or(fr.len, |v| v.max(fr.len)));

        // 检测时间戳乱序
        if fr.ts_ms < last_ts {
            disorder += 1;
        }
        last_ts = fr.ts_ms;

        // 统计 head8 模式
        *head8.entry(fr.head8_hex).or_insert(0) += 1;
    }

    // 排序 Top 5（稳定顺序：count desc, hex asc）
    let mut kv: Vec<(String, usize)> = head8.into_iter().collect();
    kv.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    kv.truncate(5);

    // 旧格式（向后兼容）
    let modes: serde_json::Value = kv
        .iter()
        .map(|(k, v)| serde_json::json!({k: *v}))
        .collect();

    // 新格式（更清晰）
    let head8_top = kv
        .into_iter()
        .map(|(hex, count)| serde_json::json!({"hex": hex, "count": count}))
        .collect::<Vec<_>>();

    // 计算时间跨度
    let ts_span_ms = match (ts_min, ts_max) {
        (Some(a), Some(b)) => b.saturating_sub(a),
        _ => 0,
    };

    // 生成时间戳
    let gen_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    Ok(serde_json::json!({
        "frames": frames,
        "tx": tx,
        "rx": rx,
        "ts_disorder": disorder,
        "head8_modes": modes,
        "head8_top": head8_top,
        "ts_min": ts_min.unwrap_or(0),
        "ts_max": ts_max.unwrap_or(0),
        "ts_span_ms": ts_span_ms,
        "len_min": len_min.unwrap_or(0),
        "len_max": len_max.unwrap_or(0),
        "generated_at_ms": gen_ms
    }))
}

/// 回放校验（仅对 RX 帧执行 decode_ack 验证）
///
/// # 参数
/// - `proto`: 实现了 `Handshake` trait 的协议
/// - `p`: JSONL 文件路径
/// - `strict`: 是否为严格模式（遇到第一个错误即返回）
///
/// # 返回
/// `(总帧数, 错误数)`
///
/// # 错误
/// 严格模式下，遇到第一个解码错误时返回错误
pub fn replay_decode<P: AsRef<Path>>(
    proto: &dyn crate::handshake::Handshake,
    p: P,
    strict: bool,
) -> Result<(usize, usize)> {
    use crate::loopback::FrameDir;

    let mut frames = 0_usize;
    let mut errors = 0_usize;

    for item in stream_frames(p)? {
        let f = item?;

        if matches!(f.dir, FrameDir::Rx) {
            frames += 1;  // 只计数 RX 帧

            // 用 tail8/head8 还原一个最小切片（与 loopback 生成规则解耦）
            // 这里不做真实反序列化，只校验 decode_ack 的容错能力
            let buf_len = f.len.clamp(1, 64);
            let buf = vec![0_u8; buf_len];

            // 校验前 32 字节（或更少）
            let check_len = buf_len.min(32);
            if proto.decode_ack(&buf[..check_len]).is_err() {
                errors += 1;
                if strict {
                    return Err(anyhow!("replay strict failed at frame #{frames}"));
                }
            }
        }
    }

    Ok((frames, errors))
}
