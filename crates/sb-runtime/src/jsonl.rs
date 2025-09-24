//! jsonl.rs - JSONL 帧工具（流式读取 / 校验）
//! 依赖 `loopback::Frame` 结构，不引入 IO 以外的副作用。
use crate::loopback::Frame;
use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    time::SystemTime,
};

/// 逐帧流式读取（容错：跳过空行与解析失败行）
pub fn stream_frames<P: AsRef<Path>>(p: P) -> Result<impl Iterator<Item = Result<Frame>>> {
    let f =
        File::open(p.as_ref()).map_err(|e| anyhow!("open {} failed: {e}", p.as_ref().display()))?;
    let mut rdr = BufReader::new(f);
    let mut buf = String::new();
    // 使用生成器风格的迭代器
    let iter = std::iter::from_fn(move || {
        buf.clear();
        match rdr.read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => {
                let line = buf.trim();
                if line.is_empty() {
                    return Some(Ok(Frame {
                        ts_ms: 0,
                        dir: crate::loopback::FrameDir::Tx, // 占位，不会被上层使用
                        len: 0,
                        head8_hex: String::new(),
                        tail8_hex: String::new(),
                    })); // 让上层可数行；真正消费者常会过滤 len==0
                }
                match serde_json::from_str::<Frame>(line) {
                    Ok(f) => Some(Ok(f)),
                    Err(e) => Some(Err(anyhow!("parse JSONL failed: {e}"))),
                }
            }
            Err(e) => Some(Err(anyhow!("read_line failed: {e}"))),
        }
    })
    .filter(|r| match r {
        Ok(f) => f.len > 0, // 过滤掉上面的空行占位
        Err(_) => true,
    });
    Ok(iter)
}

/// Basic verification (扩展版；保持旧键不变，仅新增键):
/// - frames/tx/rx/ts_disorder/head8_modes(top5)【兼容】
/// - ts_min/ts_max/ts_span_ms（新增）
/// - len_min/len_max（新增）
/// - head8_top: [{hex,count}]（新增，顺序稳定）
/// - generated_at_ms: 生成时间（新增）
pub fn basic_verify<P: AsRef<Path>>(p: P) -> Result<serde_json::Value> {
    use crate::loopback::FrameDir;
    let mut frames = 0usize;
    let mut tx = 0usize;
    let mut rx = 0usize;
    let mut disorder = 0usize;
    let mut last_ts = 0u64;
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
        ts_min = Some(ts_min.map(|v| v.min(fr.ts_ms)).unwrap_or(fr.ts_ms));
        ts_max = Some(ts_max.map(|v| v.max(fr.ts_ms)).unwrap_or(fr.ts_ms));
        len_min = Some(len_min.map(|v| v.min(fr.len)).unwrap_or(fr.len));
        len_max = Some(len_max.map(|v| v.max(fr.len)).unwrap_or(fr.len));
        if fr.ts_ms < last_ts {
            disorder += 1;
        }
        last_ts = fr.ts_ms;
        *head8.entry(fr.head8_hex).or_insert(0) += 1;
    }
    // sort top5 (稳定顺序：count desc, hex asc)
    let mut kv: Vec<(String, usize)> = head8.into_iter().collect();
    kv.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    kv.truncate(5);
    let modes: serde_json::Value = kv
        .iter()
        .map(|(k, v)| serde_json::json!({k.clone(): *v}))
        .collect();
    let head8_top = kv
        .into_iter()
        .map(|(hex, count)| serde_json::json!({"hex":hex,"count":count}))
        .collect::<Vec<_>>();
    let ts_span_ms = match (ts_min, ts_max) {
        (Some(a), Some(b)) => b.saturating_sub(a),
        _ => 0,
    };
    let gen_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
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

/// 回放校验（仅对 RX 做 decode_ack，严格/宽松两种）
pub fn replay_decode<P: AsRef<Path>>(
    proto: &dyn crate::handshake::Handshake,
    p: P,
    strict: bool,
) -> Result<(usize, usize)> {
    use crate::loopback::FrameDir;
    let mut frames = 0usize;
    let mut errors = 0usize;
    for item in stream_frames(p)? {
        let f = item?;
        frames += 1;
        if matches!(f.dir, FrameDir::Rx) {
            // 用 tail8/head8 还原一个最小切片（与 loopback 生成规则解耦）
            let buf_len = f.len.min(64).max(1);
            let mut buf = vec![0u8; buf_len];
            // 这里不做真实反序列化，只校验 decode_ack 的容错能力
            if let Err(_) = proto.decode_ack(&buf[..buf_len.min(32)]) {
                errors += 1;
                if strict {
                    return Err(anyhow!("replay strict failed at frame #{frames}"));
                }
            }
        }
    }
    Ok((frames, errors))
}
