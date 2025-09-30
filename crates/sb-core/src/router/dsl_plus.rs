//! DSL+ 扩展：在原有简洁 DSL 上叠加 include 与宏（macro/use），并支持注释/空行。
//! 设计目标：纯文本预处理 -> 产出"标准 DSL 文本"，交给既有构建器解析。
//! 注意：本模块**不**引入任何路由新语义；只做纯文本展开。
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

/// 扩展并返回"标准 DSL 文本"。`cwd` 为相对 include 的基准目录。
/// 语法：
///   - 注释与空行：以 `#` 开头的整行忽略；全空白行忽略
///   - include:  `include "relative/or/absolute/path.dsl"`
///   - 宏定义:   `@macro NAME {`  ...若干"标准 DSL 行/宏调用"... `}`
///   - 宏调用:   `use NAME`
///   - 其它：    保留为"标准 DSL 行"（如 exact:/suffix:/default:/portset:/transport: 等）
pub fn expand_dsl_plus(input: &str, cwd: Option<&Path>) -> Result<String, String> {
    let base = cwd.map(Path::to_path_buf);
    let mut visited = HashSet::<PathBuf>::new();
    let mut macros = HashMap::<String, Vec<String>>::new();
    let mut out = Vec::<String>::new();

    // 先做一次"顶层展开"（顶层允许 include 与宏定义）
    expand_into(input, base.as_ref(), &mut visited, &mut macros, &mut out)
        .map_err(|e| format!("expand_dsl_plus: {e}"))?;

    // 第二阶段：将 out 中的 use NAME 展开（允许宏套宏）
    let mut final_lines = Vec::<String>::new();
    for line in out {
        let trim = line.trim();
        if trim.is_empty() || trim.starts_with('#') {
            continue;
        }
        if let Some(name) = trim.strip_prefix("use ").map(str::trim) {
            if name.is_empty() {
                return Err("use <NAME> 缺少名称".into());
            }
            match macros.get(name) {
                Some(lines) => final_lines.extend(lines.iter().cloned()),
                None => return Err(format!("use 未定义的宏：{name}")),
            }
            continue;
        }
        // 其余视为"标准 DSL 行"
        final_lines.push(trim.to_string());
    }
    Ok(final_lines.join("\n"))
}

fn expand_into(
    text: &str,
    cwd: Option<&PathBuf>,
    visited: &mut HashSet<PathBuf>,
    macros: &mut HashMap<String, Vec<String>>,
    out: &mut Vec<String>,
) -> Result<(), String> {
    enum State {
        Normal,
        Macro {
            name: String,
            buf: Vec<String>,
            depth: usize,
        },
    }
    let mut st = State::Normal;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if matches!(st, State::Normal) && line.starts_with("include ") {
            let path = parse_include_path(line).map_err(|e| format!("@{lineno}: {e}"))?;
            let abs = to_abs_path(&path, cwd);
            let canon = canonicalize_soft(&abs);
            if let Some(p) = canon {
                if !visited.insert(p.clone()) {
                    return Err(format!("检测到 include 循环：{}", p.display()));
                }
            }
            let sub = fs::read_to_string(&abs)
                .map_err(|e| format!("@{lineno}: 读取 include 失败 {}: {e}", abs.display()))?;
            let next_cwd = abs.parent().map(|p| p.to_path_buf());
            expand_into(&sub, next_cwd.as_ref(), visited, macros, out)?;
            continue;
        }
        // 宏定义开始
        if matches!(st, State::Normal) && line.starts_with("@macro ") {
            let name = parse_macro_name(line).map_err(|e| format!("@{lineno}: {e}"))?;
            st = State::Macro {
                name,
                buf: vec![],
                depth: 1,
            };
            continue;
        }
        // 宏体/结束
        match &mut st {
            State::Macro { name, buf, depth } => {
                if line.ends_with('{') {
                    *depth += 1;
                    buf.push(line.to_string());
                    continue;
                }
                if line == "}" {
                    *depth -= 1;
                    if *depth == 0 {
                        // 完成一个宏
                        macros.insert(name.clone(), buf.clone());
                        st = State::Normal;
                    }
                    continue;
                }
                buf.push(line.to_string());
            }
            State::Normal => {
                // 非宏期：原样进入 out，后续二阶段处理 use
                out.push(line.to_string());
            }
        }
    }
    if !matches!(st, State::Normal) {
        return Err("宏定义未正确闭合（缺少 `}`）".into());
    }
    Ok(())
}

fn parse_include_path(line: &str) -> Result<String, String> {
    // 允许：include "path" | include 'path' | include path
    let rest = line
        .strip_prefix("include")
        .ok_or("非法 include 语句")?
        .trim();
    if rest.starts_with('"') || rest.starts_with('\'') {
        let q = rest.chars().next().unwrap();
        let mut s = String::new();
        let mut closed = false;
        for ch in rest.chars().skip(1) {
            if ch == q {
                closed = true;
                break;
            }
            s.push(ch);
        }
        if !closed {
            return Err("include 引号未闭合".into());
        }
        Ok(s)
    } else if rest.is_empty() {
        Err("include 缺少路径".into())
    } else {
        Ok(rest.to_string())
    }
}

fn parse_macro_name(line: &str) -> Result<String, String> {
    // @macro NAME {   —— NAME 需为 [A-Za-z0-9_]+
    let rest = line.strip_prefix("@macro").ok_or("非法宏定义")?.trim();
    let (name, tail) = rest.split_once(' ').ok_or("宏定义缺少空格与 `{`")?;
    if tail.trim() != "{" {
        return Err("宏定义需以 `{` 起始".into());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("宏名仅允许 [A-Za-z0-9_]".into());
    }
    Ok(name.to_string())
}

fn to_abs_path(p: &str, cwd: Option<&PathBuf>) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        return path;
    }
    if let Some(base) = cwd {
        return base.join(path);
    }
    path
}

fn canonicalize_soft(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}
