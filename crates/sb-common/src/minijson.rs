//! R28: 极简 JSON 构造器（内部使用；覆盖常见数字/布尔/字符串场景）

/// JSON value enum for the mini JSON builder.
#[allow(missing_docs)]
pub enum Val<'a> {
    Str(&'a str),
    NumU(u64),
    NumI(i64),
    NumF(f64),
    Bool(bool),
    Raw(&'a str), // 已经是合法 JSON 片段时可用
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn obj<const N: usize>(kvs: [(&str, Val); N]) -> String {
    let mut s = String::from("{");
    for (i, (k, v)) in kvs.into_iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(&esc(k));
        s.push_str("\":");
        match v {
            Val::Str(t) => {
                s.push('"');
                s.push_str(&esc(t));
                s.push('"');
            }
            Val::NumU(n) => {
                s.push_str(&format!("{}", n));
            }
            Val::NumI(n) => {
                s.push_str(&format!("{}", n));
            }
            Val::NumF(n) => {
                s.push_str(&format!("{}", n));
            }
            Val::Bool(b) => {
                s.push_str(if b { "true" } else { "false" });
            }
            Val::Raw(r) => {
                s.push_str(r);
            }
        }
    }
    s.push('}');
    s
}

pub fn arr_str(list: &[&str]) -> String {
    let mut s = String::from("[");
    for (i, v) in list.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(&esc(v));
        s.push('"');
    }
    s.push(']');
    s
}

/// R40：数组（无符号数）
pub fn arr_num_u(list: &[u64]) -> String {
    let mut s = String::from("[");
    for (i, v) in list.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{}", v));
    }
    s.push(']');
    s
}

/// R40：对象数组（预构造的对象字符串）
pub fn arr_obj(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(v);
    }
    s.push(']');
    s
}
