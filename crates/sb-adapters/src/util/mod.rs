//! Small helpers shared by examples/tests.
pub fn parse_payload_arg(s: &str) -> Vec<u8> {
    let st = s.trim();
    // 1) 去前缀：支持 0x/x（大小写均可）
    let mut rest = if let Some(x) = st
        .strip_prefix("0x")
        .or_else(|| st.strip_prefix("0X"))
        .or_else(|| st.strip_prefix('x'))
        .or_else(|| st.strip_prefix('X'))
    {
        x
    } else {
        st
    }
    .to_string();

    // 2) 去分隔符：空白与下划线
    rest.retain(|c| !c.is_whitespace() && c != '_');

    // 3) 若剩余全部为十六进制，则按 hex 解析；否则当作普通文本
    if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()) {
        // 奇数字节补前导 0
        if rest.len() % 2 != 0 {
            rest.insert(0, '0');
        }
        let bytes = rest.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let hx = rest.as_bytes();
        for i in (0..hx.len()).step_by(2) {
            let v = (hex_val(hx[i]) << 4) | hex_val(hx[i + 1]);
            out.push(v);
        }
        out
    } else {
        st.as_bytes().to_vec()
    }
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + (c - b'a'),
        b'A'..=b'F' => 10 + (c - b'A'),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hex_even() {
        assert_eq!(parse_payload_arg("0x48656c6c6f"), b"Hello");
    }
    #[test]
    fn test_hex_odd() {
        // 单数长度前补 0
        assert_eq!(parse_payload_arg("xF00"), vec![0x0f, 0x00]);
    }
    #[test]
    fn test_text() {
        assert_eq!(parse_payload_arg("ping"), b"ping");
    }
    #[test]
    fn test_hex_spaces() {
        assert_eq!(parse_payload_arg("48 65 6c 6c 6f"), b"Hello");
    }
}
