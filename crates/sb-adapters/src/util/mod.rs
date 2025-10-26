//! Small helpers shared by examples and tests.

/// Parses a payload argument from command-line or test input.
///
/// Supports multiple formats:
/// - Hexadecimal with prefixes: `0x48656c6c6f`, `x48656c6c6f`, `X48656c6c6f`
/// - Hexadecimal with spaces: `48 65 6c 6c 6f`
/// - Plain text: `Hello`
///
/// # Examples
///
/// ```
/// # use sb_adapters::util::parse_payload_arg;
/// assert_eq!(parse_payload_arg("0x48656c6c6f"), b"Hello");
/// assert_eq!(parse_payload_arg("48 65 6c 6c 6f"), b"Hello");
/// assert_eq!(parse_payload_arg("ping"), b"ping");
/// ```
#[must_use]
pub fn parse_payload_arg(s: &str) -> Vec<u8> {
    let st = s.trim();

    // 1) Strip hex prefix: supports 0x/x (case-insensitive)
    let rest = if let Some(x) = st
        .strip_prefix("0x")
        .or_else(|| st.strip_prefix("0X"))
        .or_else(|| st.strip_prefix('x'))
        .or_else(|| st.strip_prefix('X'))
    {
        x
    } else {
        st
    };

    // 2) Remove separators: whitespace and underscores
    let filtered: String = rest
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect();

    // 3) If remaining chars are all hex digits, parse as hex; otherwise treat as plain text
    if !filtered.is_empty() && filtered.chars().all(|c| c.is_ascii_hexdigit()) {
        // Pad odd-length hex strings with leading '0'
        let hex_str = if !filtered.len().is_multiple_of(2) {
            format!("0{filtered}")
        } else {
            filtered
        };

        let bytes = hex_str.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);

        for i in (0..bytes.len()).step_by(2) {
            let v = (hex_val(bytes[i]) << 4) | hex_val(bytes[i + 1]);
            out.push(v);
        }
        out
    } else {
        st.as_bytes().to_vec()
    }
}

/// Converts a hex digit ASCII byte to its numeric value.
#[inline]
const fn hex_val(c: u8) -> u8 {
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
        // Odd-length hex gets leading '0' padding
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
