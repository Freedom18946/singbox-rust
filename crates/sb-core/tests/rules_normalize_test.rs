#![cfg(feature = "router")]

use sb_core::router::rules_normalize;

#[test]
fn normalize_basic() {
    let txt =
        "\u{feff}  # comment \r\nsuffix:example.com=proxy\r\nexact:a.example.com=proxy\r\n\r\n";
    let out = rules_normalize(txt);
    assert!(out.contains("# comment"));
    assert!(out.contains("exact:a.example.com=proxy"));
    let exact_pos = out.find("exact:").unwrap();
    let suffix_pos = out.find("suffix:").unwrap();
    assert!(exact_pos < suffix_pos);
    assert!(out.ends_with('\n'));
}
