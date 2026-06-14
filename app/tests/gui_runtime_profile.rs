#![allow(clippy::expect_used)]

fn feature_values(name: &str) -> Vec<String> {
    let manifest = include_str!("../Cargo.toml");
    let features_start = manifest.find("\n[features]\n").expect("[features] section");
    let feature_tail = &manifest[features_start..];
    let features_end = feature_tail.find("\n[[").unwrap_or(feature_tail.len());
    let features = &feature_tail[..features_end];
    let prefix = format!("{name} = [");

    let mut lines = features.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&prefix) {
            continue;
        }

        let mut block = String::from(trimmed);
        if !trimmed.contains(']') {
            for next in lines.by_ref() {
                let next = next.trim();
                block.push('\n');
                block.push_str(next);
                if next.contains(']') {
                    break;
                }
            }
        }
        return quoted_tokens(&block);
    }

    panic!("feature `{name}` not found");
}

fn quoted_tokens(block: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = block.chars();

    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }

        let mut value = String::new();
        for quoted in chars.by_ref() {
            if quoted == '"' {
                break;
            }
            value.push(quoted);
        }
        values.push(value);
    }

    values
}

fn has_feature(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}

#[test]
fn manifest_declares_gui_runtime_contract() {
    let gui_runtime = feature_values("gui_runtime");

    assert!(has_feature(&gui_runtime, "router"));
    assert!(has_feature(&gui_runtime, "adapters"));
    assert!(has_feature(&gui_runtime, "clash_api"));
    assert!(!has_feature(&gui_runtime, "v2ray_api"));
}

#[test]
fn default_profile_remains_non_gui_runtime() {
    let default = feature_values("default");

    assert!(has_feature(&default, "router"));
    assert!(!has_feature(&default, "adapters"));
    assert!(!has_feature(&default, "clash_api"));
    assert!(!has_feature(&default, "gui_runtime"));
}

#[cfg(feature = "gui_runtime")]
#[test]
fn compiled_gui_runtime_enables_required_features() {
    const {
        assert!(cfg!(feature = "gui_runtime"));
        assert!(cfg!(feature = "router"));
        assert!(cfg!(feature = "adapters"));
        assert!(cfg!(feature = "clash_api"));
    };
}
