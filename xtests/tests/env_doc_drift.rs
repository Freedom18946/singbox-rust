use std::{collections::BTreeSet, fs};

#[test]
fn env_vars_in_docs_match_code_refs() {
    let md = fs::read_to_string("docs/02-cli-reference/environment-variables.md")
        .or_else(|_| fs::read_to_string("docs/ENV_VARS.md")) // fallback for backward compatibility
        .expect("environment-variables.md");
    let mut docs = BTreeSet::new();

    // Simple pattern matching without regex
    for line in md.lines() {
        let mut chars = line.chars().peekable();
        while let Some(&ch) = chars.peek() {
            if ch == '`' {
                chars.next(); // consume `
                let mut var = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '`' {
                        break;
                    }
                    var.push(chars.next().unwrap());
                }
                if var.starts_with("SB_")
                    && var
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    docs.insert(var);
                }
                if chars.peek() == Some(&'`') {
                    chars.next(); // consume closing `
                }
            } else {
                chars.next();
            }
        }
    }

    // very cheap code grep
    let code = String::from_utf8(
        std::process::Command::new("bash")
            .args(["-lc", "grep -Rho \"SB_[A-Z0-9_]\\+\" crates app | sort -u"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let mut code_set = BTreeSet::new();
    for line in code.lines() {
        code_set.insert(line.trim().to_string());
    }
    let only_docs: Vec<_> = docs.difference(&code_set).cloned().collect();
    let only_code: Vec<_> = code_set.difference(&docs).cloned().collect();
    assert!(
        only_docs.is_empty() && only_code.is_empty(),
        "ENV drift: docs_only={:?}, code_only={:?}",
        only_docs,
        only_code
    );
}
