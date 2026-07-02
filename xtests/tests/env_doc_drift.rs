use std::{collections::BTreeSet, fs};

#[test]
fn env_vars_in_docs_match_code_refs() {
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let md = fs::read_to_string(
        workspace_root
            .join("docs")
            .join("02-cli-reference")
            .join("environment-variables.md"),
    )
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
    let grep = std::process::Command::new("bash")
        .current_dir(&workspace_root)
        .args(["-lc", "grep -Rho \"SB_[A-Z0-9_]\\+\" crates app | sort -u"])
        .output()
        .expect("grep env vars");
    assert!(
        grep.status.success(),
        "env var grep failed: {}",
        String::from_utf8_lossy(&grep.stderr)
    );
    let code = String::from_utf8(grep.stdout).expect("grep output utf8");
    let mut code_set = BTreeSet::new();
    for line in code.lines() {
        code_set.insert(line.trim().to_string());
    }

    let only_docs: Vec<_> = docs.difference(&code_set).cloned().collect();
    // We intentionally do not require docs to cover every internal/runtime SB_* env key.
    assert!(
        only_docs.is_empty(),
        "ENV docs reference unknown vars: {:?}",
        only_docs,
    );
}
