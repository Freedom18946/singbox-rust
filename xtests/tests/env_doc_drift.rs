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
    .or_else(|_| fs::read_to_string(workspace_root.join("docs").join("ENV_VARS.md"))) // fallback for backward compatibility
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
            .current_dir(&workspace_root)
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
    // Legacy/deprecated names that may remain in docs for compatibility notes.
    let docs_legacy_allow: BTreeSet<String> = [
        "SB_CONFIG",
        "SB_DNS_HE_DELAY_MS",
        "SB_DNS_HE_DISABLE",
        "SB_H2_HOST",
        "SB_H2_PATH",
        "SB_HUP_PATH",
        "SB_TRANSPORT_FALLBACK",
        "SB_TROJAN_ALPN",
        "SB_TROJAN_RESPONSE_TIMEOUT_MS",
        "SB_TROJAN_SKIP_CERT_VERIFY",
        "SB_WS_HOST",
        "SB_WS_PATH",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let only_docs: Vec<_> = docs
        .difference(&code_set)
        .filter(|name| !docs_legacy_allow.contains(*name))
        .cloned()
        .collect();
    // We intentionally do not require docs to cover every internal/runtime SB_* env key.
    assert!(
        only_docs.is_empty(),
        "ENV docs reference unknown vars (excluding allowed legacy aliases): {:?}",
        only_docs,
    );
}
