/// Return the Go-compatible effective tag for indexed config entries.
///
/// Go sing-box treats an empty/missing tag as the entry's array index string
/// when checking duplicates. Rust accepts both raw `tag` and post-migration
/// `name`; the first non-empty value wins.
pub(crate) fn effective_tag(
    primary: Option<&str>,
    secondary: Option<&str>,
    index: usize,
) -> String {
    primary
        .filter(|tag| !tag.is_empty())
        .or_else(|| secondary.filter(|tag| !tag.is_empty()))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| index.to_string())
}
