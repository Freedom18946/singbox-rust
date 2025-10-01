//! Source format processing utilities

/// Infer format from file extension
pub fn infer_format_from_path(path: &str) -> Option<super::RuleSetFormat> {
    if path.ends_with(".srs") {
        Some(super::RuleSetFormat::Binary)
    } else if path.ends_with(".json") {
        Some(super::RuleSetFormat::Source)
    } else {
        None
    }
}

/// Infer format from URL
pub fn infer_format_from_url(url: &str) -> Option<super::RuleSetFormat> {
    infer_format_from_path(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_format() {
        assert_eq!(
            infer_format_from_path("/path/to/ruleset.srs"),
            Some(super::super::RuleSetFormat::Binary)
        );
        assert_eq!(
            infer_format_from_path("/path/to/ruleset.json"),
            Some(super::super::RuleSetFormat::Source)
        );
        assert_eq!(infer_format_from_path("/path/to/ruleset.txt"), None);
    }
}
