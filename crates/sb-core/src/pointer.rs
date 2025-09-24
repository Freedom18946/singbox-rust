//! RFC6901 JSON Pointer implementation
//!
//! This module provides JSON Pointer functionality for precise error location
//! reporting in configuration validation.

use std::fmt;

/// JSON Pointer implementation following RFC6901
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPointer {
    segments: Vec<String>,
}

impl JsonPointer {
    /// Create a new empty JSON pointer
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Create a JSON pointer from a path string
    pub fn from_path(path: &str) -> Self {
        if path.is_empty() || path == "/" {
            return Self::new();
        }

        let segments = path
            .strip_prefix('/')
            .unwrap_or(path)
            .split('/')
            .map(|s| Self::decode_segment(s))
            .collect();

        Self { segments }
    }

    /// Add a segment to the pointer
    pub fn push(&mut self, segment: &str) {
        self.segments.push(segment.to_string());
    }

    /// Add a segment and return a new pointer
    pub fn with_segment(mut self, segment: &str) -> Self {
        self.push(segment);
        self
    }

    /// Add an array index segment
    pub fn push_index(&mut self, index: usize) {
        self.segments.push(index.to_string());
    }

    /// Add an array index segment and return a new pointer
    pub fn with_index(mut self, index: usize) -> Self {
        self.push_index(index);
        self
    }

    /// Get the segments of this pointer
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Check if this pointer is empty (root)
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Get the parent pointer (remove last segment)
    pub fn parent(&self) -> Self {
        if self.segments.is_empty() {
            return self.clone();
        }

        Self {
            segments: self.segments[..self.segments.len() - 1].to_vec(),
        }
    }

    /// Get the last segment
    pub fn last_segment(&self) -> Option<&str> {
        self.segments.last().map(|s| s.as_str())
    }

    /// Convert to RFC6901 string representation
    pub fn to_string(&self) -> String {
        if self.segments.is_empty() {
            return "".to_string();
        }

        let mut result = String::new();
        for segment in &self.segments {
            result.push('/');
            result.push_str(&Self::encode_segment(segment));
        }
        result
    }

    /// Encode a segment according to RFC6901 rules
    fn encode_segment(segment: &str) -> String {
        segment
            .replace('~', "~0") // ~ must be encoded first
            .replace('/', "~1") // then /
    }

    /// Decode a segment according to RFC6901 rules
    fn decode_segment(segment: &str) -> String {
        segment
            .replace("~1", "/") // / must be decoded first
            .replace("~0", "~") // then ~
    }
}

impl Default for JsonPointer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl From<&str> for JsonPointer {
    fn from(path: &str) -> Self {
        Self::from_path(path)
    }
}

impl From<String> for JsonPointer {
    fn from(path: String) -> Self {
        Self::from_path(&path)
    }
}

/// Builder for constructing JSON pointers
pub struct JsonPointerBuilder {
    pointer: JsonPointer,
}

impl JsonPointerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            pointer: JsonPointer::new(),
        }
    }

    /// Add a field segment
    pub fn field(mut self, name: &str) -> Self {
        self.pointer.push(name);
        self
    }

    /// Add an array index segment
    pub fn index(mut self, index: usize) -> Self {
        self.pointer.push_index(index);
        self
    }

    /// Build the final pointer
    pub fn build(self) -> JsonPointer {
        self.pointer
    }
}

impl Default for JsonPointerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pointer() {
        let ptr = JsonPointer::new();
        assert!(ptr.is_empty());
        assert_eq!(ptr.to_string(), "");
        assert_eq!(ptr.segments().len(), 0);
    }

    #[test]
    fn test_simple_pointer() {
        let mut ptr = JsonPointer::new();
        ptr.push("foo");
        ptr.push("bar");

        assert_eq!(ptr.to_string(), "/foo/bar");
        assert_eq!(ptr.segments(), &["foo", "bar"]);
        assert!(!ptr.is_empty());
    }

    #[test]
    fn test_array_index_pointer() {
        let ptr = JsonPointer::new()
            .with_segment("items")
            .with_index(0)
            .with_segment("name");

        assert_eq!(ptr.to_string(), "/items/0/name");
        assert_eq!(ptr.segments(), &["items", "0", "name"]);
    }

    #[test]
    fn test_from_path() {
        let ptr = JsonPointer::from_path("/foo/bar/baz");
        assert_eq!(ptr.segments(), &["foo", "bar", "baz"]);
        assert_eq!(ptr.to_string(), "/foo/bar/baz");

        let empty_ptr = JsonPointer::from_path("");
        assert!(empty_ptr.is_empty());

        let root_ptr = JsonPointer::from_path("/");
        assert!(root_ptr.is_empty());
    }

    #[test]
    fn test_encoding_decoding() {
        // Test special characters that need encoding
        let ptr = JsonPointer::new()
            .with_segment("foo~bar") // contains ~
            .with_segment("baz/qux"); // contains /

        assert_eq!(ptr.to_string(), "/foo~0bar/baz~1qux");

        // Test decoding
        let decoded_ptr = JsonPointer::from_path("/foo~0bar/baz~1qux");
        assert_eq!(decoded_ptr.segments(), &["foo~bar", "baz/qux"]);
    }

    #[test]
    fn test_parent_and_last_segment() {
        let ptr = JsonPointer::from_path("/foo/bar/baz");

        assert_eq!(ptr.last_segment(), Some("baz"));

        let parent = ptr.parent();
        assert_eq!(parent.to_string(), "/foo/bar");
        assert_eq!(parent.last_segment(), Some("bar"));

        let grandparent = parent.parent();
        assert_eq!(grandparent.to_string(), "/foo");

        let root = grandparent.parent();
        assert_eq!(root.to_string(), "");
        assert!(root.is_empty());

        // Parent of empty should be empty
        let still_root = root.parent();
        assert!(still_root.is_empty());
    }

    #[test]
    fn test_builder() {
        let ptr = JsonPointerBuilder::new()
            .field("config")
            .field("inbounds")
            .index(0)
            .field("listen")
            .build();

        assert_eq!(ptr.to_string(), "/config/inbounds/0/listen");
        assert_eq!(ptr.segments(), &["config", "inbounds", "0", "listen"]);
    }

    #[test]
    fn test_display_trait() {
        let ptr = JsonPointer::from_path("/foo/bar");
        assert_eq!(format!("{}", ptr), "/foo/bar");
    }

    #[test]
    fn test_from_string() {
        let ptr: JsonPointer = "/foo/bar".into();
        assert_eq!(ptr.to_string(), "/foo/bar");

        let ptr: JsonPointer = String::from("/baz/qux").into();
        assert_eq!(ptr.to_string(), "/baz/qux");
    }

    #[test]
    fn test_complex_encoding() {
        // Test a complex case with multiple special characters
        let segment_with_both = "path~with/both";
        let ptr = JsonPointer::new().with_segment(segment_with_both);

        // Should encode ~ first, then /
        assert_eq!(ptr.to_string(), "/path~0with~1both");

        // Decoding should restore original
        let decoded = JsonPointer::from_path("/path~0with~1both");
        assert_eq!(decoded.segments()[0], segment_with_both);
    }
}
