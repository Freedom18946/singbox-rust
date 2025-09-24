//! Back-compat re-exports for IssueCode.
pub use sb_types::IssueCode;

// 若 sb-core 内部需要补充"分类映射"工具，可以继续在这里实现：
pub mod classify {
    use sb_types::IssueCode;
    use std::io;
    pub fn from_io_error(e: &io::Error) -> IssueCode {
        match e.kind() {
            io::ErrorKind::TimedOut => IssueCode::NetTimeout,
            io::ErrorKind::ConnectionRefused => IssueCode::NetRefused,
            _ => IssueCode::NetOther,
        }
    }
}
