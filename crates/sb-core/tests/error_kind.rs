#[test]
fn sberror_kind_and_from_impls() {
    let ioe = std::io::Error::from(std::io::ErrorKind::TimedOut);
    let se: sb_core::error::SbError = ioe.into();
    assert_eq!(se.kind(), "Io");

    let pe = sb_core::error::SbError::parse("bad token");
    assert_eq!(pe.kind(), "Parse");

    let te = sb_core::error::SbError::Timeout {
        operation: "x".into(),
        timeout_ms: 1,
    };
    assert_eq!(te.kind(), "Timeout");

    let ae = sb_core::error::SbError::addr("invalid host");
    assert_eq!(ae.kind(), "Addr");

    let oe = sb_core::error::SbError::other("boom");
    assert_eq!(oe.kind(), "Other");
}
