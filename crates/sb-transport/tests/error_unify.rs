#[test]
fn dialerror_maps_to_sberror_kinds() {
    let e = sb_transport::dialer::DialError::Io(std::io::Error::from(std::io::ErrorKind::NotFound));
    let se: sb_core::error::SbError = e.into();
    assert_eq!(se.kind(), "Io");

    let e2 = sb_transport::dialer::DialError::Other("oops".into());
    let se2: sb_core::error::SbError = e2.into();
    assert_eq!(se2.kind(), "Other");
}

