#[tokio::test]
async fn elapsed_maps_to_dialerror_timeout() {
    // Produce a timeout error via tokio::time::timeout
    let fut = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Ok::<(), ()>(())
    };
    let res = tokio::time::timeout(std::time::Duration::from_millis(1), fut).await;
    assert!(res.is_err());
    let elapsed = res.err().unwrap();

    let de: sb_transport::dialer::DialError = elapsed.into();
    match de {
        sb_transport::dialer::DialError::Other(msg) => assert_eq!(msg, "timeout"),
        _ => panic!("expected timeout mapping"),
    }
}
