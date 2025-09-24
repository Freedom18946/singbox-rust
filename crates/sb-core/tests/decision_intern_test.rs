#[test]
fn intern_dedup() {
    let a = sb_core::router::decision_intern::intern_decision("direct");
    let b = sb_core::router::decision_intern::intern_decision("direct");
    assert!(std::ptr::eq(a, b));
    assert_eq!(sb_core::router::decision_intern::intern_size(), 1);
}
