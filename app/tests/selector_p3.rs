use sb_core::outbound::p3_selector::{P3Selector, PickerConfig};

#[test]
fn cold_start_and_jitter() {
    let mut s = P3Selector::new(
        vec!["a".into(), "b".into(), "c".into()],
        PickerConfig::default(),
    );
    // 冷启动：不应拔掉新选中的迅速切换
    for _ in 0..5 {
        s.record_rtt("a", 30.0);
        s.record_rtt("b", 30.0);
        s.record_rtt("c", 30.0);
    }
    let p1 = s.pick();
    // 轻微波动不应引发切换
    s.record_rtt(&p1, 28.0);
    let p2 = s.pick();
    assert_eq!(p1, p2);
}

#[test]
fn fuse_penalty_applies() {
    let mut s = P3Selector::new(vec!["a".into(), "b".into()], PickerConfig::default());
    for _ in 0..10 {
        s.record_rtt("a", 20.0);
        s.record_rtt("b", 20.0);
    }
    s.record_result("a", false); // 熔断 a
    let p = s.pick();
    assert_eq!(p, "b");
}
