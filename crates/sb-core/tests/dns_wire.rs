#[cfg(feature = "dns_udp")]
use sb_core::dns::udp::{build_query, parse_answers};

#[cfg(feature = "dns_udp")]
#[test]
fn build_query_is_stable() {
    let q = build_query("example.com", 1).unwrap();
    assert!(q.len() > 12); // header + qname
                           // 事务 ID 非零即可（具体数值不强断言，避免 flakiness）
    assert!(q[0] != 0 || q[1] != 0);
}

#[cfg(feature = "dns_udp")]
#[test]
fn parse_invalid_response() {
    // 这是一个极简的"解析入口存在性"测试；如需真包可放置一个固定样本
    // 这里只断言函数可被调用，不 panic（实际项目可加入样本 PCAP 解析）
    let _q = build_query("example.com", 1).unwrap();
    // 伪造一个太短的响应，parse 应返回 Err
    let resp = vec![0u8; 5]; // Too short for a valid DNS response
    let r = parse_answers(&resp, 1);
    assert!(r.is_err());
}
