#![cfg(feature = "explain")]
use super::RouterHandle;
use std::net::IpAddr;

pub fn try_override(
    _r: &RouterHandle,
    _q: &super::explain::ExplainQuery,
) -> Option<(String, String)> {
    // TODO: 调用你现有的 override 查询接口；占位实现：
    None
}

pub fn try_cidr(_r: &RouterHandle, _ip: Option<IpAddr>) -> Option<(String, String)> {
    // TODO: 调用现有CIDR匹配逻辑
    None
}

pub fn try_geo(_r: &RouterHandle, _ip: Option<IpAddr>) -> Option<(String, String)> {
    // TODO: 调用现有GeoIP匹配逻辑
    None
}

pub fn try_suffix(_r: &RouterHandle, _sni: &str) -> Option<(String, String)> {
    // TODO: 调用现有后缀匹配逻辑
    None
}

pub fn try_exact(_r: &RouterHandle, _sni: &str) -> Option<(String, String)> {
    // TODO: 调用现有精确匹配逻辑
    None
}
