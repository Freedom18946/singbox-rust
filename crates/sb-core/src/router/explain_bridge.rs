#![cfg(feature = "explain")]
//! 旁路“重放”桥接：不入数据路径；从只读索引/助手获取真实匹配结果。
use super::explain::{ExplainQuery, ExplainResult, ExplainTrace};
use super::explain_index::{self, ExplainIndex};
use crate::router::RouterHandle;

/// run：固定顺序重放匹配，生成 ExplainTrace
pub fn run(router: &RouterHandle, q: ExplainQuery) -> ExplainResult {
    let mut trace = ExplainTrace::default();
    // 从 Router 旁路导出只读索引（不会修改运行时）
    let idx = load_or_fetch_index(router);

    // 1) override
    if let Some((kind, when, to, why)) = try_override(&idx, &q) {
        let rid = crate::router::rule_id::rule_sha8(kind, &when, to);
        trace.push("override", rid.clone(), true, why.clone());
        return ExplainResult::new("override", rid, why, trace);
    } else {
        trace.push("override", "-", false, "no_override");
    }

    // 2) cidr
    if let Some((kind, when, to, why)) = try_cidr(&idx, q.ip) {
        let rid = crate::router::rule_id::rule_sha8(kind, &when, to);
        trace.push("cidr", rid.clone(), true, why.clone());
        // 3) geo（可选）
        if let Some((gk, gw, gt, gwhy)) = try_geo(router, &idx, q.ip) {
            trace.push(
                "geo",
                crate::router::rule_id::rule_sha8(gk, &gw, gt),
                true,
                gwhy,
            );
        } else {
            trace.push("geo", "-", false, "no_geo_match");
        }
        return ExplainResult::new("cidr", rid, why, trace);
    } else {
        trace.push("cidr", "-", false, "no_cidr_match");
    }

    // 4) suffix / exact（域名规则）
    if let Some(sni) = &q.sni {
        if let Some((sk, sw, st, swhy)) = try_suffix(&idx, sni) {
            let rid = crate::router::rule_id::rule_sha8(sk, &sw, st);
            trace.push("suffix", rid.clone(), true, swhy.clone());
            return ExplainResult::new("suffix", rid, swhy, trace);
        } else {
            trace.push("suffix", "-", false, "no_suffix");
        }
        if let Some((ek, ew, et, ewhy)) = try_exact(&idx, sni) {
            let rid = crate::router::rule_id::rule_sha8(ek, &ew, et);
            trace.push("exact", rid.clone(), true, ewhy.clone());
            return ExplainResult::new("exact", rid, ewhy, trace);
        } else {
            trace.push("exact", "-", false, "no_exact");
        }
    } else {
        trace.push("suffix", "-", false, "no_sni");
        trace.push("exact", "-", false, "no_sni");
    }

    // 5) default
    trace.push("default", "default", true, "fallthrough");
    ExplainResult::new("default", "default", "fallthrough", trace)
}

/// Rebuild the global explain index from a rules snapshot.
pub fn rebuild_index(rules_json: &serde_json::Value) -> Result<(), String> {
    let idx = ExplainIndex::from_rules_json(rules_json);
    explain_index::set_index(idx);
    Ok(())
}

fn load_or_fetch_index(router: &RouterHandle) -> ExplainIndex {
    let idx = explain_index::get_index();
    if !idx.is_empty() {
        return idx;
    }

    if let Ok(snapshot) = router.export_rules_json() {
        if rebuild_index(&snapshot).is_ok() {
            return explain_index::get_index();
        }
    }

    idx
}

fn wrap<'a>(
    kind: &'static str,
    to: &'a str,
    when: &'a serde_json::Value,
    why: String,
) -> (&'static str, &'a serde_json::Value, &'a str, String) {
    (kind, when, to, why)
}

fn try_override<'a>(
    idx: &'a ExplainIndex,
    q: &'a super::explain::ExplainQuery,
) -> Option<(&'static str, &'a serde_json::Value, &'a str, String)> {
    if let Some(sni) = &q.sni {
        if let Some((r, why)) = idx.match_override_exact(sni) {
            return Some(wrap("override_exact", r.to.as_str(), &r.when, why));
        }
        if let Some((r, why)) = idx.match_override_suffix(sni) {
            return Some(wrap("override_suffix", r.to.as_str(), &r.when, why));
        }
    }
    None
}

fn try_cidr<'a>(
    idx: &'a ExplainIndex,
    ip: Option<std::net::IpAddr>,
) -> Option<(&'static str, &'a serde_json::Value, &'a str, String)> {
    idx.match_cidr(ip)
        .map(move |(r, why)| wrap("cidr", r.to.as_str(), &r.when, why))
}

fn try_geo<'a>(
    router: &RouterHandle,
    idx: &'a ExplainIndex,
    ip: Option<std::net::IpAddr>,
) -> Option<(&'static str, &'a serde_json::Value, &'a str, String)> {
    let ip = ip?;
    if let Some(cc) = router.geo_cc(ip) {
        return idx
            .match_geo_cc(&cc)
            .map(|(r, why)| wrap("geo", &r.to, &r.when, why));
    }
    None
}

fn try_suffix<'a>(
    idx: &'a ExplainIndex,
    sni: &'a str,
) -> Option<(&'static str, &'a serde_json::Value, &'a str, String)> {
    idx.match_suffix(sni)
        .map(move |(r, why)| wrap("suffix", r.to.as_str(), &r.when, why))
}

fn try_exact<'a>(
    idx: &'a ExplainIndex,
    sni: &'a str,
) -> Option<(&'static str, &'a serde_json::Value, &'a str, String)> {
    idx.match_exact(sni)
        .map(move |(r, why)| wrap("exact", r.to.as_str(), &r.when, why))
}
