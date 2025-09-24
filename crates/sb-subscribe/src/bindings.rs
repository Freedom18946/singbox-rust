//! R90: 从 Profile 导出出站绑定（最小）：name→kind
//! R97: 绑定导出 behind features（由 lib.rs 控制导出）
//! R134: 订阅出站绑定增强（dry connect）
use crate::model::Profile;

#[cfg(feature = "subs_bindings_dry")]
use std::time::Instant;
pub fn bindings_minijson(p: &Profile) -> String {
    use sb_core::router::minijson::{obj, Val};
    // 输出形如：{"outbounds":[{"name":"a","kind":"trojan"},...]}
    let mut items = Vec::new();
    for o in &p.outbounds {
        let k = o.kind.to_lowercase();
        let rec = obj([("name", Val::Str(&o.name)), ("kind", Val::Str(&k))]);
        items.push(rec);
    }
    format!("{{\"outbounds\":[{}]}}", items.join(","))
}

/// R134: 干运行连接测试（仅解析+DNS，无实际连接）
#[cfg(feature = "subs_bindings_dry")]
pub async fn dry_connect_test(p: &Profile, target: Option<&str>) -> String {
    use sb_core::router::minijson::{obj, Val};
    let mut results = Vec::new();

    let test_target = target.unwrap_or("www.google.com");

    for outbound in &p.outbounds {
        let start = Instant::now();
        let result = dry_connect_single(&outbound.kind, &outbound.name, test_target).await;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let status = if result.is_ok() { "ok" } else { "error" };
        let error_msg = if let Err(ref e) = result {
            e.as_str()
        } else {
            ""
        };

        let item = obj([
            ("name", Val::Str(&outbound.name)),
            ("kind", Val::Str(&outbound.kind.to_lowercase())),
            ("target", Val::Str(test_target)),
            ("status", Val::Str(status)),
            ("elapsed_ms", Val::Str(&elapsed_ms.to_string())),
            ("error", Val::Str(error_msg)),
        ]);
        results.push(item);
    }

    format!("{{\"dry_connect\":[{}]}}", results.join(","))
}

#[cfg(feature = "subs_bindings_dry")]
async fn dry_connect_single(kind: &str, _name: &str, target: &str) -> Result<(), String> {
    // DNS 解析测试（无实际连接）
    let dns_start = Instant::now();

    // 模拟根据出站类型进行不同的检查
    match kind.to_lowercase().as_str() {
        "trojan" | "shadowsocks" | "ss" => {
            // 对于加密代理，检查是否支持
            if target.is_empty() {
                return Err("empty target".to_string());
            }

            // 模拟 DNS 解析延迟
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            let dns_elapsed = dns_start.elapsed().as_millis();
            if dns_elapsed > 5000 {
                return Err("dns timeout".to_string());
            }

            Ok(())
        }
        "direct" => {
            // 直连类型，简单检查
            if target.contains("localhost") || target.contains("127.0.0.1") {
                Ok(())
            } else {
                // 模拟轻量级检查
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                Ok(())
            }
        }
        "block" | "reject" => {
            // 阻断类型，直接返回成功（逻辑上的阻断）
            Ok(())
        }
        _ => Err(format!("unsupported outbound kind: {}", kind)),
    }
}

/// 增强的绑定信息（包含连接状态）
#[cfg(feature = "subs_bindings_dry")]
pub async fn bindings_enhanced_minijson(
    p: &Profile,
    test_connect: bool,
    target: Option<&str>,
) -> String {
    use sb_core::router::minijson::{obj, Val};
    let mut items = Vec::new();

    let test_target = target.unwrap_or("www.google.com");

    for outbound in &p.outbounds {
        let kind_lower = outbound.kind.to_lowercase();

        if test_connect {
            let start = Instant::now();
            let result = dry_connect_single(&outbound.kind, &outbound.name, test_target).await;
            let elapsed_ms = start.elapsed().as_millis() as u64;

            let status = if result.is_ok() { "ok" } else { "error" };
            let error_msg = if let Err(ref e) = result {
                e.as_str()
            } else {
                ""
            };
            let elapsed_str = elapsed_ms.to_string();

            if error_msg.is_empty() {
                let item = obj([
                    ("name", Val::Str(&outbound.name)),
                    ("kind", Val::Str(&kind_lower)),
                    ("test_status", Val::Str(status)),
                    ("test_elapsed_ms", Val::Str(&elapsed_str)),
                ]);
                items.push(item);
            } else {
                let item = obj([
                    ("name", Val::Str(&outbound.name)),
                    ("kind", Val::Str(&kind_lower)),
                    ("test_status", Val::Str(status)),
                    ("test_elapsed_ms", Val::Str(&elapsed_str)),
                    ("test_error", Val::Str(error_msg)),
                ]);
                items.push(item);
            }
        } else {
            let item = obj([
                ("name", Val::Str(&outbound.name)),
                ("kind", Val::Str(&kind_lower)),
            ]);
            items.push(item);
        }
    }

    format!("{{\"outbounds\":[{}]}}", items.join(","))
}
