#!/bin/bash
# check-boundaries.sh - 依赖边界检查（CI / pre-commit 使用）
# 用法:
#   ./check-boundaries.sh            # 严格模式（默认）：任何违规返回非零
#   ./check-boundaries.sh --strict   # 严格模式（显式）
#   ./check-boundaries.sh --report   # 报告模式：仅输出，不失败
#
# 覆盖违规类别：
#   V1(Web) V2(TLS/QUIC) V3(协议实现) V4(sb-adapters 反向依赖) V5(subscribe)
#   V6(strict): default feature 闭包 + feature owner tree + workspace 反向依赖 allowlist

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

REPORT_ONLY=false
case "${1:-}" in
    ""|"--strict")
        ;;
    "--report")
        REPORT_ONLY=true
        ;;
    *)
        echo "Usage: $0 [--strict|--report]" >&2
        exit 2
        ;;
esac

FAILED=0
fail() { FAILED=$((FAILED + 1)); }

echo "=== 依赖边界检查 ($(date +%Y-%m-%d\ %H:%M)) ==="
echo ""

# ─── Helper: check if a file is inside a feature-gated module ─────
# Returns 0 (true) if the file's parent module is behind a #[cfg(feature ...)]
# in its parent mod.rs, or if the file itself is in a known feature-gated directory.
is_feature_gated_module() {
    local file="$1"
    case "$file" in
        # Known feature-gated parent modules
        */services/ssmapi/*) return 0 ;;
        */services/derp/*) return 0 ;;
        */services/mesh_test/*) return 0 ;;
        # outbound protocol files (gated by out_* features)
        */outbound/trojan.rs|*/outbound/trojan/*) return 0 ;;
        */outbound/vmess.rs|*/outbound/vmess/*) return 0 ;;
        */outbound/vless.rs|*/outbound/vless/*) return 0 ;;
        */outbound/shadowsocks.rs|*/outbound/ss/*) return 0 ;;
        */outbound/shadowtls.rs) return 0 ;;
        */outbound/naive_h2.rs) return 0 ;;
        */outbound/hysteria.rs|*/outbound/hysteria/*) return 0 ;;
        */outbound/hysteria2.rs|*/outbound/hysteria2/*) return 0 ;;
        */outbound/tuic.rs|*/outbound/tuic/*) return 0 ;;
        */outbound/wireguard.rs) return 0 ;;
        */outbound/ssh.rs) return 0 ;;
        */outbound/quic/*) return 0 ;;
        # transport/tls module (gated by tls_rustls)
        */transport/tls.rs|*/transport/tls/*) return 0 ;;
        # dns modules with TLS deps
        */dns/upstream.rs) return 0 ;;
    esac
    return 1
}

# Helper: check if a specific line in a file is protected by an inline #[cfg(feature ...)]
# Checks up to 5 preceding lines for a cfg(feature gate.
is_line_feature_gated() {
    local file="$1"
    local linenum="$2"
    # Check preceding lines (up to 5) for #[cfg(feature
    local i
    for i in 1 2 3 4 5; do
        local check_line=$((linenum - i))
        [ "$check_line" -lt 1 ] && break
        local prev
        prev=$(sed -n "${check_line}p" "$file" 2>/dev/null || true)
        # If we hit a blank line or closing brace, stop looking
        case "$prev" in
            "") break ;;
            "}") break ;;
        esac
        if echo "$prev" | grep -q '#\[cfg(.*feature'; then
            return 0
        fi
    done
    return 1
}

# ─── V1: sb-core Web 框架 ──────────────────────────────
echo "── V1: sb-core Web 框架依赖 ──"

# V1a: Source code check — only count NON-feature-gated imports
# Feature-gated web framework code is acceptable (it's optional).
V1_COUNT=0
while IFS= read -r file; do
    # Skip files inside feature-gated modules
    if is_feature_gated_module "$file"; then
        continue
    fi
    # For each matching line, check if the previous line is a #[cfg(feature gate
    while IFS=: read -r linenum content; do
        if ! is_line_feature_gated "$file" "$linenum"; then
            V1_COUNT=$((V1_COUNT + 1))
        fi
    done < <(grep -n "use axum\|use tonic\|use tower::" "$file" 2>/dev/null || true)
done < <(find crates/sb-core/src/ -name '*.rs' 2>/dev/null)

# V1b: Cargo.toml — no non-optional web framework deps
V1_CARGO=0
for dep in axum tonic tower; do
    # Match lines like: axum = "0.7"  or  axum = { version = ...}
    # But NOT lines with optional = true
    if grep -qE "^${dep} " crates/sb-core/Cargo.toml 2>/dev/null; then
        # Check if it's optional
        line=$(grep -E "^${dep} " crates/sb-core/Cargo.toml 2>/dev/null || true)
        if ! echo "$line" | grep -q "optional"; then
            V1_CARGO=$((V1_CARGO + 1))
        fi
    fi
done

V1_TOTAL=$((V1_COUNT + V1_CARGO))
if [ "$V1_TOTAL" -gt 0 ]; then
    echo "  FAIL: sb-core 有 $V1_COUNT 处非门控 Web 框架引用, $V1_CARGO 个非可选 Cargo.toml 依赖"
    fail
else
    echo "  PASS"
fi

# ─── V2: sb-core TLS/QUIC (feature-gate aware) ───────────
echo "── V2: sb-core TLS/QUIC 依赖 ──"

# Count only NON-feature-gated TLS/QUIC imports
V2_COUNT=0
while IFS= read -r file; do
    # Skip files in feature-gated modules
    if is_feature_gated_module "$file"; then
        continue
    fi
    # For each matching line, check inline feature gate
    while IFS=: read -r linenum content; do
        if ! is_line_feature_gated "$file" "$linenum"; then
            V2_COUNT=$((V2_COUNT + 1))
        fi
    done < <(grep -n "use rustls\|use quinn\|use tokio_rustls\|use tokio_tungstenite\|use reqwest" "$file" 2>/dev/null || true)
done < <(find crates/sb-core/src/ -name '*.rs' 2>/dev/null)

if [ "$V2_COUNT" -gt 0 ]; then
    echo "  FAIL: sb-core 有 $V2_COUNT 处非门控 TLS/QUIC 引用"
    fail
else
    echo "  PASS"
fi

# ─── V3: sb-core 协议实现 (feature-gate aware) ───────────
echo "── V3: sb-core 协议实现代码 ──"

# Check if protocol modules exist AND are NOT behind feature gates in outbound/mod.rs
OUTBOUND_MOD="crates/sb-core/src/outbound/mod.rs"
V3_FILES=0
V3_UNGATED=""
for proto in trojan vmess vless shadowsocks shadowtls hysteria hysteria2 tuic wireguard ssh naive; do
    # Check if files physically exist
    if ! ls crates/sb-core/src/outbound/${proto}* 2>/dev/null | grep -q .; then
        continue
    fi
    # Check if the module is feature-gated in outbound/mod.rs
    # Look for: #[cfg(feature = "out_xxx")] or #[cfg(all(feature = "out_xxx", ...))]
    # followed by: pub mod <proto>
    # Map protocol name to its feature name
    local_feature=""
    case "$proto" in
        shadowsocks) local_feature="out_ss" ;;
        naive)       local_feature="out_naive" ;;
        *)           local_feature="out_${proto}" ;;
    esac
    # Check if the pub mod line for this proto has a cfg gate on the preceding line(s)
    if [ -f "$OUTBOUND_MOD" ]; then
        # Find the line with "pub mod <proto>" (or "pub mod <proto> {")
        mod_line=$(grep -n "pub mod ${proto}" "$OUTBOUND_MOD" 2>/dev/null | head -1 || true)
        if [ -n "$mod_line" ]; then
            mod_linenum=$(echo "$mod_line" | cut -d: -f1)
            # Check preceding 3 lines for #[cfg(feature
            gated=false
            for i in 1 2 3; do
                check=$((mod_linenum - i))
                [ "$check" -lt 1 ] && break
                prev=$(sed -n "${check}p" "$OUTBOUND_MOD" 2>/dev/null || true)
                if echo "$prev" | grep -q '#\[cfg(.*feature'; then
                    gated=true
                    break
                fi
                # Stop if we hit something that's not an attribute or blank
                case "$prev" in
                    "#["*|""|" "*) ;; # continue checking
                    *) break ;;
                esac
            done
            if ! $gated; then
                V3_FILES=$((V3_FILES + 1))
                V3_UNGATED="${V3_UNGATED} ${proto}"
            fi
        fi
    fi
done

if [ "$V3_FILES" -gt 0 ]; then
    echo "  FAIL: sb-core/outbound/ 有 $V3_FILES 个非门控协议实现:${V3_UNGATED}"
    fail
else
    echo "  PASS (all protocol modules are feature-gated)"
fi

# ─── V4: sb-adapters 反向依赖 ──────────────────────────
echo "── V4: sb-adapters → sb-core 反向依赖 ──"

if grep -q 'sb-core' crates/sb-adapters/Cargo.toml 2>/dev/null; then
    # V4a: non-inbound (outbound/, register.rs, stubs) — actionable violations
    V4A_USES=$(grep -rn "use sb_core" crates/sb-adapters/src/outbound/ crates/sb-adapters/src/register.rs crates/sb-adapters/src/service_stubs.rs crates/sb-adapters/src/endpoint_stubs.rs 2>/dev/null | wc -l | tr -d ' ')

    # V4b: inbound + service + endpoint — legitimate architecture dependency
    V4B_USES=$(grep -rn "use sb_core" crates/sb-adapters/src/inbound/ crates/sb-adapters/src/service/ crates/sb-adapters/src/endpoint/ 2>/dev/null | wc -l | tr -d ' ')

    V4_TOTAL=$((V4A_USES + V4B_USES))

    echo "  V4a (outbound/register): $V4A_USES 处 use sb_core (threshold: 25)"
    echo "  V4b (inbound/service/endpoint): $V4B_USES 处 use sb_core (INFO only)"
    echo "  Total: $V4_TOTAL 处"

    # V4a threshold: warn if exceeds baseline but don't fail (these are known remaining deps)
    # V4b: legitimate dependency, INFO only
    if [ "$V4A_USES" -gt 25 ]; then
        echo "  WARN: V4a exceeds threshold (25)"
        fail
    else
        echo "  PASS (V4a within threshold)"
    fi
else
    echo "  PASS"
fi

# ─── V5: sb-subscribe 越界 ─────────────────────────────
echo "── V5: sb-subscribe → sb-core 越界 ──"

# Check if sb-core is a NON-optional dependency in sb-subscribe
V5_LINE=$(grep -E "^sb-core[[:space:]]*=" crates/sb-subscribe/Cargo.toml 2>/dev/null || true)
if [ -n "$V5_LINE" ] && ! echo "$V5_LINE" | grep -q "optional"; then
    echo "  FAIL: sb-subscribe 非可选依赖 sb-core"
    fail
else
    echo "  PASS (sb-core is optional or absent)"
fi

# ─── Cargo.toml 级别检查 ───────────────────────────────
echo "── Cargo.toml: sb-core 非可选禁止依赖 ──"

# Check for non-optional forbidden deps in sb-core Cargo.toml
FORBIDDEN_DEPS=0
FORBIDDEN_LIST=""
for dep in axum tonic tower hyper rustls quinn reqwest tokio-tungstenite snow; do
    # Match the dep as a line starting with the dep name
    line=$(grep -E "^${dep}[[:space:]]*=" crates/sb-core/Cargo.toml 2>/dev/null || true)
    if [ -n "$line" ]; then
        # Check if it's marked optional
        if ! echo "$line" | grep -q "optional"; then
            FORBIDDEN_DEPS=$((FORBIDDEN_DEPS + 1))
            FORBIDDEN_LIST="${FORBIDDEN_LIST} ${dep}"
        fi
    fi
done
if [ "$FORBIDDEN_DEPS" -gt 0 ]; then
    echo "  FAIL: sb-core Cargo.toml 含 $FORBIDDEN_DEPS 个非可选禁止依赖:${FORBIDDEN_LIST}"
    fail
else
    echo "  PASS"
fi

# ─── sb-types 纯净性 ──────────────────────────────────
echo "── sb-types 纯净性 ──"

if grep -qE "tokio|hyper|axum|rustls|quinn" crates/sb-types/Cargo.toml 2>/dev/null; then
    echo "  FAIL: sb-types 含运行时/网络依赖"
    fail
else
    echo "  PASS"
fi

# ─── V6: strict 模式（feature tree + default closure + reverse deps） ──────
echo "── V6: strict feature tree / default closure / reverse deps ──"

if python3 - <<'PY'
import json
import subprocess
import sys
import tomllib
from pathlib import Path

core_cargo = Path("crates/sb-core/Cargo.toml")
data = tomllib.loads(core_cargo.read_text(encoding="utf-8"))
deps = data.get("dependencies", {})
features = data.get("features", {})
default_features = features.get("default", [])

FORBIDDEN = [
    "axum",
    "tonic",
    "tower",
    "hyper",
    "rustls",
    "quinn",
    "reqwest",
    "tokio-tungstenite",
    "snow",
]

OWNER_POLICY = {
    "axum": {"service_clash_api", "service_v2ray_api", "service_ssmapi"},
    "tonic": {"service_v2ray_api"},
    "tower": set(),
    "hyper": {"out_naive", "service_derp"},
    "rustls": {"tls_rustls"},
    "quinn": {"out_quic", "dns_doq", "dns_doh3"},
    "reqwest": {"dns_doh", "service_derp"},
    "tokio-tungstenite": {"service_derp"},
    "snow": {"dns_tailscale", "out_tailscale"},
}

# 这些依赖允许在 sb-core default feature 闭包里出现（当前决议口径）
ALLOW_IN_DEFAULT = {"rustls", "quinn", "reqwest", "snow"}

errors = []
notes = []


def dep_optional(dep_name: str):
    v = deps.get(dep_name)
    if v is None:
        return None
    if isinstance(v, str):
        return False
    if isinstance(v, dict):
        return bool(v.get("optional", False))
    return False


def compute_feature_closure(seed):
    seen = set()
    stack = list(seed)
    while stack:
        feat = stack.pop()
        if feat in seen:
            continue
        seen.add(feat)
        for item in features.get(feat, []):
            if not isinstance(item, str):
                continue
            if item.startswith("dep:"):
                continue
            # 其他 crate feature（如 sb-platform/tun）不在本 crate 内展开
            if "/" in item:
                continue
            if item in features:
                stack.append(item)
    return seen


# 1) forbidden deps 必须 optional（若存在）
for dep in FORBIDDEN:
    opt = dep_optional(dep)
    if opt is False:
        errors.append(f"forbidden dep '{dep}' exists but is not optional")


# 2) feature owner tree：dep:xxx 只能从批准的 owner feature 出现
dep_owners = {}
for feat, items in features.items():
    for item in items:
        if isinstance(item, str) and item.startswith("dep:"):
            dep = item[4:]
            dep_owners.setdefault(dep, set()).add(feat)

for dep, allowed in OWNER_POLICY.items():
    owners = dep_owners.get(dep, set())
    if dep in deps and dep_optional(dep):
        if not owners:
            # optional 但没有任何 owner feature，通常是漂移或死配置
            errors.append(f"optional dep '{dep}' has no owner feature (missing dep:{dep} mapping)")
    if owners:
        unknown = owners - allowed
        if unknown:
            errors.append(
                f"dep '{dep}' is referenced by non-approved features: {sorted(unknown)} "
                f"(allowed: {sorted(allowed)})"
            )


# 3) default feature 闭包：只允许 ALLOW_IN_DEFAULT 中的 forbidden deps 出现
default_closure = compute_feature_closure(default_features)
default_dep_sources = {}
for feat in default_closure:
    for item in features.get(feat, []):
        if isinstance(item, str) and item.startswith("dep:"):
            dep = item[4:]
            default_dep_sources.setdefault(dep, set()).add(feat)

for dep in sorted(default_dep_sources):
    if dep in FORBIDDEN and dep not in ALLOW_IN_DEFAULT:
        sources = sorted(default_dep_sources[dep])
        errors.append(
            f"default feature closure unexpectedly activates forbidden dep '{dep}' via features {sources}"
        )

notes.append(f"default features: {sorted(default_features)}")
notes.append(f"default closure size: {len(default_closure)}")
notes.append(
    "default forbidden deps active: "
    + str(sorted(dep for dep in default_dep_sources if dep in FORBIDDEN))
)


# 4) workspace 直接反向依赖 allowlist（reverse dependency）
try:
    meta = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            text=True,
        )
    )
except subprocess.CalledProcessError as exc:
    errors.append(f"failed to run cargo metadata: {exc}")
else:
    workspace_ids = set(meta.get("workspace_members", []))
    packages = meta.get("packages", [])

    core_id = None
    for p in packages:
        if p.get("name") == "sb-core":
            core_id = p.get("id")
            break
    if core_id is None:
        errors.append("cannot locate sb-core package in cargo metadata")
    else:
        allowlist = {"app", "sb-api", "sb-adapters", "sb-benches", "xtests"}
        optional_allowlist = {"sb-subscribe"}
        actual = set()
        optional_actual = set()
        for p in packages:
            if p.get("id") not in workspace_ids:
                continue
            if p.get("name") == "sb-core":
                continue
            has_optional = False
            has_non_optional = False
            for dep in p.get("dependencies", []):
                if dep.get("name") == "sb-core":
                    if dep.get("optional"):
                        has_optional = True
                    else:
                        has_non_optional = True
            if has_non_optional:
                actual.add(p.get("name"))
            elif has_optional:
                optional_actual.add(p.get("name"))

        unknown = actual - allowlist
        if unknown:
            errors.append(
                f"workspace crates depend on sb-core but are not allowlisted: {sorted(unknown)}"
            )
        optional_unknown = optional_actual - optional_allowlist
        if optional_unknown:
            errors.append(
                "workspace crates OPTIONAL-depend on sb-core but are not allowlisted: "
                f"{sorted(optional_unknown)}"
            )
        notes.append(f"reverse deps (workspace direct): {sorted(actual)}")
        notes.append(f"reverse deps (workspace optional): {sorted(optional_actual)}")


if errors:
    for e in errors:
        print(f"  FAIL: {e}")
    sys.exit(1)

for n in notes:
    print(f"  INFO: {n}")
print("  PASS")
PY
then
    :
else
    fail
fi

# ─── 汇总 ─────────────────────────────────────────────
echo ""
echo "════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo "全部检查通过 ($FAILED 违规)"
    exit 0
else
    echo "发现 $FAILED 类违规"
    if $REPORT_ONLY; then
        echo "(报告模式，不阻断)"
        exit 0
    else
        exit 1
    fi
fi
